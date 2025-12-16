package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var errOpenRouterNotConfigured = errors.New("OpenRouter not configured (set OPENROUTER_API_KEY)")

func readBodyWithLimit(r io.Reader, max int64) (body []byte, truncated bool, _ error) {
	if max <= 0 {
		max = 1
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

func tailBytes(b []byte, n int) string {
	if n <= 0 || len(b) == 0 {
		return ""
	}
	if len(b) <= n {
		return string(b)
	}
	return string(b[len(b)-n:])
}

func openRouterRequestID(h http.Header) string {
	if h == nil {
		return ""
	}
	for _, k := range []string{"x-request-id", "x-openrouter-request-id", "cf-ray"} {
		if v := strings.TrimSpace(h.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

func decodeOpenAIChatCompletion(res *http.Response, maxCapture int64) (openAIChatCompletionResponse, []byte, bool, error) {
	if res == nil || res.Body == nil {
		return openAIChatCompletionResponse{}, nil, false, errors.New("nil response body")
	}
	if maxCapture <= 0 {
		maxCapture = 1 << 20
	}

	// Decode without waiting for EOF; some upstreams keep the connection open.
	lr := io.LimitReader(res.Body, maxCapture+1)
	var buf bytes.Buffer
	tee := io.TeeReader(lr, &buf)
	dec := json.NewDecoder(tee)
	dec.UseNumber()

	var decoded openAIChatCompletionResponse
	err := dec.Decode(&decoded)

	raw := buf.Bytes()
	truncated := int64(len(raw)) > maxCapture
	if truncated {
		raw = raw[:maxCapture]
	}
	return decoded, append([]byte(nil), raw...), truncated, err
}

func evaluateMaturityWithOpenRouter(ctx context.Context, criteria []MaturityCriterion, ev MaturityEvidence, req MaturityAnalyzeRequest, cfg LLMRequestConfig) (MaturityReport, *LLMMetadata, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY"))
	}
	if apiKey == "" {
		return MaturityReport{}, nil, errOpenRouterNotConfigured
	}

	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("OPENROUTER_BASE_URL")), "/")
	}
	if baseURL == "" {
		baseURL = "https://openrouter.ai/api/v1"
	}

	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = strings.TrimSpace(os.Getenv("OPENROUTER_MODEL"))
	}
	if model == "" {
		model = "openai/gpt-4o-mini"
	}

	promptObj := map[string]any{
		"targetLevel": strings.TrimSpace(req.TargetLevel),
		"evidence":    buildEvidenceForLLM(ev),
		"userNotes":   strings.TrimSpace(req.UserNotes),
		"userAnswers": req.Answers,
		"criteria":    criteria,
	}

	system := `You are a Kubernetes cluster maturity assessor. You will receive a rubric (criteria with 5 levels) and evidence collected from a Kubernetes cluster (plus optional user notes and per-criterion user answers).
Return ONLY valid JSON (no markdown) with these keys:
- overallLevel: number (1-5, one decimal allowed)
- categoryScores: array of {category: string, level: number}
- criteriaScores: array of {key: string, category: string, criterion: string, level: integer 1-5, confidence: number 0-1, rationale: string, evidence: string[], missing: string[], nextSteps: string[]}
- notes: string (optional)
Rules:
- Emit exactly one criteriaScores entry per input criterion key.
- Use evidence + userNotes + userAnswers; if uncertain, choose the most likely level but reduce confidence and add missing questions.
- For missing, write concrete questions in Turkish that would let a human pick L1-L5.
- Keep rationale short and actionable.`

	user := "INPUT_JSON=" + mustJSON(promptObj)

	body := openAIChatCompletionRequest{
		Model: model,
		Messages: []openAIChatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature:    0.2,
		ResponseFormat: &openAIResponseFormat{Type: "json_object"},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return MaturityReport{}, nil, err
	}

	doRequest := func(payload []byte) (*http.Response, openAIChatCompletionResponse, []byte, bool, error) {
		if llmDebugEnabled() {
			log.Printf("openrouter -> request model=%s bytes=%d sha1=%s", model, len(payload), sha1Hex(payload))
			if llmDebugBodiesEnabled() {
				log.Printf("openrouter -> request body=%q", truncateForLog(redactLLMSecrets(string(payload)), 1400))
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(payload))
		if err != nil {
			return nil, openAIChatCompletionResponse{}, nil, false, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
		// Recommended by OpenRouter (optional but improves routing/observability).
		if v := strings.TrimSpace(os.Getenv("OPENROUTER_SITE_URL")); v != "" {
			httpReq.Header.Set("HTTP-Referer", v)
		}
		if v := strings.TrimSpace(os.Getenv("OPENROUTER_APP_NAME")); v != "" {
			httpReq.Header.Set("X-Title", v)
		}
		// Free/slow models can take long; keep this generous for analyze.
		client := &http.Client{Timeout: 180 * time.Second}
		res, err := client.Do(httpReq)
		if err != nil {
			return nil, openAIChatCompletionResponse{}, nil, false, err
		}
		defer res.Body.Close()
		decoded, raw, truncated, decErr := decodeOpenAIChatCompletion(res, 64<<20)
		if decErr != nil {
			if llmDebugEnabled() || (!errors.Is(decErr, context.DeadlineExceeded) && !errors.Is(decErr, context.Canceled)) {
				log.Printf("openrouter <- decode failed status=%d bytes=%d truncated=%t requestId=%s: %v; tail=%q",
					res.StatusCode, len(raw), truncated, openRouterRequestID(res.Header), decErr, truncateForLog(redactLLMSecrets(tailBytes(raw, 240)), 240))
			}
			return res, openAIChatCompletionResponse{}, raw, truncated, decErr
		}
		if llmDebugEnabled() {
			log.Printf("openrouter <- response status=%d bytes=%d truncated=%t requestId=%s", res.StatusCode, len(raw), truncated, openRouterRequestID(res.Header))
			if llmDebugBodiesEnabled() {
				log.Printf("openrouter <- response bodyTail=%q", truncateForLog(redactLLMSecrets(tailBytes(raw, 1400)), 1400))
			}
		}
		return res, decoded, raw, truncated, nil
	}

	var (
		res     *http.Response
		decoded openAIChatCompletionResponse
		raw     []byte
		resErr  error
	)
	for attempt := 0; attempt < 2; attempt++ {
		res, decoded, raw, _, resErr = doRequest(b)
		if resErr != nil {
			if attempt == 0 {
				continue
			}
			return MaturityReport{}, nil, resErr
		}

		// Some OpenRouter models don't support response_format; retry once without it.
		if res.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(raw), []byte("response_format")) {
			body.ResponseFormat = nil
			b, _ = json.Marshal(body)
			continue
		}

		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return MaturityReport{}, &LLMMetadata{Provider: "openrouter", Model: model, RequestID: openRouterRequestID(res.Header)}, fmt.Errorf("openrouter error (HTTP %d): %s", res.StatusCode, strings.TrimSpace(string(raw)))
		}

		if len(decoded.Choices) == 0 {
			return MaturityReport{}, &LLMMetadata{Provider: "openrouter", Model: model, RequestID: openRouterRequestID(res.Header), TotalTokens: decoded.Usage.TotalTokens}, errors.New("openrouter: empty choices")
		}

		text := strings.TrimSpace(decoded.Choices[0].Message.Content)
		if text == "" {
			return MaturityReport{}, &LLMMetadata{Provider: "openrouter", Model: model, RequestID: openRouterRequestID(res.Header), TotalTokens: decoded.Usage.TotalTokens}, errors.New("openrouter: empty content")
		}

		var out struct {
			OverallLevel   float64                  `json:"overallLevel"`
			CategoryScores []MaturityCategoryScore  `json:"categoryScores"`
			CriteriaScores []MaturityCriterionScore `json:"criteriaScores"`
			Notes          string                   `json:"notes"`
		}
		normalized := coerceLLMJSON(text)
		if err := json.Unmarshal([]byte(normalized), &out); err != nil {
			return MaturityReport{}, &LLMMetadata{Provider: "openrouter", Model: model, RequestID: openRouterRequestID(res.Header), TotalTokens: decoded.Usage.TotalTokens}, fmt.Errorf("openrouter JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
		}

		report := MaturityReport{
			GeneratedAt:    time.Now(),
			Cluster:        ev.Cluster,
			OverallLevel:   out.OverallLevel,
			CategoryScores: out.CategoryScores,
			CriteriaScores: out.CriteriaScores,
			Notes:          strings.TrimSpace(out.Notes),
		}
		fillMissingScores(&report, criteria)
		recomputeAggregates(&report)

		meta := &LLMMetadata{
			Provider:    "openrouter",
			Model:       model,
			RequestID:   openRouterRequestID(res.Header),
			TotalTokens: decoded.Usage.TotalTokens,
		}
		return report, meta, nil
	}

	return MaturityReport{}, &LLMMetadata{Provider: "openrouter", Model: model}, errors.New("openrouter: exhausted retries")
}

func generateQuestionsWithOpenRouter(ctx context.Context, system, user string, cfg LLMRequestConfig) ([]MaturityQuestion, *LLMMetadata, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY"))
	}
	if apiKey == "" {
		return nil, nil, errOpenRouterNotConfigured
	}

	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("OPENROUTER_BASE_URL")), "/")
	}
	if baseURL == "" {
		baseURL = "https://openrouter.ai/api/v1"
	}

	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = strings.TrimSpace(os.Getenv("OPENROUTER_MODEL"))
	}
	if model == "" {
		model = "openai/gpt-4o-mini"
	}

	body := openAIChatCompletionRequest{
		Model: model,
		Messages: []openAIChatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature:    0.2,
		ResponseFormat: &openAIResponseFormat{Type: "json_object"},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}

	doRequest := func(payload []byte) (*http.Response, openAIChatCompletionResponse, []byte, bool, error) {
		if llmDebugEnabled() {
			log.Printf("openrouter -> request model=%s bytes=%d sha1=%s", model, len(payload), sha1Hex(payload))
			if llmDebugBodiesEnabled() {
				log.Printf("openrouter -> request body=%q", truncateForLog(redactLLMSecrets(string(payload)), 1400))
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(payload))
		if err != nil {
			return nil, openAIChatCompletionResponse{}, nil, false, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
		if v := strings.TrimSpace(os.Getenv("OPENROUTER_SITE_URL")); v != "" {
			httpReq.Header.Set("HTTP-Referer", v)
		}
		if v := strings.TrimSpace(os.Getenv("OPENROUTER_APP_NAME")); v != "" {
			httpReq.Header.Set("X-Title", v)
		}
		timeoutSeconds := envInt("LLM_HTTP_TIMEOUT_OPENROUTER_QUESTIONS_SECONDS", envInt("LLM_HTTP_TIMEOUT_QUESTIONS_SECONDS", 300))
		client := &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}
		res, err := client.Do(httpReq)
		if err != nil {
			return nil, openAIChatCompletionResponse{}, nil, false, err
		}
		defer res.Body.Close()
		decoded, raw, truncated, decErr := decodeOpenAIChatCompletion(res, 64<<20)
		if decErr != nil {
			if llmDebugEnabled() || (!errors.Is(decErr, context.DeadlineExceeded) && !errors.Is(decErr, context.Canceled)) {
				log.Printf("openrouter <- decode failed status=%d bytes=%d truncated=%t requestId=%s: %v; tail=%q",
					res.StatusCode, len(raw), truncated, openRouterRequestID(res.Header), decErr, truncateForLog(redactLLMSecrets(tailBytes(raw, 240)), 240))
			}
			return res, openAIChatCompletionResponse{}, raw, truncated, decErr
		}
		if llmDebugEnabled() {
			log.Printf("openrouter <- response status=%d bytes=%d truncated=%t requestId=%s", res.StatusCode, len(raw), truncated, openRouterRequestID(res.Header))
			if llmDebugBodiesEnabled() {
				log.Printf("openrouter <- response bodyTail=%q", truncateForLog(redactLLMSecrets(tailBytes(raw, 1400)), 1400))
			}
		}
		return res, decoded, raw, truncated, nil
	}

	var (
		res     *http.Response
		decoded openAIChatCompletionResponse
		raw     []byte
	)
	retries := envInt("LLM_HTTP_RETRIES_OPENROUTER_QUESTIONS", 0) // total attempts = 1 + retries
	for attempt := 0; attempt <= retries; attempt++ {
		var err error
		res, decoded, raw, _, err = doRequest(b)
		if err != nil {
			if attempt < retries && isRetryableNetErr(err) {
				_ = sleepWithContext(ctx, time.Duration(250*(attempt+1))*time.Millisecond)
				continue
			}
			return nil, nil, err
		}
		requestID := openRouterRequestID(res.Header)

		if res.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(raw), []byte("response_format")) {
			body.ResponseFormat = nil
			b, _ = json.Marshal(body)
			continue
		}

		if res.StatusCode < 200 || res.StatusCode >= 300 {
			httpErr := fmt.Errorf("openrouter error (HTTP %d): %s", res.StatusCode, strings.TrimSpace(string(raw)))
			if attempt < retries && isRetryableHTTPStatus(res.StatusCode) {
				_ = sleepWithContext(ctx, time.Duration(500*(attempt+1))*time.Millisecond)
				continue
			}
			return nil, &LLMMetadata{Provider: "openrouter", Model: model, RequestID: requestID}, httpErr
		}
		if len(decoded.Choices) == 0 {
			return nil, &LLMMetadata{Provider: "openrouter", Model: model, RequestID: requestID, TotalTokens: decoded.Usage.TotalTokens}, errors.New("openrouter: empty choices")
		}

		text := strings.TrimSpace(decoded.Choices[0].Message.Content)
		if text == "" {
			return nil, &LLMMetadata{Provider: "openrouter", Model: model, RequestID: requestID, TotalTokens: decoded.Usage.TotalTokens}, errors.New("openrouter: empty content")
		}

		var out struct {
			Questions []MaturityQuestion `json:"questions"`
		}
		normalized := coerceLLMJSON(text)
		if err := json.Unmarshal([]byte(normalized), &out); err != nil {
			return nil, &LLMMetadata{Provider: "openrouter", Model: model, RequestID: requestID, TotalTokens: decoded.Usage.TotalTokens}, fmt.Errorf("openrouter JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
		}

		meta := &LLMMetadata{
			Provider:    "openrouter",
			Model:       model,
			RequestID:   requestID,
			TotalTokens: decoded.Usage.TotalTokens,
		}
		return out.Questions, meta, nil
	}

	return nil, &LLMMetadata{Provider: "openrouter", Model: model}, errors.New("openrouter: exhausted retries")
}
