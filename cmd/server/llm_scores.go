package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func evaluateCriteriaScores(ctx context.Context, provider string, criteria []MaturityCriterion, ev MaturityEvidence, req MaturityAnalyzeRequest, cfg LLMRequestConfig) ([]MaturityCriterionScore, *LLMMetadata, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "openai":
		return evaluateCriteriaScoresWithOpenAI(ctx, criteria, ev, req, cfg)
	case "openrouter":
		return evaluateCriteriaScoresWithOpenRouter(ctx, criteria, ev, req, cfg)
	case "gemini", "":
		return evaluateCriteriaScoresWithGemini(ctx, criteria, ev, req, cfg)
	default:
		return evaluateCriteriaScoresWithGemini(ctx, criteria, ev, req, cfg)
	}
}

func criteriaScoresSystemPrompt() string {
	return `You are a Kubernetes cluster maturity assessor.
Return ONLY valid JSON (no markdown) with:
{ "criteriaScores": [ { "key": string, "category": string, "criterion": string, "level": integer 1-5, "confidence": number 0-1, "rationale": string, "evidence": string[], "missing": string[], "nextSteps": string[] } ] }
Rules:
- Emit exactly one criteriaScores entry per input criterion key.
- Use evidence + userNotes + userAnswers; if uncertain, choose the most likely level but reduce confidence and add missing questions.
- For missing, write concrete questions in Turkish that would let a human pick L1-L5.
- Keep rationale short and actionable.`
}

func filterAnswersForCriteria(all map[string]string, criteria []MaturityCriterion) map[string]string {
	if len(all) == 0 || len(criteria) == 0 {
		return nil
	}
	keys := map[string]struct{}{}
	for _, c := range criteria {
		if k := strings.TrimSpace(c.Key); k != "" {
			keys[k] = struct{}{}
		}
	}
	out := map[string]string{}
	for k, v := range all {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, ok := keys[k]; !ok {
			continue
		}
		if vv := strings.TrimSpace(v); vv != "" {
			out[k] = vv
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func evaluateCriteriaScoresWithOpenAI(ctx context.Context, criteria []MaturityCriterion, ev MaturityEvidence, req MaturityAnalyzeRequest, cfg LLMRequestConfig) ([]MaturityCriterionScore, *LLMMetadata, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	}
	if apiKey == "" {
		return nil, nil, errLLMNotConfigured
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")), "/")
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = strings.TrimSpace(os.Getenv("OPENAI_MODEL"))
	}
	if model == "" {
		model = "gpt-4o-mini"
	}

	promptObj := map[string]any{
		"evidence":    buildEvidenceForLLM(ev),
		"userNotes":   strings.TrimSpace(req.UserNotes),
		"userAnswers": filterAnswersForCriteria(req.Answers, criteria),
		"criteria":    criteria,
	}
	system := criteriaScoresSystemPrompt()
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
		return nil, nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: time.Duration(envInt("LLM_HTTP_TIMEOUT_ANALYZE_SECONDS", 25)) * time.Second}
	res, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	resBody, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, &LLMMetadata{Provider: "openai", Model: model, RequestID: res.Header.Get("x-request-id")}, fmt.Errorf("openai error (HTTP %d): %s", res.StatusCode, strings.TrimSpace(string(resBody)))
	}
	var decoded openAIChatCompletionResponse
	if err := json.Unmarshal(resBody, &decoded); err != nil {
		return nil, &LLMMetadata{Provider: "openai", Model: model, RequestID: res.Header.Get("x-request-id")}, err
	}
	if len(decoded.Choices) == 0 {
		return nil, &LLMMetadata{Provider: "openai", Model: model, RequestID: res.Header.Get("x-request-id"), TotalTokens: decoded.Usage.TotalTokens}, errors.New("openai: empty choices")
	}
	text := strings.TrimSpace(decoded.Choices[0].Message.Content)
	var out struct {
		CriteriaScores []MaturityCriterionScore `json:"criteriaScores"`
	}
	normalized := coerceLLMJSON(text)
	if err := json.Unmarshal([]byte(normalized), &out); err != nil {
		return nil, &LLMMetadata{Provider: "openai", Model: model, RequestID: res.Header.Get("x-request-id"), TotalTokens: decoded.Usage.TotalTokens}, fmt.Errorf("openai JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
	}
	meta := &LLMMetadata{Provider: "openai", Model: model, RequestID: res.Header.Get("x-request-id"), TotalTokens: decoded.Usage.TotalTokens}
	return out.CriteriaScores, meta, nil
}

func evaluateCriteriaScoresWithOpenRouter(ctx context.Context, criteria []MaturityCriterion, ev MaturityEvidence, req MaturityAnalyzeRequest, cfg LLMRequestConfig) ([]MaturityCriterionScore, *LLMMetadata, error) {
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

	promptObj := map[string]any{
		"evidence":    buildEvidenceForLLM(ev),
		"userNotes":   strings.TrimSpace(req.UserNotes),
		"userAnswers": filterAnswersForCriteria(req.Answers, criteria),
		"criteria":    criteria,
	}
	system := criteriaScoresSystemPrompt()
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
		return nil, nil, err
	}

	buildReq := func() (*http.Request, error) {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(b))
		if err != nil {
			return nil, err
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
		return httpReq, nil
	}

	timeoutSeconds := envInt("LLM_HTTP_TIMEOUT_OPENROUTER_ANALYZE_SECONDS", envInt("LLM_HTTP_TIMEOUT_ANALYZE_SECONDS", 25))
	retries := envInt("LLM_HTTP_RETRIES_OPENROUTER_ANALYZE", 2) // total attempts = 1 + retries
	client := &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}

	var lastMeta *LLMMetadata
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return nil, lastMeta, ctx.Err()
		}

		httpReq, err := buildReq()
		if err != nil {
			return nil, lastMeta, err
		}

		res, err := client.Do(httpReq)
		if err != nil {
			lastErr = err
			if attempt < retries && isRetryableNetErr(err) {
				_ = sleepWithContext(ctx, time.Duration(250*(attempt+1))*time.Millisecond)
				continue
			}
			return nil, lastMeta, err
		}

		decoded, raw, _, decErr := decodeOpenAIChatCompletion(res, 8<<20)
		requestID := openRouterRequestID(res.Header)
		_ = res.Body.Close()

		lastMeta = &LLMMetadata{Provider: "openrouter", Model: model, RequestID: requestID, TotalTokens: decoded.Usage.TotalTokens}

		if decErr != nil {
			lastErr = decErr
			if attempt < retries && isRetryableNetErr(decErr) {
				_ = sleepWithContext(ctx, time.Duration(250*(attempt+1))*time.Millisecond)
				continue
			}
			return nil, lastMeta, decErr
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			httpErr := fmt.Errorf("openrouter error (HTTP %d): %s", res.StatusCode, strings.TrimSpace(string(raw)))
			lastErr = httpErr
			if attempt < retries && isRetryableHTTPStatus(res.StatusCode) {
				_ = sleepWithContext(ctx, time.Duration(500*(attempt+1))*time.Millisecond)
				continue
			}
			return nil, lastMeta, httpErr
		}
		if len(decoded.Choices) == 0 {
			return nil, lastMeta, errors.New("openrouter: empty choices")
		}

		text := strings.TrimSpace(decoded.Choices[0].Message.Content)
		var out struct {
			CriteriaScores []MaturityCriterionScore `json:"criteriaScores"`
		}
		normalized := coerceLLMJSON(text)
		if err := json.Unmarshal([]byte(normalized), &out); err != nil {
			return nil, lastMeta, fmt.Errorf("openrouter JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
		}
		return out.CriteriaScores, lastMeta, nil
	}

	if lastErr == nil {
		lastErr = errors.New("openrouter: exhausted retries")
	}
	return nil, lastMeta, lastErr
}

func evaluateCriteriaScoresWithGemini(ctx context.Context, criteria []MaturityCriterion, ev MaturityEvidence, req MaturityAnalyzeRequest, cfg LLMRequestConfig) ([]MaturityCriterionScore, *LLMMetadata, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))
	}
	if apiKey == "" {
		return nil, nil, errGeminiNotConfigured
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("GEMINI_BASE_URL")), "/")
	}
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com"
	}
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = strings.TrimSpace(os.Getenv("GEMINI_MODEL"))
	}
	if model == "" {
		model = "gemini-1.5-flash"
	}

	system := criteriaScoresSystemPrompt()
	promptObj := map[string]any{
		"evidence":    buildEvidenceForLLM(ev),
		"userNotes":   strings.TrimSpace(req.UserNotes),
		"userAnswers": filterAnswersForCriteria(req.Answers, criteria),
		"criteria":    criteria,
	}
	user := "INPUT_JSON=" + mustJSON(promptObj)

	contents := []map[string]any{
		{"role": "user", "parts": []map[string]string{{"text": system + "\n\n" + user}}},
	}
	body := map[string]any{
		"contents": contents,
		"generationConfig": map[string]any{
			"temperature": 0.2,
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}

	modelPath := model
	if !strings.HasPrefix(modelPath, "models/") {
		modelPath = "models/" + modelPath
	}

	urlV1 := geminiGenerateContentURL(baseURL, modelPath, apiKey, "v1")
	status, headers, resBody, err := geminiPostWithRetry(ctx, urlV1, b)
	if err != nil && isGeminiModelNotFoundForV1(status, resBody) {
		urlBeta := geminiGenerateContentURL(baseURL, modelPath, apiKey, "v1beta")
		status, headers, resBody, err = geminiPostWithRetry(ctx, urlBeta, b)
	}
	requestID := ""
	if headers != nil {
		requestID = strings.TrimSpace(headers.Get("x-goog-request-id"))
		if requestID == "" {
			requestID = strings.TrimSpace(headers.Get("x-request-id"))
		}
	}
	if err != nil {
		return nil, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID}, err
	}

	var decoded geminiGenerateContentResponse
	if err := json.Unmarshal(resBody, &decoded); err != nil {
		return nil, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID}, err
	}

	text := ""
	if len(decoded.Candidates) > 0 && len(decoded.Candidates[0].Content.Parts) > 0 {
		text = decoded.Candidates[0].Content.Parts[0].Text
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID, TotalTokens: decoded.UsageMetadata.TotalTokenCount}, errors.New("gemini: empty content")
	}

	var out struct {
		CriteriaScores []MaturityCriterionScore `json:"criteriaScores"`
	}
	normalized := coerceLLMJSON(text)
	if err := json.Unmarshal([]byte(normalized), &out); err != nil {
		return nil, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID, TotalTokens: decoded.UsageMetadata.TotalTokenCount}, fmt.Errorf("gemini JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
	}
	meta := &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID, TotalTokens: decoded.UsageMetadata.TotalTokenCount}
	return out.CriteriaScores, meta, nil
}
