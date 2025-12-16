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

type ExplainItem struct {
	Key        string  `json:"key"`
	Category   string  `json:"category,omitempty"`
	Criterion  string  `json:"criterion,omitempty"`
	Level      int     `json:"level,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Rationale  string  `json:"rationale,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
}

type ExplainRequest struct {
	Items     []ExplainItem     `json:"items"`
	UserNotes string            `json:"userNotes,omitempty"`
	Evidence  map[string]any    `json:"evidence,omitempty"` // pre-summarized evidence (small)
	LLM       *LLMRequestConfig `json:"llm,omitempty"`
}

type ExplainResult struct {
	Key     string `json:"key"`
	Summary string `json:"summary"`
}

type ExplainResponse struct {
	GeneratedAt time.Time       `json:"generatedAt"`
	Results     []ExplainResult `json:"results"`
	LLM         *LLMMetadata    `json:"llm,omitempty"`
	Note        string          `json:"note,omitempty"`
}

func handleMaturityExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req ExplainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSONError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	// Minimal validation.
	items := make([]ExplainItem, 0, len(req.Items))
	seen := map[string]bool{}
	for _, it := range req.Items {
		it.Key = strings.TrimSpace(it.Key)
		if it.Key == "" || seen[it.Key] {
			continue
		}
		seen[it.Key] = true
		items = append(items, it)
	}
	if len(items) == 0 {
		respondJSONError(w, http.StatusBadRequest, "No items to explain")
		return
	}
	if len(items) > 20 {
		items = items[:20]
	}

	results, meta, note := ExplainMaturityScores(r.Context(), items, req.Evidence, strings.TrimSpace(req.UserNotes), req.LLM)
	resp := ExplainResponse{
		GeneratedAt: time.Now(),
		Results:     results,
		LLM:         meta,
		Note:        note,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func ExplainMaturityScores(ctx context.Context, items []ExplainItem, evidence map[string]any, userNotes string, cfg *LLMRequestConfig) ([]ExplainResult, *LLMMetadata, string) {
	// Default fallback: return trimmed rationale or a simple placeholder.
	fallback := func(note string) ([]ExplainResult, *LLMMetadata, string) {
		out := make([]ExplainResult, 0, len(items))
		for _, it := range items {
			s := strings.TrimSpace(it.Rationale)
			if s == "" {
				if it.Level > 0 {
					s = fmt.Sprintf("Özet: L%d seçimi için kanıt/nota göre ön değerlendirme yapıldı; detay için kanıt ekleyin.", it.Level)
				} else {
					s = "Özet: Yeterli kanıt yok; bu kriter için kanıt ekleyin."
				}
			}
			out = append(out, ExplainResult{Key: it.Key, Summary: s})
		}
		return out, nil, note
	}

	cfgN := normalizeLLMConfig(cfg)
	if cfgN.Provider == "" {
		cfgN.Provider = strings.ToLower(strings.TrimSpace(os.Getenv("LLM_PROVIDER")))
	}

	// If no provider selected, keep it cheap.
	if cfgN.Provider == "none" || cfgN.Provider == "off" || cfgN.Provider == "disabled" {
		return fallback("LLM disabled")
	}

	system := `You summarize why a Kubernetes maturity criterion got a certain level.
Return ONLY valid JSON (no markdown) with:
{ "results": [ { "key": string, "summary": string } ] }
Rules:
- Output exactly one results entry per input item key.
- summary MUST be Turkish, max 1-2 short sentences.
- summary must state: (a) the chosen level, (b) the 1-2 strongest evidence signals from the provided evidence/rationale.
- If evidence is insufficient, say what is missing in a short way.`

	promptObj := map[string]any{
		"userNotes": strings.TrimSpace(userNotes),
		"evidence":  evidence,
		"items":     items,
	}
	user := "INPUT_JSON=" + mustJSON(promptObj)

	switch cfgN.Provider {
	case "openai":
		out, meta, err := explainWithOpenAI(ctx, system, user, cfgN)
		if err != nil {
			log.Printf("LLM explain failed (provider=openai model=%s): %v", cfgN.Model, err)
			return fallback(err.Error())
		}
		return out, meta, ""
	case "openrouter":
		out, meta, err := explainWithOpenRouter(ctx, system, user, cfgN)
		if err != nil {
			log.Printf("LLM explain failed (provider=openrouter model=%s): %v", cfgN.Model, err)
			return fallback(err.Error())
		}
		return out, meta, ""
	case "gemini", "":
		out, meta, err := explainWithGemini(ctx, system, user, cfgN)
		if err != nil {
			log.Printf("LLM explain failed (provider=gemini model=%s): %v", cfgN.Model, err)
			return fallback(err.Error())
		}
		return out, meta, ""
	default:
		return fallback("Unknown LLM provider")
	}
}

func explainWithOpenAI(ctx context.Context, system, user string, cfg LLMRequestConfig) ([]ExplainResult, *LLMMetadata, error) {
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

	client := &http.Client{Timeout: 60 * time.Second}
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
		Results []ExplainResult `json:"results"`
	}
	normalized := coerceLLMJSON(text)
	if err := json.Unmarshal([]byte(normalized), &out); err != nil {
		return nil, &LLMMetadata{Provider: "openai", Model: model, RequestID: res.Header.Get("x-request-id"), TotalTokens: decoded.Usage.TotalTokens}, fmt.Errorf("openai JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
	}
	meta := &LLMMetadata{Provider: "openai", Model: model, RequestID: res.Header.Get("x-request-id"), TotalTokens: decoded.Usage.TotalTokens}
	return out.Results, meta, nil
}

func explainWithOpenRouter(ctx context.Context, system, user string, cfg LLMRequestConfig) ([]ExplainResult, *LLMMetadata, error) {
	// Reuse OpenRouter chat-completions style (OpenAI compatible).
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

	timeoutSeconds := envInt("LLM_HTTP_TIMEOUT_OPENROUTER_EXPLAIN_SECONDS", 90)
	retries := envInt("LLM_HTTP_RETRIES_OPENROUTER_EXPLAIN", 1) // total attempts = 1 + retries
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

		decoded, raw, _, decErr := decodeOpenAIChatCompletion(res, 4<<20)
		requestID := openRouterRequestID(res.Header)
		_ = res.Body.Close()

		lastMeta = &LLMMetadata{Provider: "openrouter", Model: model, RequestID: requestID, TotalTokens: decoded.Usage.TotalTokens}
		bodySnippet := strings.TrimSpace(truncateForError(redactLLMSecrets(string(raw)), 800))
		if bodySnippet == "" && len(raw) > 0 {
			bodySnippet = "(non-text body)"
		}

		if decErr != nil {
			lastErr = decErr
			lower := strings.ToLower(bodySnippet)
			wrapped := decErr
			if strings.HasPrefix(lower, "<!doctype") || strings.HasPrefix(lower, "<html") || strings.HasPrefix(lower, "<") {
				wrapped = fmt.Errorf("openrouter returned non-JSON (status=%d): %w; body=%q", res.StatusCode, decErr, bodySnippet)
			} else if bodySnippet != "" {
				wrapped = fmt.Errorf("openrouter JSON decode failed (status=%d): %w; body=%q", res.StatusCode, decErr, bodySnippet)
			}
			if attempt < retries && (isRetryableNetErr(decErr) || isRetryableHTTPStatus(res.StatusCode)) {
				_ = sleepWithContext(ctx, time.Duration(500*(attempt+1))*time.Millisecond)
				continue
			}
			return nil, lastMeta, wrapped
		}

		if res.StatusCode < 200 || res.StatusCode >= 300 {
			httpErr := fmt.Errorf("openrouter error (HTTP %d): %s", res.StatusCode, bodySnippet)
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
		Results []ExplainResult `json:"results"`
	}
	normalized := coerceLLMJSON(text)
	if err := json.Unmarshal([]byte(normalized), &out); err != nil {
			return nil, lastMeta, fmt.Errorf("openrouter JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
	}
		return out.Results, lastMeta, nil
	}

	if lastErr == nil {
		lastErr = errors.New("openrouter: exhausted retries")
	}
	return nil, lastMeta, lastErr
}

func explainWithGemini(ctx context.Context, system, user string, cfg LLMRequestConfig) ([]ExplainResult, *LLMMetadata, error) {
	// Gemini path: keep compatibility with current gemini.go plumbing by calling generateContent.
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
		Results []ExplainResult `json:"results"`
	}
	normalized := coerceLLMJSON(text)
	if err := json.Unmarshal([]byte(normalized), &out); err != nil {
		return nil, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID, TotalTokens: decoded.UsageMetadata.TotalTokenCount}, fmt.Errorf("gemini JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
	}
	meta := &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID, TotalTokens: decoded.UsageMetadata.TotalTokenCount}
	return out.Results, meta, nil
}
