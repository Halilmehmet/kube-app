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
	"regexp"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

type geminiGenerateContentResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata struct {
		TotalTokenCount int `json:"totalTokenCount"`
	} `json:"usageMetadata"`
}

var errGeminiNotConfigured = errors.New("Gemini not configured (set GEMINI_API_KEY)")

func isRetryableGeminiStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func redactAPIKeyInText(s string) string {
	if s == "" {
		return s
	}
	const keyMarker = "key="
	for {
		i := strings.Index(s, keyMarker)
		if i < 0 {
			return s
		}
		j := i + len(keyMarker)
		for j < len(s) {
			c := s[j]
			if c == '&' || c == '"' || c == '\'' || c == ' ' || c == '\n' || c == '\r' {
				break
			}
			j++
		}
		s = s[:i] + keyMarker + "REDACTED" + s[j:]
	}
}

var (
	geminiCacheMu sync.Mutex
	geminiCache   = map[string]struct {
		expiresAt time.Time
		body      []byte
	}{}
)

func geminiCacheKey(url string, body []byte) string {
	// Never cache the raw key; normalize query string.
	normalizedURL := url
	if i := strings.Index(normalizedURL, "key="); i >= 0 {
		normalizedURL = normalizedURL[:i] + "key=REDACTED"
	}
	sum := sha1.Sum(body)
	return normalizedURL + "#" + hex.EncodeToString(sum[:])
}

func getGeminiCached(url string, body []byte) ([]byte, bool) {
	k := geminiCacheKey(url, body)
	now := time.Now()
	geminiCacheMu.Lock()
	defer geminiCacheMu.Unlock()
	if v, ok := geminiCache[k]; ok {
		if now.Before(v.expiresAt) && len(v.body) > 0 {
			return append([]byte(nil), v.body...), true
		}
		delete(geminiCache, k)
	}
	return nil, false
}

func putGeminiCached(url string, body []byte, resBody []byte) {
	// Very small TTL to avoid hammering the API while the UI is re-trying/refreshing.
	const ttl = 2 * time.Minute
	if len(resBody) == 0 {
		return
	}
	k := geminiCacheKey(url, body)
	geminiCacheMu.Lock()
	defer geminiCacheMu.Unlock()
	// Keep cache bounded.
	if len(geminiCache) > 64 {
		for key, v := range geminiCache {
			if time.Now().After(v.expiresAt) {
				delete(geminiCache, key)
			}
		}
		if len(geminiCache) > 64 {
			// Drop one arbitrary entry.
			for key := range geminiCache {
				delete(geminiCache, key)
				break
			}
		}
	}
	geminiCache[k] = struct {
		expiresAt time.Time
		body      []byte
	}{expiresAt: time.Now().Add(ttl), body: append([]byte(nil), resBody...)}
}

var reRetryDelay = regexp.MustCompile(`"retryDelay"\s*:\s*"([^"]+)"`)

func parseGeminiRetryDelay(resBody []byte) time.Duration {
	if len(resBody) == 0 {
		return 0
	}
	m := reRetryDelay.FindSubmatch(resBody)
	if len(m) < 2 {
		return 0
	}
	d, err := time.ParseDuration(string(m[1]))
	if err != nil {
		return 0
	}
	// Keep it bounded so requests don't stall forever.
	if d < 0 {
		return 0
	}
	if d > 15*time.Second {
		return 15 * time.Second
	}
	return d
}

func geminiGenerateContentURL(baseURL, modelPath, apiKey, apiVersion string) string {
	apiVersion = strings.TrimSpace(apiVersion)
	if apiVersion == "" {
		apiVersion = "v1"
	}
	return fmt.Sprintf("%s/%s/%s:generateContent?key=%s", baseURL, apiVersion, modelPath, apiKey)
}

func isGeminiModelNotFoundForV1(status int, resBody []byte) bool {
	if status != http.StatusNotFound {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(string(resBody)))
	return strings.Contains(msg, "not found for api version v1") || strings.Contains(msg, "call listmodels")
}

func geminiPostWithRetry(ctx context.Context, url string, body []byte) (int, http.Header, []byte, error) {
	// Keep time bounded; Gemini overloads/timeouts should not stall the UI for minutes.
	client := &http.Client{Timeout: 20 * time.Second}

	// Small bounded retries for transient overloads (503) or rate limits (429).
	backoffs := []time.Duration{0, 900 * time.Millisecond}

	var lastStatus int
	var lastHeaders http.Header
	var lastBody []byte
	var lastErr error

	if cached, ok := getGeminiCached(url, body); ok {
		return http.StatusOK, nil, cached, nil
	}

	if llmDebugEnabled() {
		log.Printf("gemini -> request url=%s bytes=%d sha1=%s", redactAPIKeyInText(url), len(body), sha1Hex(body))
		if llmDebugBodiesEnabled() {
			log.Printf("gemini -> request body=%q", truncateForLog(redactLLMSecrets(string(body)), 1400))
		}
	}

	for attempt, wait := range backoffs {
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return lastStatus, lastHeaders, lastBody, ctx.Err()
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return 0, nil, nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		res, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("gemini request failed: %s", redactAPIKeyInText(err.Error()))
			if attempt < len(backoffs)-1 {
				log.Printf("gemini request failed (attempt=%d/%d): %s", attempt+1, len(backoffs), lastErr.Error())
				continue
			}
			return 0, nil, nil, lastErr
		}

		headers := res.Header.Clone()
		resBody, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()

		lastStatus = res.StatusCode
		lastHeaders = headers
		lastBody = resBody

		if res.StatusCode >= 200 && res.StatusCode < 300 {
			if llmDebugEnabled() {
				log.Printf("gemini <- response status=%d bytes=%d requestId=%s", res.StatusCode, len(resBody), strings.TrimSpace(headers.Get("x-goog-request-id")))
				if llmDebugBodiesEnabled() {
					log.Printf("gemini <- response bodyTail=%q", truncateForLog(redactLLMSecrets(tailBytes(resBody, 1400)), 1400))
				}
			}
			putGeminiCached(url, body, resBody)
			return res.StatusCode, headers, resBody, nil
		}

		trimmed := strings.TrimSpace(string(resBody))
		lastErr = fmt.Errorf("gemini error (HTTP %d): %s", res.StatusCode, trimmed)
		if isRetryableGeminiStatus(res.StatusCode) && attempt < len(backoffs)-1 {
			if res.StatusCode == http.StatusTooManyRequests {
				if d := parseGeminiRetryDelay(resBody); d > 0 {
					log.Printf("gemini rate limited; retrying after %s", d)
					select {
					case <-time.After(d):
					case <-ctx.Done():
						return lastStatus, lastHeaders, lastBody, ctx.Err()
					}
				}
			}
			log.Printf("gemini retryable error (attempt=%d/%d status=%d): %s", attempt+1, len(backoffs), res.StatusCode, truncateForError(trimmed, 300))
			continue
		}
		return res.StatusCode, headers, resBody, lastErr
	}

	return lastStatus, lastHeaders, lastBody, lastErr
}

func evaluateMaturityWithGemini(ctx context.Context, criteria []MaturityCriterion, ev MaturityEvidence, req MaturityAnalyzeRequest, cfg LLMRequestConfig) (MaturityReport, *LLMMetadata, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))
	}
	if apiKey == "" {
		return MaturityReport{}, nil, errGeminiNotConfigured
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

	promptObj := map[string]any{
		"targetLevel": strings.TrimSpace(req.TargetLevel),
		"evidence":    buildEvidenceForLLM(ev),
		"userNotes":   strings.TrimSpace(req.UserNotes),
		"userAnswers": req.Answers,
		"criteria":    criteria,
	}
	user := "INPUT_JSON=" + mustJSON(promptObj)

	// Gemini v1: roles are {user, model}. Keep the prompt schema minimal for compatibility:
	// - Put instructions + input into a single user message.
	// - Avoid responseMimeType/systemInstruction fields (not supported on all v1 models).
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
		return MaturityReport{}, nil, err
	}

	modelPath := model
	if !strings.HasPrefix(modelPath, "models/") {
		modelPath = "models/" + modelPath
	}

	urlV1 := geminiGenerateContentURL(baseURL, modelPath, apiKey, "v1")
	status, headers, resBody, err := geminiPostWithRetry(ctx, urlV1, b)
	if err != nil && isGeminiModelNotFoundForV1(status, resBody) {
		// Some older models (e.g. 1.5) are only available on v1beta.
		urlBeta := geminiGenerateContentURL(baseURL, modelPath, apiKey, "v1beta")
		log.Printf("gemini model not found on v1; falling back to v1beta (model=%s)", model)
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
		// Keep status/body in the error message for debugging.
		if status == 0 {
			return MaturityReport{}, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID}, err
		}
		return MaturityReport{}, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID}, fmt.Errorf("gemini error (HTTP %d): %s", status, strings.TrimSpace(string(resBody)))
	}

	var decoded geminiGenerateContentResponse
	if err := json.Unmarshal(resBody, &decoded); err != nil {
		return MaturityReport{}, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID}, fmt.Errorf("failed to parse gemini response: %w", err)
	}

	text := ""
	if len(decoded.Candidates) > 0 && len(decoded.Candidates[0].Content.Parts) > 0 {
		text = decoded.Candidates[0].Content.Parts[0].Text
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return MaturityReport{}, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID, TotalTokens: decoded.UsageMetadata.TotalTokenCount}, errors.New("gemini: empty content")
	}

	var out struct {
		OverallLevel   float64                  `json:"overallLevel"`
		CategoryScores []MaturityCategoryScore  `json:"categoryScores"`
		CriteriaScores []MaturityCriterionScore `json:"criteriaScores"`
		Notes          string                   `json:"notes"`
	}
	normalized := normalizeLLMJSON(text)
	if err := json.Unmarshal([]byte(normalized), &out); err != nil {
		return MaturityReport{}, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID, TotalTokens: decoded.UsageMetadata.TotalTokenCount}, fmt.Errorf("gemini JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
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
		Provider:    "gemini",
		Model:       model,
		RequestID:   requestID,
		TotalTokens: decoded.UsageMetadata.TotalTokenCount,
	}
	return report, meta, nil
}

func firstHeader(res *http.Response, keys ...string) string {
	if res == nil {
		return ""
	}
	for _, k := range keys {
		if v := strings.TrimSpace(res.Header.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

func generateQuestionsWithGemini(ctx context.Context, system, user string, cfg LLMRequestConfig) ([]MaturityQuestion, *LLMMetadata, error) {
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
		log.Printf("gemini model not found on v1; falling back to v1beta (model=%s)", model)
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
		if status == 0 {
			return nil, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID}, err
		}
		return nil, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID}, fmt.Errorf("gemini error (HTTP %d): %s", status, strings.TrimSpace(string(resBody)))
	}

	var decoded geminiGenerateContentResponse
	if err := json.Unmarshal(resBody, &decoded); err != nil {
		return nil, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID}, fmt.Errorf("failed to parse gemini response: %w", err)
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
		Questions []MaturityQuestion `json:"questions"`
	}
	normalized := normalizeLLMJSON(text)
	if err := json.Unmarshal([]byte(normalized), &out); err != nil {
		return nil, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID, TotalTokens: decoded.UsageMetadata.TotalTokenCount}, fmt.Errorf("gemini JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
	}

	meta := &LLMMetadata{
		Provider:    "gemini",
		Model:       model,
		RequestID:   requestID,
		TotalTokens: decoded.UsageMetadata.TotalTokenCount,
	}
	return out.Questions, meta, nil
}
