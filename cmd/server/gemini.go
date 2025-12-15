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
		"evidence":    ev,
		"userNotes":   strings.TrimSpace(req.UserNotes),
		"userAnswers": req.Answers,
		"criteria":    criteria,
	}
	user := "INPUT_JSON=" + mustJSON(promptObj)

	// Use only one JSON field casing; Gemini treats camelCase/snake_case as the same oneof.
	contents := []map[string]any{
		{
			"role":  "system",
			"parts": []map[string]string{{"text": system}},
		},
		{
			"role":  "user",
			"parts": []map[string]string{{"text": user}},
		},
	}
	body := map[string]any{
		"contents":         contents,
		"temperature":      0.2,
		"responseMimeType": "application/json",
	}

	b, err := json.Marshal(body)
	if err != nil {
		return MaturityReport{}, nil, err
	}

	modelPath := model
	if !strings.HasPrefix(modelPath, "models/") {
		modelPath = "models/" + modelPath
	}

	url := fmt.Sprintf("%s/v1beta/%s:generateContent?key=%s", baseURL, modelPath, apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return MaturityReport{}, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 90 * time.Second}
	res, err := client.Do(httpReq)
	if err != nil {
		return MaturityReport{}, nil, err
	}
	defer res.Body.Close()

	resBody, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return MaturityReport{}, &LLMMetadata{Provider: "gemini", Model: model, RequestID: firstHeader(res, "x-goog-request-id", "x-request-id")}, fmt.Errorf("gemini error (HTTP %d): %s", res.StatusCode, strings.TrimSpace(string(resBody)))
	}

	var decoded geminiGenerateContentResponse
	if err := json.Unmarshal(resBody, &decoded); err != nil {
		return MaturityReport{}, &LLMMetadata{Provider: "gemini", Model: model, RequestID: firstHeader(res, "x-goog-request-id", "x-request-id")}, fmt.Errorf("failed to parse gemini response: %w", err)
	}

	text := ""
	if len(decoded.Candidates) > 0 && len(decoded.Candidates[0].Content.Parts) > 0 {
		text = decoded.Candidates[0].Content.Parts[0].Text
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return MaturityReport{}, &LLMMetadata{Provider: "gemini", Model: model, RequestID: firstHeader(res, "x-goog-request-id", "x-request-id"), TotalTokens: decoded.UsageMetadata.TotalTokenCount}, errors.New("gemini: empty content")
	}

	var out struct {
		OverallLevel   float64                  `json:"overallLevel"`
		CategoryScores []MaturityCategoryScore  `json:"categoryScores"`
		CriteriaScores []MaturityCriterionScore `json:"criteriaScores"`
		Notes          string                   `json:"notes"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return MaturityReport{}, &LLMMetadata{Provider: "gemini", Model: model, RequestID: firstHeader(res, "x-goog-request-id", "x-request-id"), TotalTokens: decoded.UsageMetadata.TotalTokenCount}, fmt.Errorf("gemini JSON parse failed: %w; content=%q", err, truncateForError(text, 2000))
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
		RequestID:   firstHeader(res, "x-goog-request-id", "x-request-id"),
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
		{
			"role":  "system",
			"parts": []map[string]string{{"text": system}},
		},
		{
			"role":  "user",
			"parts": []map[string]string{{"text": user}},
		},
	}
	body := map[string]any{
		"contents":         contents,
		"temperature":      0.2,
		"responseMimeType": "application/json",
	}

	b, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}

	modelPath := model
	if !strings.HasPrefix(modelPath, "models/") {
		modelPath = "models/" + modelPath
	}

	url := fmt.Sprintf("%s/v1beta/%s:generateContent?key=%s", baseURL, modelPath, apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 90 * time.Second}
	res, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	resBody, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	requestID := firstHeader(res, "x-goog-request-id", "x-request-id")
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, &LLMMetadata{Provider: "gemini", Model: model, RequestID: requestID}, fmt.Errorf("gemini error (HTTP %d): %s", res.StatusCode, strings.TrimSpace(string(resBody)))
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
	if err := json.Unmarshal([]byte(text), &out); err != nil {
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
