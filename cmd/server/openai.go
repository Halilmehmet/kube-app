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

type openAIChatCompletionRequest struct {
	Model          string                `json:"model"`
	Messages       []openAIChatMessage   `json:"messages"`
	Temperature    float64               `json:"temperature,omitempty"`
	ResponseFormat *openAIResponseFormat `json:"response_format,omitempty"`
}

type openAIResponseFormat struct {
	Type string `json:"type"`
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatCompletionResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Message openAIChatMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
}

func evaluateMaturityWithOpenAI(ctx context.Context, criteria []MaturityCriterion, ev MaturityEvidence, req MaturityAnalyzeRequest, cfg LLMRequestConfig) (MaturityReport, *LLMMetadata, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	}
	if apiKey == "" {
		return MaturityReport{}, nil, errLLMNotConfigured
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
		"targetLevel": strings.TrimSpace(req.TargetLevel),
		"evidence":    ev,
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

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return MaturityReport{}, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 90 * time.Second}
	res, err := client.Do(httpReq)
	if err != nil {
		return MaturityReport{}, nil, err
	}
	defer res.Body.Close()

	resBody, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return MaturityReport{}, &LLMMetadata{Provider: "openai", Model: model, RequestID: res.Header.Get("x-request-id")}, fmt.Errorf("openai error (HTTP %d): %s", res.StatusCode, strings.TrimSpace(string(resBody)))
	}

	var decoded openAIChatCompletionResponse
	if err := json.Unmarshal(resBody, &decoded); err != nil {
		return MaturityReport{}, &LLMMetadata{Provider: "openai", Model: model, RequestID: res.Header.Get("x-request-id")}, fmt.Errorf("failed to parse openai response: %w", err)
	}
	if len(decoded.Choices) == 0 {
		return MaturityReport{}, &LLMMetadata{Provider: "openai", Model: model, RequestID: decoded.ID}, errors.New("openai: empty choices")
	}
	content := strings.TrimSpace(decoded.Choices[0].Message.Content)
	if content == "" {
		return MaturityReport{}, &LLMMetadata{Provider: "openai", Model: model, RequestID: decoded.ID, TotalTokens: decoded.Usage.TotalTokens}, errors.New("openai: empty content")
	}

	var out struct {
		OverallLevel   float64                  `json:"overallLevel"`
		CategoryScores []MaturityCategoryScore  `json:"categoryScores"`
		CriteriaScores []MaturityCriterionScore `json:"criteriaScores"`
		Notes          string                   `json:"notes"`
	}
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		return MaturityReport{}, &LLMMetadata{Provider: "openai", Model: model, RequestID: decoded.ID, TotalTokens: decoded.Usage.TotalTokens}, fmt.Errorf("openai JSON parse failed: %w; content=%q", err, truncateForError(content, 2000))
	}

	report := MaturityReport{
		GeneratedAt:    time.Now(),
		Cluster:        ev.Cluster,
		OverallLevel:   out.OverallLevel,
		CategoryScores: out.CategoryScores,
		CriteriaScores: out.CriteriaScores,
		Notes:          strings.TrimSpace(out.Notes),
	}

	// Ensure we have all keys and fix obvious issues.
	fillMissingScores(&report, criteria)
	recomputeAggregates(&report)

	meta := &LLMMetadata{
		Provider:    "openai",
		Model:       model,
		RequestID:   decoded.ID,
		TotalTokens: decoded.Usage.TotalTokens,
	}
	return report, meta, nil
}

func fillMissingScores(report *MaturityReport, criteria []MaturityCriterion) {
	if report == nil {
		return
	}
	got := map[string]MaturityCriterionScore{}
	for _, cs := range report.CriteriaScores {
		got[cs.Key] = cs
	}
	out := make([]MaturityCriterionScore, 0, len(criteria))
	for _, c := range criteria {
		cs, ok := got[c.Key]
		if !ok {
			out = append(out, MaturityCriterionScore{
				Key:        c.Key,
				Category:   c.Category,
				Criterion:  c.Name,
				Level:      0,
				Confidence: 0.0,
				Rationale:  "Missing from LLM output.",
				Missing:    []string{"Rerun analysis; LLM output was incomplete."},
			})
			continue
		}
		if cs.Category == "" {
			cs.Category = c.Category
		}
		if cs.Criterion == "" {
			cs.Criterion = c.Name
		}
		if cs.Level < 0 || cs.Level > 5 {
			cs.Level = 0
			cs.Confidence = 0.0
			cs.Rationale = strings.TrimSpace(cs.Rationale + " (invalid level fixed)")
		}
		if cs.Confidence < 0 {
			cs.Confidence = 0
		}
		if cs.Confidence > 1 {
			cs.Confidence = 1
		}
		out = append(out, cs)
	}
	report.CriteriaScores = out
}

func truncateForError(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func generateQuestionsWithOpenAI(ctx context.Context, system, user string, cfg LLMRequestConfig) ([]MaturityQuestion, *LLMMetadata, error) {
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

	client := &http.Client{Timeout: 90 * time.Second}
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
		return nil, &LLMMetadata{Provider: "openai", Model: model, RequestID: res.Header.Get("x-request-id")}, fmt.Errorf("failed to parse openai response: %w", err)
	}
	if len(decoded.Choices) == 0 {
		return nil, &LLMMetadata{Provider: "openai", Model: model, RequestID: decoded.ID}, errors.New("openai: empty choices")
	}
	content := strings.TrimSpace(decoded.Choices[0].Message.Content)
	if content == "" {
		return nil, &LLMMetadata{Provider: "openai", Model: model, RequestID: decoded.ID, TotalTokens: decoded.Usage.TotalTokens}, errors.New("openai: empty content")
	}

	var out struct {
		Questions []MaturityQuestion `json:"questions"`
	}
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		return nil, &LLMMetadata{Provider: "openai", Model: model, RequestID: decoded.ID, TotalTokens: decoded.Usage.TotalTokens}, fmt.Errorf("openai JSON parse failed: %w; content=%q", err, truncateForError(content, 2000))
	}

	meta := &LLMMetadata{
		Provider:    "openai",
		Model:       model,
		RequestID:   decoded.ID,
		TotalTokens: decoded.Usage.TotalTokens,
	}
	return out.Questions, meta, nil
}
