package main

import (
	"context"
	"errors"
	"log"
	"math"
	"sort"
	"strings"
)

func generatePrecheckQuestionsBatched(
	ctx context.Context,
	provider string,
	system string,
	_ string, // unused legacy 'user' string
	candidates []questionCandidate,
	choices []string,
	req MaturityQuestionsRequest,
	cfg LLMRequestConfig,
	ev MaturityEvidence,
) ([]MaturityQuestion, *LLMMetadata, string) {
	batchSize := envInt("LLM_QUESTIONS_BATCH_SIZE", 6)
	concurrency := envInt("LLM_QUESTIONS_CONCURRENCY", 6)
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "openrouter":
		batchSize = envInt("LLM_QUESTIONS_BATCH_SIZE_OPENROUTER", 4)
		concurrency = envInt("LLM_QUESTIONS_CONCURRENCY_OPENROUTER", 1)
	}

	// Small inputs: keep single call (better global ranking).
	if len(candidates) <= batchSize || req.MaxQuestions <= 10 {
		return generatePrecheckQuestionsSingle(ctx, provider, system, candidates, choices, req, cfg, ev)
	}

	// Split candidates; keep batches small for model latency and avoid giant prompts.
	batches := chunkSlice(candidates, batchSize)
	maxQ := req.MaxQuestions
	if maxQ <= 0 {
		maxQ = 20
	}

	// Assign a small quota per batch, then merge & trim.
	perBatch := int(math.Ceil(float64(maxQ) / float64(len(batches))))
	if perBatch < 2 {
		perBatch = 2
	}
	if perBatch > 8 {
		perBatch = 8
	}

	type batchOut struct {
		Questions []MaturityQuestion
		Meta      *LLMMetadata
		Err       error
	}

	runOne := func(ctx context.Context, batch []questionCandidate) (batchOut, error) {
		localReq := req
		localReq.MaxQuestions = perBatch
		out, meta, errStr := generatePrecheckQuestionsSingle(ctx, provider, system, batch, choices, localReq, cfg, ev)
		if errStr != "" && meta == nil {
			// preserve the note in logs; caller will handle fallback.
			return batchOut{Questions: nil, Meta: nil, Err: errors.New(errStr)}, nil
		}
		// Here, errStr is used as a note; single generator already falls back to heuristic if LLM fails.
		// Treat it as non-fatal so we can still merge.
		_ = errStr
		return batchOut{Questions: out, Meta: meta, Err: nil}, nil
	}

	outs, _ := runBatched(ctx, batches, concurrency, runOne)

	var meta *LLMMetadata
	var all []MaturityQuestion
	for _, o := range outs {
		if o.Meta != nil && meta == nil {
			meta = o.Meta
		}
		if len(o.Questions) > 0 {
			all = append(all, o.Questions...)
		}
	}

	if len(all) == 0 {
		// Nothing produced; fall back to heuristic.
		return fallbackQuestions(candidates, choices), meta, "No LLM questions; fallback"
	}

	merged := normalizePrecheckQuestions(all, candidates, choices)
	// Ensure deterministic stable priority.
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].Priority == merged[j].Priority {
			return merged[i].Key < merged[j].Key
		}
		return merged[i].Priority < merged[j].Priority
	})
	if len(merged) > maxQ {
		merged = merged[:maxQ]
	}

	// Reassign priorities 1..N after trimming.
	for i := range merged {
		merged[i].Priority = i + 1
	}

	return merged, meta, ""
}

func generatePrecheckQuestionsSingle(
	ctx context.Context,
	provider string,
	system string,
	candidates []questionCandidate,
	choices []string,
	req MaturityQuestionsRequest,
	cfg LLMRequestConfig,
	ev MaturityEvidence,
) ([]MaturityQuestion, *LLMMetadata, string) {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "" {
		p = "gemini"
	}

	promptObj := map[string]any{
		"cluster":      ev.Cluster,
		"maxQuestions": req.MaxQuestions,
		"userNotes":    strings.TrimSpace(req.UserNotes),
		"evidence": map[string]any{
			"kubernetesVersion": ev.KubernetesVersion,
			"nodeCount":         ev.NodeCount,
			"zones":             ev.Zones,
			"detectedAddons":    ev.DetectedAddons,
			"permissions":       ev.Permissions,
			"kubectl":           summarizeKubectlForPrecheck(ev.Kubectl),
		},
		"candidates": candidates,
		"choices":    choices,
	}
	user := "INPUT_JSON=" + mustJSON(promptObj)

	switch p {
	case "openai":
		out, meta, err := generateQuestionsWithOpenAI(ctx, system, user, cfg)
		if err == nil && len(out) > 0 {
			return normalizePrecheckQuestions(out, candidates, choices), meta, ""
		}
		if err != nil {
			log.Printf("LLM precheck questions failed (provider=openai model=%s): %v", cfg.Model, err)
		}
		return fallbackQuestions(candidates, choices), meta, errString(err)
	case "openrouter":
		out, meta, err := generateQuestionsWithOpenRouter(ctx, system, user, cfg)
		if err == nil && len(out) > 0 {
			return normalizePrecheckQuestions(out, candidates, choices), meta, ""
		}
		if err != nil {
			log.Printf("LLM precheck questions failed (provider=openrouter model=%s): %v", cfg.Model, err)
		}
		return fallbackQuestions(candidates, choices), meta, errString(err)
	case "gemini":
		out, meta, err := generateQuestionsWithGemini(ctx, system, user, cfg)
		if err == nil && len(out) > 0 {
			return normalizePrecheckQuestions(out, candidates, choices), meta, ""
		}
		if err != nil {
			log.Printf("LLM precheck questions failed (provider=gemini model=%s): %v", cfg.Model, err)
		}
		return fallbackQuestions(candidates, choices), meta, errString(err)
	default:
		return fallbackQuestions(candidates, choices), nil, "Unknown LLM provider"
	}
}
