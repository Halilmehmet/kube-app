package main

import (
	"context"
	"log"
	"math"
	"sort"
	"strings"
	"time"
)

func evaluateMaturityBatched(ctx context.Context, provider string, criteria []MaturityCriterion, ev MaturityEvidence, req MaturityAnalyzeRequest, cfg LLMRequestConfig) (MaturityReport, *LLMMetadata, error) {
	batchSize := envInt("LLM_ANALYZE_BATCH_SIZE", 5)
	concurrency := envInt("LLM_ANALYZE_CONCURRENCY", 6)
	skipConfidence := float64(envInt("LLM_ANALYZE_SKIP_INFERRED_CONFIDENCE_X100", 70)) / 100.0
	maxLLMCriteria := envInt("LLM_ANALYZE_MAX_CRITERIA", 18)
	if batchSize < 1 {
		batchSize = 1
	}

	// Seed baseline scores from inferred results (fast), so partial LLM failures still return a full report.
	inferredByKey := map[string]MaturityCriterionScore{}
	for _, s := range ev.InferredScores {
		if strings.TrimSpace(s.Key) == "" {
			continue
		}
		inferredByKey[s.Key] = s
	}

	scoreByKey := map[string]MaturityCriterionScore{}
	var llmCriteria []MaturityCriterion
	for _, c := range criteria {
		key := strings.TrimSpace(c.Key)
		if key == "" {
			continue
		}

		// Baseline: inferred score if present, else unscored placeholder with concrete missing questions.
		if inf, ok := inferredByKey[key]; ok && (inf.Level > 0 || inf.Confidence > 0 || strings.TrimSpace(inf.Rationale) != "") {
			inf.Key = key
			if strings.TrimSpace(inf.Category) == "" {
				inf.Category = c.Category
			}
			if strings.TrimSpace(inf.Criterion) == "" {
				inf.Criterion = c.Name
			}
			scoreByKey[key] = inf
		} else {
			scoreByKey[key] = MaturityCriterionScore{
				Key:        key,
				Category:   c.Category,
				Criterion:  c.Name,
				Level:      0,
				Confidence: 0,
				Rationale:  "Bilgi bulunamadı / skorlanmadı.",
				Missing:    defaultMissingQuestions(c),
			}
		}

		// Skip LLM if user already selected a level (override).
		if v, ok := req.Overrides[key]; ok && v >= 1 && v <= 5 {
			continue
		}

		// Skip LLM when inferred looks solid to speed up (LLM only for low-confidence / suspicious).
		if inf, ok := inferredByKey[key]; ok && inf.Level > 0 && inf.Confidence >= skipConfidence && !isSuspiciousInferredScore(&inf) {
			continue
		}
		llmCriteria = append(llmCriteria, c)
	}

	// Keep LLM workload bounded; prioritize lowest-confidence/suspicious criteria.
	if maxLLMCriteria > 0 && len(llmCriteria) > maxLLMCriteria {
		score := func(c MaturityCriterion) float64 {
			key := strings.TrimSpace(c.Key)
			if key == "" {
				return 1e9
			}
			inf, ok := inferredByKey[key]
			if !ok || inf.Level <= 0 {
				return 9e8
			}
			s := (1.0 - inf.Confidence) * 1000
			if isSuspiciousInferredScore(&inf) {
				s += 250
			}
			// Prefer "unknown" criteria where inferred is basically absent.
			if inf.Confidence <= 0 {
				s += 100
			}
			if math.IsNaN(s) || math.IsInf(s, 0) {
				return 1e9
			}
			return s
		}
		sort.SliceStable(llmCriteria, func(i, j int) bool { return score(llmCriteria[i]) > score(llmCriteria[j]) })
		llmCriteria = llmCriteria[:maxLLMCriteria]
	}

	// If nothing needs LLM, just return baseline.
	if len(llmCriteria) == 0 {
		report := MaturityReport{
			GeneratedAt:    time.Now(),
			Cluster:        ev.Cluster,
			CriteriaScores: make([]MaturityCriterionScore, 0, len(criteria)),
			Notes:          strings.TrimSpace(req.UserNotes),
		}
		for _, c := range criteria {
			if s, ok := scoreByKey[c.Key]; ok {
				report.CriteriaScores = append(report.CriteriaScores, s)
			}
		}
		applyOverrides(&report, req.Overrides)
		recomputeAggregates(&report)
		return report, nil, nil
	}

	// Group by category, then chunk within each category for parallelism.
	byCat := map[string][]MaturityCriterion{}
	var cats []string
	for _, c := range llmCriteria {
		k := strings.TrimSpace(c.Category)
		if k == "" {
			k = "Other"
		}
		if _, ok := byCat[k]; !ok {
			cats = append(cats, k)
		}
		byCat[k] = append(byCat[k], c)
	}
	sort.Strings(cats)

	var batches [][]MaturityCriterion
	for _, cat := range cats {
		chunks := chunkSlice(byCat[cat], batchSize)
		batches = append(batches, chunks...)
	}

	type batchRes struct {
		Scores []MaturityCriterionScore
		Meta   *LLMMetadata
	}

	runOne := func(ctx context.Context, batch []MaturityCriterion) (batchRes, error) {
		scores, meta, err := evaluateCriteriaScores(ctx, provider, batch, ev, req, cfg)
		if err != nil {
			return batchRes{}, err
		}
		return batchRes{Scores: scores, Meta: meta}, nil
	}

	outs, errs := runBatched(ctx, batches, concurrency, runOne)

	var meta *LLMMetadata
	var anySuccess bool

	for i := range outs {
		if errs[i] != nil {
			log.Printf("LLM batch failed (provider=%s model=%s): %v", provider, cfg.Model, errs[i])
			continue
		}
		anySuccess = true
		if meta == nil && outs[i].Meta != nil {
			meta = outs[i].Meta
		}
		for _, s := range outs[i].Scores {
			if strings.TrimSpace(s.Key) == "" {
				continue
			}
			scoreByKey[s.Key] = s
		}
	}

	if !anySuccess {
		// Return the first error as representative.
		for _, e := range errs {
			if e != nil {
				// Return baseline report with error (caller will fall back to non-LLM if desired).
				report := MaturityReport{
					GeneratedAt:    time.Now(),
					Cluster:        ev.Cluster,
					CriteriaScores: make([]MaturityCriterionScore, 0, len(criteria)),
					Notes:          strings.TrimSpace(req.UserNotes),
				}
				for _, c := range criteria {
					if s, ok := scoreByKey[c.Key]; ok {
						report.CriteriaScores = append(report.CriteriaScores, s)
					}
				}
				applyOverrides(&report, req.Overrides)
				recomputeAggregates(&report)
				return report, meta, e
			}
		}
		report := MaturityReport{
			GeneratedAt:    time.Now(),
			Cluster:        ev.Cluster,
			CriteriaScores: make([]MaturityCriterionScore, 0, len(criteria)),
			Notes:          strings.TrimSpace(req.UserNotes),
		}
		for _, c := range criteria {
			if s, ok := scoreByKey[c.Key]; ok {
				report.CriteriaScores = append(report.CriteriaScores, s)
			}
		}
		applyOverrides(&report, req.Overrides)
		recomputeAggregates(&report)
		return report, meta, context.Canceled
	}

	// Build report from merged scores and recompute aggregates server-side.
	finalScores := make([]MaturityCriterionScore, 0, len(criteria))
	for _, c := range criteria {
		if s, ok := scoreByKey[c.Key]; ok {
			finalScores = append(finalScores, s)
		}
	}

	report := MaturityReport{
		GeneratedAt:    time.Now(),
		Cluster:        ev.Cluster,
		CriteriaScores: finalScores,
		Notes:          strings.TrimSpace(req.UserNotes),
	}

	applyOverrides(&report, req.Overrides)
	recomputeAggregates(&report)
	return report, meta, nil
}
