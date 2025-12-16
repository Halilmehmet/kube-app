package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

type LLMMetadata struct {
	Provider    string `json:"provider"`
	Model       string `json:"model,omitempty"`
	RequestID   string `json:"requestId,omitempty"`
	TotalTokens int    `json:"totalTokens,omitempty"`
}

type LLMRequestConfig struct {
	Provider string `json:"provider,omitempty"` // auto|openai|gemini|none
	Model    string `json:"model,omitempty"`
	APIKey   string `json:"apiKey,omitempty"`
	BaseURL  string `json:"baseUrl,omitempty"`
}

var errLLMNotConfigured = errors.New("LLM not configured (set OPENAI_API_KEY)")

type questionCandidate struct {
	Criterion MaturityCriterion       `json:"criterion"`
	Inferred  *MaturityCriterionScore `json:"inferred,omitempty"`
}

func isSuspiciousInferredScore(s *MaturityCriterionScore) bool {
	if s == nil {
		return true
	}
	r := strings.ToLower(strings.TrimSpace(s.Rationale))
	if r == "" {
		return true
	}
	markers := []string{
		"doğrulanmad",
		"dogrulanmad",
		"varsay",
		"şüphe",
		"suphe",
		"kontrol edilmeli",
		"doğrulanmalı",
		"dogrulanmali",
		"crd eksik olabilir",
		"izin",
		"permission",
	}
	for _, m := range markers {
		if strings.Contains(r, m) {
			return true
		}
	}
	return false
}

func EvaluateMaturity(ctx context.Context, doc MaturityCriteriaDoc, ev MaturityEvidence, req MaturityAnalyzeRequest) (MaturityReport, *LLMMetadata, error) {
	flattened := flattenCriteria(doc)

	var (
		report  MaturityReport
		llmMeta *LLMMetadata
		err     error
	)

	// UI stores wizard choices as "L3 — note..." in answers; treat as overrides to avoid extra LLM work.
	if ov := overridesFromAnswers(req.Answers); len(ov) > 0 {
		if req.Overrides == nil {
			req.Overrides = map[string]int{}
		}
		for k, v := range ov {
			if _, exists := req.Overrides[k]; !exists {
				req.Overrides[k] = v
			}
		}
	}

	cfg := normalizeLLMConfig(req.LLM)
	if cfg.Provider == "" {
		cfg.Provider = strings.ToLower(strings.TrimSpace(os.Getenv("LLM_PROVIDER")))
	}

	switch cfg.Provider {
	case "":
		// Auto-select
		if strings.TrimSpace(cfg.APIKey) != "" {
			// If UI provided a key but not provider, default to Gemini unless model hints OpenAI/OpenRouter.
			// OpenRouter models are often "provider/model".
			if strings.Contains(cfg.Model, "/") {
				report, llmMeta, err = evaluateMaturityBatched(ctx, "openrouter", flattened, ev, req, cfg)
			} else if strings.Contains(strings.ToLower(cfg.Model), "gpt") || strings.Contains(strings.ToLower(cfg.Model), "openai") {
				report, llmMeta, err = evaluateMaturityBatched(ctx, "openai", flattened, ev, req, cfg)
			} else {
				report, llmMeta, err = evaluateMaturityBatched(ctx, "gemini", flattened, ev, req, cfg)
			}
		} else if strings.TrimSpace(os.Getenv("OPENAI_API_KEY")) != "" {
			report, llmMeta, err = evaluateMaturityBatched(ctx, "openai", flattened, ev, req, cfg)
		} else if strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) != "" {
			report, llmMeta, err = evaluateMaturityBatched(ctx, "openrouter", flattened, ev, req, cfg)
		} else if strings.TrimSpace(os.Getenv("GEMINI_API_KEY")) != "" {
			report, llmMeta, err = evaluateMaturityBatched(ctx, "gemini", flattened, ev, req, cfg)
		} else {
			report = evaluateMaturityWithoutLLM(flattened, ev, req, "LLM not configured (set OPENAI_API_KEY or GEMINI_API_KEY)")
		}
	case "openai":
		report, llmMeta, err = evaluateMaturityBatched(ctx, "openai", flattened, ev, req, cfg)
	case "openrouter":
		report, llmMeta, err = evaluateMaturityBatched(ctx, "openrouter", flattened, ev, req, cfg)
	case "gemini":
		report, llmMeta, err = evaluateMaturityBatched(ctx, "gemini", flattened, ev, req, cfg)
	case "none", "off", "disabled":
		report = evaluateMaturityWithoutLLM(flattened, ev, req, "LLM disabled (LLM_PROVIDER)")
	default:
		report = evaluateMaturityWithoutLLM(flattened, ev, req, "Unknown LLM_PROVIDER; use openai|gemini|none")
	}

	if err != nil {
		// If we have a usable report (inferred baseline), prefer returning it with a note.
		log.Printf("LLM evaluate failed (provider=%s model=%s): %v", cfg.Provider, cfg.Model, err)
		if len(report.CriteriaScores) > 0 {
			if strings.TrimSpace(report.Notes) == "" {
				report.Notes = "LLM error: " + err.Error()
			} else {
				report.Notes = strings.TrimSpace(report.Notes) + " | LLM error: " + err.Error()
			}
			applyOverrides(&report, req.Overrides)
			recomputeAggregates(&report)
			return report, llmMeta, nil
		}
		report = evaluateMaturityWithoutLLM(flattened, ev, req, err.Error())
		return report, llmMeta, nil
	}

	applyOverrides(&report, req.Overrides)
	recomputeAggregates(&report)
	return report, llmMeta, nil
}

func overridesFromAnswers(answers map[string]string) map[string]int {
	if len(answers) == 0 {
		return nil
	}
	out := map[string]int{}
	for k, v := range answers {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) < 2 {
			continue
		}
		if v[0] != 'L' && v[0] != 'l' {
			continue
		}
		if v[1] < '1' || v[1] > '5' {
			continue
		}
		out[k] = int(v[1] - '0')
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeLLMConfig(cfg *LLMRequestConfig) LLMRequestConfig {
	if cfg == nil {
		return LLMRequestConfig{}
	}
	out := *cfg
	out.Provider = strings.ToLower(strings.TrimSpace(out.Provider))
	out.Model = strings.TrimSpace(out.Model)
	out.APIKey = strings.TrimSpace(out.APIKey)
	out.BaseURL = strings.TrimSpace(out.BaseURL)
	return out
}

func flattenCriteria(doc MaturityCriteriaDoc) []MaturityCriterion {
	var out []MaturityCriterion
	for _, c := range doc.Categories {
		for _, cr := range c.Criteria {
			out = append(out, cr)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category == out[j].Category {
			return out[i].Name < out[j].Name
		}
		return out[i].Category < out[j].Category
	})
	return out
}

func evaluateMaturityWithoutLLM(criteria []MaturityCriterion, ev MaturityEvidence, req MaturityAnalyzeRequest, note string) MaturityReport {
	scores := make([]MaturityCriterionScore, 0, len(criteria))
	for _, c := range criteria {
		level := 0
		conf := 0.0
		rationale := "Bilgi bulunamadı / skorlanmadı."
		missing := defaultMissingQuestions(c)
		if note != "" {
			missing = append(missing, note)
		}
		if v, ok := req.Overrides[c.Key]; ok && v >= 1 && v <= 5 {
			level = v
			conf = 1
			rationale = "User override."
			missing = nil
		}
		scores = append(scores, MaturityCriterionScore{
			Key:        c.Key,
			Category:   c.Category,
			Criterion:  c.Name,
			Level:      level,
			Confidence: conf,
			Rationale:  rationale,
			Evidence: []string{
				fmt.Sprintf("kubernetesVersion=%s", ev.KubernetesVersion),
				fmt.Sprintf("nodeCount=%d", ev.NodeCount),
				fmt.Sprintf("namespaceCount=%d", ev.NamespaceCount),
			},
			Missing: missing,
		})
	}
	report := MaturityReport{
		GeneratedAt:    time.Now(),
		Cluster:        ev.Cluster,
		CriteriaScores: scores,
		Notes:          strings.TrimSpace(req.UserNotes),
	}
	recomputeAggregates(&report)
	return report
}

func defaultMissingQuestions(c MaturityCriterion) []string {
	var out []string
	out = append(out, "İstenen: L1–L5 seviyesini seçin ve 1-2 cümleyle nedenini yazın.")
	out = append(out, "Kanıt: en az 1 adet ekleyin (YAML snippet/link, `kubectl ... -o yaml` çıktısı, dashboard ekran görüntüsü, runbook/ADR linki).")
	if display := strings.TrimSpace(c.Name); display != "" {
		cmds := strings.Join(suggestKubectlCommandsForCriterion(display), "` / `")
		if strings.TrimSpace(cmds) != "" {
			out = append(out, fmt.Sprintf("Kontrol: %s kriterini doğrulamak için şu komutlardan birinin çıktısını ekleyin (örn. `%s`).", display, cmds))
		} else {
			out = append(out, fmt.Sprintf("Kontrol: %s kriterini doğrulamak için ilgili YAML/rapor çıktısını ekleyin.", display))
		}
	}
	if len(c.Levels) == 5 {
		var opts []string
		for i, v := range c.Levels {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			opts = append(opts, fmt.Sprintf("L%d=%s", i+1, truncateForQuestion(v, 70)))
		}
		if len(opts) > 0 {
			out = append(out, "Seviye tanımları (özet): "+strings.Join(opts, " | "))
		}
	}
	return out
}

func suggestKubectlCommandsForCriterion(criterionName string) []string {
	name := strings.ToLower(strings.TrimSpace(criterionName))
	var cmds []string
	add := func(values ...string) {
		for _, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			cmds = append(cmds, v)
		}
	}
	switch {
	case strings.Contains(name, "networkpolicy") || strings.Contains(name, "egress") || strings.Contains(name, "cilium"):
		add("kubectl get networkpolicy -A", "kubectl get ciliumnetworkpolicies -A", "kubectl get ciliumclusterwidenetworkpolicies")
	case strings.Contains(name, "ingress"):
		add("kubectl get ingress -A", "kubectl get ingressclass", "kubectl get svc -A")
	case strings.Contains(name, "cert") || strings.Contains(name, "tls"):
		add("kubectl get certificates -A", "kubectl get issuers -A", "kubectl get clusterissuers", "kubectl get ingress -A -o yaml")
	case strings.Contains(name, "prometheus") || strings.Contains(name, "metrics") || strings.Contains(name, "scrape"):
		add("kubectl get prometheusrules -A", "kubectl get servicemonitors -A", "kubectl get podmonitors -A")
	case strings.Contains(name, "grafana") || strings.Contains(name, "dashboard"):
		add("kubectl get deploy -A | grep -i grafana", "kubectl get svc -A | grep -i grafana")
	case strings.Contains(name, "log") || strings.Contains(name, "loki"):
		add("kubectl get deploy -A | grep -i loki", "kubectl get pods -A | grep -i loki")
	case strings.Contains(name, "velero") || strings.Contains(name, "backup") || strings.Contains(name, "restore") || strings.Contains(name, "dr"):
		add("kubectl get schedules.velero.io -n velero", "kubectl get backupstoragelocations.velero.io -n velero -o yaml", "kubectl get backups.velero.io -A", "kubectl get restores.velero.io -A")
	case strings.Contains(name, "longhorn"):
		add("kubectl get backups.longhorn.io -A", "kubectl get restores.longhorn.io -A", "kubectl get pods -n longhorn-system")
	case strings.Contains(name, "hpa"):
		add("kubectl get hpa -A", "kubectl get deploy -A")
	case strings.Contains(name, "resourcequota"):
		add("kubectl get resourcequota -A -o yaml")
	case strings.Contains(name, "limitrange"):
		add("kubectl get limitrange -A -o yaml")
	case strings.Contains(name, "service account") || strings.Contains(name, "rbac") || strings.Contains(name, "cluster-admin"):
		add("kubectl get sa -A", "kubectl get clusterrolebinding", "kubectl get rolebinding -A")
	default:
		add("kubectl get all -A", "kubectl get ns -o yaml")
	}

	seen := map[string]bool{}
	unique := make([]string, 0, len(cmds))
	for _, c := range cmds {
		if seen[c] {
			continue
		}
		seen[c] = true
		unique = append(unique, c)
	}
	if len(unique) > 3 {
		unique = unique[:3]
	}
	return unique
}

func truncateForQuestion(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.TrimSpace(s[:max]) + "..."
}

func applyOverrides(report *MaturityReport, overrides map[string]int) {
	if report == nil || len(overrides) == 0 {
		return
	}
	for i := range report.CriteriaScores {
		if v, ok := overrides[report.CriteriaScores[i].Key]; ok && v >= 1 && v <= 5 {
			report.CriteriaScores[i].Level = v
			report.CriteriaScores[i].Confidence = 1
			if report.CriteriaScores[i].Rationale == "" {
				report.CriteriaScores[i].Rationale = "User override."
			} else if !strings.Contains(strings.ToLower(report.CriteriaScores[i].Rationale), "override") {
				report.CriteriaScores[i].Rationale = strings.TrimSpace(report.CriteriaScores[i].Rationale + " (user override)")
			}
		}
	}
}

func recomputeAggregates(report *MaturityReport) {
	if report == nil {
		return
	}
	if len(report.CriteriaScores) == 0 {
		report.OverallLevel = 0
		report.CategoryScores = nil
		return
	}

	byCat := map[string][]int{}
	for _, cs := range report.CriteriaScores {
		if cs.Level <= 0 {
			continue
		}
		byCat[cs.Category] = append(byCat[cs.Category], cs.Level)
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	var categoryScores []MaturityCategoryScore
	var overallSum float64
	for _, cat := range cats {
		levels := byCat[cat]
		if len(levels) == 0 {
			continue
		}
		sum := 0
		for _, v := range levels {
			sum += v
		}
		avg := float64(sum) / float64(len(levels))
		avg = math.Round(avg*10) / 10
		categoryScores = append(categoryScores, MaturityCategoryScore{Category: cat, Level: avg})
		overallSum += avg
	}
	report.CategoryScores = categoryScores
	if len(categoryScores) > 0 {
		report.OverallLevel = math.Round((overallSum/float64(len(categoryScores)))*10) / 10
	} else {
		report.OverallLevel = 0
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func GeneratePrecheckQuestions(ctx context.Context, doc MaturityCriteriaDoc, ev MaturityEvidence, req MaturityQuestionsRequest) ([]MaturityQuestion, *LLMMetadata, string) {
	criteria := flattenCriteria(doc)
	inferredByKey := map[string]MaturityCriterionScore{}
	for _, s := range ev.InferredScores {
		inferredByKey[s.Key] = s
	}

	var candidates []questionCandidate
	for _, c := range criteria {
		if v, ok := req.Answers[c.Key]; ok && strings.TrimSpace(v) != "" {
			continue
		}
		inf, ok := inferredByKey[c.Key]
		if !ok || inf.Level <= 0 || inf.Confidence < req.MinConfidence || isSuspiciousInferredScore(&inf) {
			var ptr *MaturityCriterionScore
			if ok {
				cp := inf
				ptr = &cp
			}
			candidates = append(candidates, questionCandidate{Criterion: c, Inferred: ptr})
		}
	}
	if len(candidates) == 0 {
		return nil, nil, "No missing/low-confidence criteria."
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		score := func(c questionCandidate) float64 {
			if c.Inferred == nil {
				return 1e9
			}
			if c.Inferred.Level <= 0 {
				return 9e8
			}
			s := (1.0 - c.Inferred.Confidence) * 1000
			if isSuspiciousInferredScore(c.Inferred) {
				s += 250
			}
			return s
		}
		return score(candidates[i]) > score(candidates[j])
	})

	if len(candidates) > req.MaxQuestions {
		candidates = candidates[:req.MaxQuestions]
	}

	cfg := normalizeLLMConfig(req.LLM)
	if cfg.Provider == "" {
		cfg.Provider = strings.ToLower(strings.TrimSpace(os.Getenv("LLM_PROVIDER")))
	}

	// Always use quick choices for speed.
	choices := []string{"L1", "L2", "L3", "L4", "L5", "Bilmiyorum"}

	system := `You generate a short, clear questionnaire for a Kubernetes maturity assessment.
	You receive rubric criteria + precheck results (level/confidence/rationale) and cluster evidence summary.
	Return ONLY valid JSON (no markdown) with:
	{ "questions": [ { "key": string, "category": string, "criterion": string, "question": string, "choices": ["L1","L2","L3","L4","L5","Bilmiyorum"], "hints": string[], "priority": number } ] }
	Rules:
	- Ask at most maxQuestions (use the provided candidates list as the pool).
	- Make each question specific to the criterion.
	- Question must be readable and self-contained (no shorthand).
	- Avoid generic “Hangi seviye?” questions; ask for concrete facts/evidence that decide L1-L5.
	- Provide 2-4 hints to help the user answer quickly; each hint must explicitly state what is required (use prefixes like "İstenen:" / "Kanıt:" when possible), plus where to look + kubectl commands + example evidence.
	- Include a short level summary hint when possible.
	- Use the provided choices exactly.
	- priority: 1..N (1 is highest).`

	switch cfg.Provider {
	case "openai":
		return generatePrecheckQuestionsBatched(ctx, "openai", system, "", candidates, choices, req, cfg, ev)
	case "openrouter":
		return generatePrecheckQuestionsBatched(ctx, "openrouter", system, "", candidates, choices, req, cfg, ev)
	case "gemini", "":
		// If provider unspecified, we try gemini first, then fall back.
		return generatePrecheckQuestionsBatched(ctx, "gemini", system, "", candidates, choices, req, cfg, ev)
	case "none", "off", "disabled":
		return fallbackQuestions(candidates, choices), nil, "LLM disabled"
	default:
		return fallbackQuestions(candidates, choices), nil, "Unknown LLM provider"
	}
}

func normalizePrecheckQuestions(in []MaturityQuestion, candidates []questionCandidate, choices []string) []MaturityQuestion {
	byKey := map[string]questionCandidate{}
	byName := map[string]questionCandidate{}
	for _, c := range candidates {
		byKey[c.Criterion.Key] = c
		byName[strings.ToLower(strings.TrimSpace(c.Criterion.Name))] = c
	}

	formatInferredHint := func(s *MaturityCriterionScore) string {
		if s == nil || s.Level <= 0 {
			return ""
		}
		conf := ""
		if s.Confidence > 0 {
			conf = fmt.Sprintf(" (~%.0f%%)", s.Confidence*100)
		}
		r := strings.TrimSpace(s.Rationale)
		if r != "" {
			r = truncateForQuestion(r, 120)
			return fmt.Sprintf("Ön tespit: L%d%s — %s", s.Level, conf, r)
		}
		return fmt.Sprintf("Ön tespit: L%d%s", s.Level, conf)
	}

	out := make([]MaturityQuestion, 0, len(in))
	seen := map[string]bool{}
	for i, q := range in {
		q.Key = strings.TrimSpace(q.Key)
		if q.Key == "" {
			nameKey := strings.ToLower(strings.TrimSpace(q.Criterion))
			if cand, ok := byName[nameKey]; ok {
				q.Key = cand.Criterion.Key
			}
		}
		if q.Key == "" {
			continue
		}
		if seen[q.Key] {
			continue
		}
		seen[q.Key] = true

		cand, ok := byKey[q.Key]
		if ok {
			if strings.TrimSpace(q.Category) == "" {
				q.Category = cand.Criterion.Category
			}
			if strings.TrimSpace(q.Criterion) == "" {
				q.Criterion = cand.Criterion.Name
			}
		}

		q.Question = strings.TrimSpace(q.Question)
		if q.Question == "" {
			q.Question = fmt.Sprintf("%s için mevcut durumunuzu en iyi hangi seviye (L1–L5) anlatıyor? Kısa bir kanıt ekleyin.", strings.TrimSpace(q.Criterion))
		}
		q.Choices = choices

		var hints []string
		for _, h := range q.Hints {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			hints = append(hints, h)
		}

		// Add precheck context first (helps the user understand why we ask).
		if ok && cand.Inferred != nil {
			if s := formatInferredHint(cand.Inferred); s != "" && !containsAnyHint(hints, "ön tespit") {
				hints = append([]string{s}, hints...)
			}
		}

		// Ensure there is at least one “where/how to verify” hint.
		cmds := suggestKubectlCommandsForCriterion(q.Criterion)
		if len(cmds) > 0 && !containsAnyHint(hints, "kubectl") {
			hints = append(hints, "Örnek komut: "+cmds[0])
		}

		// Ensure there is a short level summary hint.
		if ok && len(cand.Criterion.Levels) == 5 && !containsAnyHint(hints, "L1=") {
			// Keep level summary short & readable.
			var parts []string
			add := func(idx int) {
				if idx < 1 || idx > 5 {
					return
				}
				v := strings.TrimSpace(cand.Criterion.Levels[idx-1])
				if v == "" {
					return
				}
				parts = append(parts, fmt.Sprintf("L%d=%s", idx, truncateForQuestion(v, 45)))
			}
			add(1)
			add(3)
			add(5)
			if len(parts) > 0 {
				hints = append(hints, "Seviye özeti (kısa): "+strings.Join(parts, " | "))
			}
		}

		// Ensure the user knows exactly what is being asked.
		if !containsAnyHint(hints, "istenen:") {
			hints = append(hints, "İstenen: L1–L5 seçimi + 1-2 cümle gerekçe; en az 1 kanıt (YAML/komut çıktısı/link).")
		}

		if len(hints) < 2 {
			hints = append(hints, "Kanıt: YAML/komut çıktısı/link ekleyin (en az 1).")
		}
		if len(hints) > 6 {
			hints = hints[:6]
		}
		q.Hints = hints

		if q.Priority <= 0 {
			q.Priority = i + 1
		}
		out = append(out, q)
	}

	// Ensure deterministic order by priority.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority == out[j].Priority {
			return out[i].Key < out[j].Key
		}
		return out[i].Priority < out[j].Priority
	})
	return out
}

func containsAnyHint(hints []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return false
	}
	for _, h := range hints {
		if strings.Contains(strings.ToLower(h), needle) {
			return true
		}
	}
	return false
}

func fallbackQuestions(candidates []questionCandidate, choices []string) []MaturityQuestion {
	var out []MaturityQuestion
	for i, c := range candidates {
		cmds := suggestKubectlCommandsForCriterion(c.Criterion.Name)
		var hints []string
		if c.Inferred != nil && c.Inferred.Level > 0 {
			conf := ""
			if c.Inferred.Confidence > 0 {
				conf = fmt.Sprintf(" (~%.0f%%)", c.Inferred.Confidence*100)
			}
			r := strings.TrimSpace(c.Inferred.Rationale)
			if r != "" {
				r = truncateForQuestion(r, 120)
				hints = append(hints, fmt.Sprintf("Ön tespit: L%d%s — %s", c.Inferred.Level, conf, r))
			} else {
				hints = append(hints, fmt.Sprintf("Ön tespit: L%d%s", c.Inferred.Level, conf))
			}
		}
		hints = append(hints, "İstenen: L1–L5 seçimi + 1-2 cümle gerekçe; en az 1 kanıt (YAML/komut çıktısı/link).")
		if len(cmds) > 0 {
			hints = append(hints, "Örnek komut: "+cmds[0])
		}
		if len(c.Criterion.Levels) == 5 {
			var parts []string
			add := func(idx int) {
				if idx < 1 || idx > 5 {
					return
				}
				v := strings.TrimSpace(c.Criterion.Levels[idx-1])
				if v == "" {
					return
				}
				parts = append(parts, fmt.Sprintf("L%d=%s", idx, truncateForQuestion(v, 45)))
			}
			add(1)
			add(3)
			add(5)
			if len(parts) > 0 {
				hints = append(hints, "Seviye özeti (kısa): "+strings.Join(parts, " | "))
			}
		}
		q := MaturityQuestion{
			Key:       c.Criterion.Key,
			Category:  c.Criterion.Category,
			Criterion: c.Criterion.Name,
			Question:  fmt.Sprintf("%s için hangi seviye (L1–L5) geçerli? Seçiminizi 1-2 cümle gerekçe ve en az 1 kanıtla destekleyin.", c.Criterion.Name),
			Choices:   choices,
			Hints:     hints,
			Priority:  i + 1,
		}
		out = append(out, q)
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
