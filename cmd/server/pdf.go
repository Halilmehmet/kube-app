package main

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/phpdave11/gofpdf"
)

func GenerateMaturityPDF(doc MaturityCriteriaDoc, report MaturityReport, answers map[string]string) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(12, 12, 12)
	pdf.SetAutoPageBreak(true, 14)
	pdf.AddPage()

	pdf.SetFont("Helvetica", "B", 16)
	pdf.CellFormat(0, 9, "Kubernetes Cluster Olgunluk Raporu", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 6, fmt.Sprintf("Cluster: %s", report.Cluster), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 6, fmt.Sprintf("Generated: %s", report.GeneratedAt.Format(time.RFC3339)), "", 1, "L", false, 0, "")
	if report.LLM != nil && report.LLM.Provider != "" {
		model := report.LLM.Provider
		if report.LLM.Model != "" {
			model += " / " + report.LLM.Model
		}
		pdf.CellFormat(0, 6, fmt.Sprintf("LLM: %s", model), "", 1, "L", false, 0, "")
	}
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "B", 12)
	pdf.CellFormat(0, 7, fmt.Sprintf("Genel Seviye: L%.1f", report.OverallLevel), "", 1, "L", false, 0, "")
	pdf.Ln(1)

	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 6, "Kategori Skorları", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	for _, cs := range report.CategoryScores {
		pdf.CellFormat(0, 5.5, fmt.Sprintf("- %s: L%.1f", cs.Category, cs.Level), "", 1, "L", false, 0, "")
	}
	pdf.Ln(2)

	byCategory := map[string][]MaturityCriterionScore{}
	for _, cs := range report.CriteriaScores {
		byCategory[cs.Category] = append(byCategory[cs.Category], cs)
	}
	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 6, "Kriter Detayları", "", 1, "L", false, 0, "")

	for _, cat := range cats {
		pdf.Ln(1)
		pdf.SetFont("Helvetica", "B", 11)
		pdf.MultiCell(0, 6, cat, "", "L", false)

		items := byCategory[cat]
		sort.SliceStable(items, func(i, j int) bool { return items[i].Criterion < items[j].Criterion })
		for _, it := range items {
			level := "—"
			if it.Level > 0 {
				level = fmt.Sprintf("L%d", it.Level)
			}
			conf := ""
			if it.Level > 0 {
				conf = fmt.Sprintf(" (%.0f%%)", it.Confidence*100)
			}

			pdf.SetFont("Helvetica", "B", 10)
			pdf.MultiCell(0, 5.2, fmt.Sprintf("%s  %s%s", it.Criterion, level, conf), "", "L", false)

			pdf.SetFont("Helvetica", "", 9.5)
			if strings.TrimSpace(answerForKey(answers, it.Key)) != "" {
				pdf.MultiCell(0, 4.8, "Manuel Not: "+truncateForPDF(answerForKey(answers, it.Key), 260), "", "L", false)
			}
			if strings.TrimSpace(it.Rationale) != "" {
				pdf.MultiCell(0, 4.8, "Gerekçe: "+strings.TrimSpace(it.Rationale), "", "L", false)
			}
			if len(it.Evidence) > 0 {
				pdf.MultiCell(0, 4.8, "Kanıt: "+strings.Join(trimList(it.Evidence, 4), " | "), "", "L", false)
			}
			if len(it.Missing) > 0 {
				pdf.MultiCell(0, 4.8, "Eksik/Şüpheli: "+strings.Join(trimList(it.Missing, 4), " | "), "", "L", false)
			}
			if len(it.NextSteps) > 0 {
				pdf.MultiCell(0, 4.8, "Öneri: "+strings.Join(trimList(it.NextSteps, 4), " | "), "", "L", false)
			}
			pdf.Ln(1)
		}
	}

	if strings.TrimSpace(report.Notes) != "" {
		pdf.AddPage()
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(0, 6, "Notlar", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.MultiCell(0, 5.2, strings.TrimSpace(report.Notes), "", "L", false)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func trimList(values []string, max int) []string {
	if len(values) <= max {
		return values
	}
	return values[:max]
}

func answerForKey(answers map[string]string, key string) string {
	if answers == nil {
		return ""
	}
	return strings.TrimSpace(answers[key])
}

func truncateForPDF(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= max {
		return s
	}
	return strings.TrimSpace(s[:max]) + "..."
}
