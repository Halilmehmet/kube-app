package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phpdave11/gofpdf"
)

type pdfColor struct {
	R int
	G int
	B int
}

func (c pdfColor) setFill(pdf *gofpdf.Fpdf) { pdf.SetFillColor(c.R, c.G, c.B) }
func (c pdfColor) setDraw(pdf *gofpdf.Fpdf) { pdf.SetDrawColor(c.R, c.G, c.B) }
func (c pdfColor) setText(pdf *gofpdf.Fpdf) { pdf.SetTextColor(c.R, c.G, c.B) }

var (
	pdfBg          = pdfColor{R: 248, G: 250, B: 252} // slate-50
	pdfCardBg      = pdfColor{R: 255, G: 255, B: 255}
	pdfBorder      = pdfColor{R: 226, G: 232, B: 240} // slate-200
	pdfShadow      = pdfColor{R: 203, G: 213, B: 225} // slate-300
	pdfTextMain    = pdfColor{R: 15, G: 23, B: 42}    // slate-900
	pdfTextMute    = pdfColor{R: 71, G: 85, B: 105}   // slate-600
	pdfHeaderStart = pdfColor{R: 37, G: 99, B: 235}   // blue-600
	pdfHeaderEnd   = pdfColor{R: 99, G: 102, B: 241}  // indigo-500
	pdfHeaderText  = pdfColor{R: 255, G: 255, B: 255}
	pdfBarTrack    = pdfColor{R: 226, G: 232, B: 240}
	pdfBarStart    = pdfColor{R: 59, G: 130, B: 246} // blue-500
	pdfBarEnd      = pdfColor{R: 34, G: 197, B: 94}  // green-500
	pdfBarHot      = pdfColor{R: 236, G: 72, B: 153} // pink-500
)

func configurePDFFont(pdf *gofpdf.Fpdf) string {
	type cand struct {
		family      string
		regularPath string
		boldPath    string
	}
	candidates := []cand{
		{family: "ArialUTF8", regularPath: "/System/Library/Fonts/Supplemental/Arial.ttf", boldPath: "/System/Library/Fonts/Supplemental/Arial Bold.ttf"},
		{family: "ArialUnicodeUTF8", regularPath: "/System/Library/Fonts/Supplemental/Arial Unicode.ttf", boldPath: "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"},
		{family: "DejaVuSansUTF8", regularPath: "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", boldPath: "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"},
		{family: "LiberationSansUTF8", regularPath: "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf", boldPath: "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"},
	}

	for _, c := range candidates {
		regularBytes, err := os.ReadFile(c.regularPath)
		if err != nil || len(regularBytes) == 0 {
			continue
		}
		boldBytes := regularBytes
		if strings.TrimSpace(c.boldPath) != "" {
			if b, err := os.ReadFile(c.boldPath); err == nil && len(b) > 0 {
				boldBytes = b
			}
		}

		pdf.SetError(nil)
		pdf.AddUTF8FontFromBytes(c.family, "", regularBytes)
		pdf.AddUTF8FontFromBytes(c.family, "B", boldBytes)
		if pdf.Error() == nil {
			return c.family
		}
	}

	pdf.SetError(nil)
	return "Helvetica"
}

func parseLeadingOrder(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	parts := strings.SplitN(s, ".", 2)
	if len(parts) < 2 {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func levelColor(level int) pdfColor {
	switch level {
	case 1:
		return pdfColor{R: 248, G: 113, B: 113} // red-400
	case 2:
		return pdfColor{R: 251, G: 146, B: 60} // orange-400
	case 3:
		return pdfColor{R: 250, G: 204, B: 21} // yellow-400
	case 4:
		return pdfColor{R: 34, G: 197, B: 94} // green-500
	case 5:
		return pdfColor{R: 59, G: 130, B: 246} // blue-500
	default:
		return pdfTextMute
	}
}

func drawCard(pdf *gofpdf.Fpdf, x, y, w, h float64) {
	// Simple shadow (no alpha support).
	pdfShadow.setFill(pdf)
	pdf.RoundedRect(x+0.9, y+0.9, w, h, 4, "1234", "F")
	pdfCardBg.setFill(pdf)
	pdfBorder.setDraw(pdf)
	pdf.SetLineWidth(0.25)
	pdf.RoundedRect(x, y, w, h, 4, "1234", "FD")
}

func drawBadge(pdf *gofpdf.Fpdf, family string, x, y, w, h float64, text string, border pdfColor) {
	pdf.SetLineWidth(0.35)
	border.setDraw(pdf)
	pdfCardBg.setFill(pdf)
	pdf.RoundedRect(x, y, w, h, h/2, "1234", "FD")
	pdfTextMain.setText(pdf)
	pdf.SetFont(family, "B", 9.5)
	pdf.SetXY(x, y+(h-6.5)/2)
	pdf.CellFormat(w, 6.5, text, "", 0, "CM", false, 0, "")
}

func drawProgressBar(pdf *gofpdf.Fpdf, x, y, w, h float64, frac float64, c1, c2 pdfColor) {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	pdfBarTrack.setFill(pdf)
	pdfBarTrack.setDraw(pdf)
	pdf.SetLineWidth(0.15)
	pdf.RoundedRect(x, y, w, h, h/2, "1234", "FD")
	if frac <= 0 {
		return
	}
	fillW := w * frac
	pdf.ClipRoundedRect(x, y, fillW, h, h/2, false)
	pdf.LinearGradient(x, y, fillW, h, c1.R, c1.G, c1.B, c2.R, c2.G, c2.B, x, y, x+fillW, y)
	pdf.ClipEnd()
}

func drawChip(pdf *gofpdf.Fpdf, family string, x, y float64, label string) (w float64) {
	pdf.SetFont(family, "B", 8.8)
	padX := 2.6
	padY := 1.6
	txtW := pdf.GetStringWidth(label)
	w = txtW + padX*2
	h := 7.4
	pdfColor{R: 241, G: 245, B: 249}.setFill(pdf) // slate-100
	pdfBorder.setDraw(pdf)
	pdf.SetLineWidth(0.25)
	pdf.RoundedRect(x, y, w, h, 3.6, "1234", "FD")
	pdfTextMute.setText(pdf)
	pdf.SetXY(x+padX, y+padY)
	pdf.CellFormat(txtW, 4.6, label, "", 0, "L", false, 0, "")
	return w
}

func addonsFromEvidence(ev MaturityEvidence, max int) []string {
	if len(ev.DetectedAddons) == 0 {
		return nil
	}
	var out []string
	for k, ok := range ev.DetectedAddons {
		if ok && strings.TrimSpace(k) != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func ensurePageSpace(pdf *gofpdf.Fpdf, minBottom float64) {
	_, pageH := pdf.GetPageSize()
	if pdf.GetY() > pageH-minBottom {
		pdf.AddPage()
	}
}

func GenerateMaturityPDF(doc MaturityCriteriaDoc, report MaturityReport, req MaturityAnalyzeRequest, ev MaturityEvidence) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(14, 14, 14)
	pdf.SetAutoPageBreak(false, 14)

	family := configurePDFFont(pdf)

	const headerH = 20.0
	const margin = 14.0
	const bottomMargin = 14.0

	pdf.SetHeaderFunc(func() {
		w, h := pdf.GetPageSize()
		pdfBg.setFill(pdf)
		pdf.Rect(0, 0, w, h, "F")

		pdf.LinearGradient(0, 0, w, headerH, pdfHeaderStart.R, pdfHeaderStart.G, pdfHeaderStart.B, pdfHeaderEnd.R, pdfHeaderEnd.G, pdfHeaderEnd.B, 0, 0, w, 0)
		pdfHeaderText.setText(pdf)

		pdf.SetFont(family, "B", 14)
		pdf.SetXY(margin, 6.3)
		pdf.CellFormat(w-2*margin-32, 7, "Kubernetes Cluster Olgunluk Raporu", "", 0, "L", false, 0, "")

		overall := fmt.Sprintf("L%.1f", report.OverallLevel)
		drawBadge(pdf, family, w-margin-28, 5.6, 28, 9.0, overall, pdfHeaderText)

		pdf.SetFont(family, "", 9.5)
		pdf.SetXY(margin, 14.2)
		pdf.CellFormat(w-2*margin, 5, fmt.Sprintf("Cluster: %s • %s", strings.TrimSpace(report.Cluster), report.GeneratedAt.Format("2006-01-02 15:04")), "", 0, "L", false, 0, "")

		pdf.SetY(headerH + 6)
	})

	pdf.SetFooterFunc(func() {
		w, h := pdf.GetPageSize()
		pdfTextMute.setText(pdf)
		pdf.SetFont(family, "", 9)
		pdf.SetXY(margin, h-10)
		rubric := strings.TrimSpace(filepath.Base(doc.SourcePath))
		if rubric == "" {
			rubric = "rubric"
		}
		pdf.CellFormat(w-2*margin, 6, rubric, "", 0, "L", false, 0, "")
		pdf.CellFormat(w-2*margin, 6, fmt.Sprintf("Sayfa %d", pdf.PageNo()), "", 0, "R", false, 0, "")
	})

	pdf.AddPage()

	pageW, pageH := pdf.GetPageSize()
	contentW := pageW - 2*margin
	contentBottom := pageH - bottomMargin

	// ===== Overview cards =====
	y := pdf.GetY()
	gap := 8.0
	cardW := (contentW - gap) / 2
	cardH := 54.0

	drawCard(pdf, margin, y, cardW, cardH)
	drawCard(pdf, margin+cardW+gap, y, cardW, cardH)

	// Left card: meta + legend
	pdfTextMain.setText(pdf)
	pdf.SetFont(family, "B", 12)
	pdf.SetXY(margin+10, y+9)
	pdf.CellFormat(0, 6, "Genel", "", 0, "L", false, 0, "")

	drawBadge(pdf, family, margin+cardW-10-26, y+8.2, 26, 9.0, fmt.Sprintf("L%.1f", report.OverallLevel), pdfBorder)

	pdfTextMute.setText(pdf)
	pdf.SetFont(family, "", 10)
	metaY := y + 18
	meta := []string{
		"Generated: " + report.GeneratedAt.Format(time.RFC3339),
	}
	if strings.TrimSpace(req.TargetLevel) != "" {
		meta = append(meta, "Hedef Seviye: "+strings.TrimSpace(req.TargetLevel))
	}
	if report.LLM != nil && report.LLM.Provider != "" {
		model := report.LLM.Provider
		if report.LLM.Model != "" {
			model += " / " + report.LLM.Model
		}
		meta = append(meta, "LLM: "+model)
	}
	for _, line := range meta {
		pdf.SetXY(margin+10, metaY)
		pdf.CellFormat(cardW-20, 5.2, line, "", 0, "L", false, 0, "")
		metaY += 5.4
	}

	pdf.SetFont(family, "B", 9.5)
	pdf.SetXY(margin+10, y+cardH-12)
	pdf.CellFormat(0, 5, "Renkler:", "", 0, "L", false, 0, "")
	lx := margin + 30
	for i := 1; i <= 5; i++ {
		c := levelColor(i)
		c.setFill(pdf)
		pdf.RoundedRect(lx, y+cardH-11.2, 6.2, 3.4, 1.7, "1234", "F")
		pdfTextMute.setText(pdf)
		pdf.SetFont(family, "", 9.2)
		pdf.SetXY(lx+7.0, y+cardH-13.1)
		pdf.CellFormat(0, 7, fmt.Sprintf("L%d", i), "", 0, "L", false, 0, "")
		lx += 14.8
	}

	// Right card: evidence highlights + addons
	pdfTextMain.setText(pdf)
	pdf.SetFont(family, "B", 12)
	pdf.SetXY(margin+cardW+gap+10, y+9)
	pdf.CellFormat(0, 6, "Kanıt Özeti", "", 0, "L", false, 0, "")

	pdfTextMute.setText(pdf)
	pdf.SetFont(family, "", 10)
	kv := strings.TrimSpace(ev.KubernetesVersion)
	if kv == "" {
		kv = "—"
	}
	evY := y + 18
	leftCol := []string{
		"K8S: " + kv,
		fmt.Sprintf("Nodes: %d", ev.NodeCount),
		fmt.Sprintf("Namespaces: %d", ev.NamespaceCount),
	}
	rightCol := []string{
		fmt.Sprintf("Zones: %d", ev.ZoneCount),
		fmt.Sprintf("Ingress: %d", ev.IngressCount),
		fmt.Sprintf("NetworkPolicy: %d", ev.NetworkPolicyCount),
	}
	colX1 := margin + cardW + gap + 10
	colX2 := margin + cardW + gap + 10 + (cardW-20)/2 + 6
	for i := 0; i < 3; i++ {
		pdf.SetXY(colX1, evY)
		pdf.CellFormat(0, 5.2, leftCol[i], "", 0, "L", false, 0, "")
		pdf.SetXY(colX2, evY)
		pdf.CellFormat(0, 5.2, rightCol[i], "", 0, "L", false, 0, "")
		evY += 6.0
	}

	addons := addonsFromEvidence(ev, 10)
	if len(addons) > 0 {
		chipY := y + cardH - 13.0
		chipX := margin + cardW + gap + 10
		for _, a := range addons {
			w := drawChip(pdf, family, chipX, chipY, a)
			chipX += w + 3.0
			if chipX+w > margin+2*cardW+gap-10 {
				break
			}
		}
	}

	pdf.SetY(y + cardH + 10)

	// ===== Category scores =====
	pdfTextMain.setText(pdf)
	pdf.SetFont(family, "B", 12)
	pdf.CellFormat(0, 7, "Kategori Skorları", "", 1, "L", false, 0, "")

	type catRow struct {
		Title string
		Level float64
		Order int
		HasO  bool
	}
	var rows []catRow
	for _, cs := range report.CategoryScores {
		n, ok := parseLeadingOrder(cs.Category)
		rows = append(rows, catRow{Title: cs.Category, Level: cs.Level, Order: n, HasO: ok})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].HasO && rows[j].HasO && rows[i].Order != rows[j].Order {
			return rows[i].Order < rows[j].Order
		}
		if rows[i].HasO != rows[j].HasO {
			return rows[i].HasO
		}
		return rows[i].Title < rows[j].Title
	})

	pdf.SetFont(family, "B", 10.5)
	for _, r := range rows {
		ensurePageSpace(pdf, 32)
		pdfTextMain.setText(pdf)
		pdf.CellFormat(74, 6.2, strings.TrimSpace(r.Title), "", 0, "L", false, 0, "")
		drawProgressBar(pdf, margin+78, pdf.GetY()+2.2, 76, 3.4, r.Level/5.0, pdfBarStart, pdfBarEnd)
		pdfTextMute.setText(pdf)
		pdf.CellFormat(0, 6.2, fmt.Sprintf("L%.1f", r.Level), "", 1, "R", false, 0, "")
	}
	pdf.Ln(2)

	// ===== Criteria details =====
	pdfTextMain.setText(pdf)
	pdf.SetFont(family, "B", 12)
	pdf.CellFormat(0, 7, "Kriter Detayları", "", 1, "L", false, 0, "")

	byCategory := map[string][]MaturityCriterionScore{}
	for _, cs := range report.CriteriaScores {
		byCategory[cs.Category] = append(byCategory[cs.Category], cs)
	}
	catTitles := make([]string, 0, len(byCategory))
	for c := range byCategory {
		catTitles = append(catTitles, c)
	}
	sort.SliceStable(catTitles, func(i, j int) bool {
		ni, oi := parseLeadingOrder(catTitles[i])
		nj, oj := parseLeadingOrder(catTitles[j])
		if oi && oj && ni != nj {
			return ni < nj
		}
		if oi != oj {
			return oi
		}
		return catTitles[i] < catTitles[j]
	})
	catLevel := map[string]float64{}
	for _, cs := range report.CategoryScores {
		catLevel[cs.Category] = cs.Level
	}

	for _, cat := range catTitles {
		ensurePageSpace(pdf, 40)
		pdf.Ln(2)

		pdfTextMain.setText(pdf)
		pdf.SetFont(family, "B", 11.5)
		pdf.CellFormat(0, 6.5, strings.TrimSpace(cat), "", 1, "L", false, 0, "")
		pdfTextMute.setText(pdf)
		pdf.SetFont(family, "", 10)
		pdf.CellFormat(0, 5.2, fmt.Sprintf("Ortalama: L%.1f • %d kriter", catLevel[cat], len(byCategory[cat])), "", 1, "L", false, 0, "")

		items := byCategory[cat]
		sort.SliceStable(items, func(i, j int) bool { return items[i].Criterion < items[j].Criterion })

		for _, it := range items {
			// Prepare a short, readable details line (keeps PDF compact).
			var parts []string
			if ans := strings.TrimSpace(answerForKey(req.Answers, it.Key)); ans != "" {
				parts = append(parts, "Manuel: "+truncateForPDF(ans, 160))
			}
			if r := strings.TrimSpace(it.Rationale); r != "" {
				parts = append(parts, truncateForPDF(r, 220))
			}
			if len(parts) == 0 && len(it.Evidence) > 0 {
				parts = append(parts, "Kanıt: "+strings.Join(trimList(it.Evidence, 3), " | "))
			}
			detail := strings.TrimSpace(strings.Join(parts, " • "))
			if detail == "" {
				detail = "—"
			}

			rowX := margin
			rowW := contentW
			y0 := pdf.GetY()

			// Height estimation (title + details).
			titleW := rowW - 56
			pdf.SetFont(family, "B", 10.5)
			titleLines := pdf.SplitLines([]byte(strings.TrimSpace(it.Criterion)), titleW)
			pdf.SetFont(family, "", 9.5)
			detailLines := pdf.SplitLines([]byte(detail), titleW)
			h := 6.0 + float64(len(titleLines))*5.0 + float64(len(detailLines))*4.3 + 5.0
			if h < 18 {
				h = 18
			}

			if y0+h > contentBottom {
				pdf.AddPage()
				y0 = pdf.GetY()
			}

			pdfCardBg.setFill(pdf)
			pdfBorder.setDraw(pdf)
			pdf.SetLineWidth(0.18)
			pdf.RoundedRect(rowX, y0, rowW, h, 3.0, "1234", "FD")

			lc := levelColor(it.Level)
			lc.setFill(pdf)
			pdf.RoundedRect(rowX+1.2, y0+1.2, 2.4, h-2.4, 1.2, "1234", "F")

			levelStr := "—"
			if it.Level > 0 {
				levelStr = fmt.Sprintf("L%d", it.Level)
			}
			drawBadge(pdf, family, rowX+rowW-28, y0+2.8, 18, 7.6, levelStr, lc)

			conf := it.Confidence
			if conf < 0 {
				conf = 0
			}
			if conf > 1 {
				conf = 1
			}
			drawProgressBar(pdf, rowX+rowW-44, y0+13.0, 20, 2.8, conf, pdfBarHot, pdfBarStart)
			pdfTextMute.setText(pdf)
			pdf.SetFont(family, "B", 9.2)
			pdf.SetXY(rowX+rowW-28, y0+11.0)
			pdf.CellFormat(18, 6, fmt.Sprintf("%.0f%%", conf*100), "", 0, "RM", false, 0, "")

			pdfTextMain.setText(pdf)
			pdf.SetFont(family, "B", 10.5)
			pdf.SetXY(rowX+6.0, y0+3.0)
			pdf.MultiCell(titleW, 5.0, strings.TrimSpace(it.Criterion), "", "L", false)

			pdfTextMute.setText(pdf)
			pdf.SetFont(family, "", 9.5)
			pdf.SetXY(rowX+6.0, y0+3.0+float64(len(titleLines))*5.0)
			pdf.MultiCell(titleW, 4.3, detail, "", "L", false)

			pdf.SetY(y0 + h + 4.2)
		}
	}

	// Notes / comments page
	if strings.TrimSpace(report.Notes) != "" {
		pdf.AddPage()
		pdfTextMain.setText(pdf)
		pdf.SetFont(family, "B", 12)
		pdf.CellFormat(0, 7, "Notlar / Yorumlar", "", 1, "L", false, 0, "")

		y0 := pdf.GetY() + 2
		h := contentBottom - y0
		if h < 20 {
			pdf.AddPage()
			y0 = pdf.GetY() + 2
			h = contentBottom - y0
		}
		drawCard(pdf, margin, y0, contentW, h)
		pdfTextMain.setText(pdf)
		pdf.SetFont(family, "", 11)
		pdf.SetXY(margin+10, y0+10)
		pdf.MultiCell(contentW-20, 5.8, strings.TrimSpace(report.Notes), "", "L", false)
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
