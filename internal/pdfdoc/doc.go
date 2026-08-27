package pdfdoc

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/go-pdf/fpdf"
)

const (
	pageWidth    = 210.0
	margin       = 14.0
	contentWidth = pageWidth - 2*margin
)

// Doc is a simple A4 report writer used by scan and health PDF artifacts.
type Doc struct {
	pdf            *fpdf.Fpdf
	classification string
	footer         string
}

func New(title, classification, footer string) *Doc {
	pdf := fpdf.New("P", "mm", "A4", "")
	// Keep page streams uncompressed so operators can search report text in the file.
	pdf.SetCompression(false)
	pdf.SetTitle(safe(title), false)
	pdf.SetAuthor("garga", false)
	pdf.SetMargins(margin, 18, margin)
	pdf.SetAutoPageBreak(true, 18)
	doc := &Doc{pdf: pdf, classification: safe(classification), footer: safe(footer)}
	pdf.SetHeaderFunc(func() {
		if doc.classification == "" {
			return
		}
		pdf.SetFillColor(17, 24, 39)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.CellFormat(contentWidth, 7, doc.classification, "0", 1, "C", true, 0, "")
		pdf.Ln(4)
		pdf.SetTextColor(23, 32, 51)
	})
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(95, 107, 122)
		label := doc.footer
		if label != "" {
			label += "  |  "
		}
		pdf.CellFormat(contentWidth, 5, fmt.Sprintf("%spage %d", label, pdf.PageNo()), "0", 0, "C", false, 0, "")
		pdf.SetTextColor(23, 32, 51)
	})
	pdf.AddPage()
	return doc
}

func (doc *Doc) Logo(png []byte) {
	if len(png) == 0 || doc.pdf.Err() {
		return
	}
	options := fpdf.ImageOptions{ImageType: "PNG", ReadDpi: true}
	doc.pdf.RegisterImageOptionsReader("garga-logo", options, bytes.NewReader(png))
	doc.pdf.ImageOptions("garga-logo", margin, doc.pdf.GetY(), 42, 0, false, options, 0, "")
	doc.pdf.Ln(24)
}

func (doc *Doc) Title(text string) {
	doc.pdf.SetFont("Helvetica", "B", 18)
	doc.pdf.SetTextColor(7, 89, 133)
	doc.pdf.MultiCell(contentWidth, 8, safe(text), "", "", false)
	doc.pdf.SetTextColor(23, 32, 51)
	doc.pdf.Ln(2)
}

func (doc *Doc) Subtitle(text string) {
	doc.pdf.SetFont("Helvetica", "", 10)
	doc.pdf.SetTextColor(95, 107, 122)
	doc.pdf.MultiCell(contentWidth, 5, safe(text), "", "", false)
	doc.pdf.SetTextColor(23, 32, 51)
	doc.pdf.Ln(3)
}

func (doc *Doc) Section(text string) {
	doc.ensure(16)
	doc.pdf.SetFont("Helvetica", "B", 13)
	doc.pdf.SetTextColor(7, 89, 133)
	doc.pdf.MultiCell(contentWidth, 7, safe(text), "", "", false)
	doc.pdf.SetDrawColor(217, 226, 236)
	x, y := doc.pdf.GetXY()
	doc.pdf.Line(x, y, x+contentWidth, y)
	doc.pdf.Ln(3)
	doc.pdf.SetTextColor(23, 32, 51)
}

func (doc *Doc) Heading(text string) {
	doc.ensure(12)
	doc.pdf.SetFont("Helvetica", "B", 11)
	doc.pdf.MultiCell(contentWidth, 6, safe(text), "", "", false)
	doc.pdf.Ln(1)
}

func (doc *Doc) Para(text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	doc.pdf.SetFont("Helvetica", "", 9)
	doc.pdf.MultiCell(contentWidth, 4.4, safe(text), "", "", false)
	doc.pdf.Ln(1.5)
}

func (doc *Doc) KV(key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	doc.pdf.SetFont("Helvetica", "B", 8)
	doc.pdf.CellFormat(42, 4.4, safe(key), "", 0, "L", false, 0, "")
	doc.pdf.SetFont("Helvetica", "", 8)
	doc.pdf.MultiCell(contentWidth-42, 4.4, safe(value), "", "", false)
}

func (doc *Doc) Bullets(items []string) {
	doc.pdf.SetFont("Helvetica", "", 9)
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		doc.pdf.CellFormat(6, 4.4, "-", "", 0, "L", false, 0, "")
		doc.pdf.MultiCell(contentWidth-6, 4.4, safe(item), "", "", false)
	}
	doc.pdf.Ln(1)
}

func (doc *Doc) Badge(severity, title string) {
	r, g, b := severityRGB(severity)
	const chip = 24.0
	const gap = 2.0
	const lineHeight = 5.0
	titleWidth := contentWidth - chip - gap
	doc.pdf.SetFont("Helvetica", "B", 10)
	lines := doc.wrap(safe(title), titleWidth)
	height := 6.0
	if needed := float64(len(lines)) * lineHeight; needed > height {
		height = needed
	}
	doc.ensure(height + 2)
	left, _, _, _ := doc.pdf.GetMargins()
	_, y := doc.pdf.GetXY()
	doc.pdf.SetXY(left, y)
	doc.pdf.SetFillColor(r, g, b)
	doc.pdf.SetTextColor(255, 255, 255)
	doc.pdf.SetFont("Helvetica", "B", 8)
	doc.pdf.CellFormat(chip, 6, strings.ToUpper(safe(severity)), "0", 0, "C", true, 0, "")
	doc.pdf.SetTextColor(23, 32, 51)
	doc.pdf.SetFont("Helvetica", "B", 10)
	cy := y
	for _, line := range lines {
		doc.pdf.SetXY(left+chip+gap, cy)
		doc.pdf.CellFormat(titleWidth, lineHeight, line, "", 0, "L", false, 0, "")
		cy += lineHeight
	}
	doc.pdf.SetXY(left, y+height+1)
}

func (doc *Doc) Table(headers []string, rows [][]string) {
	doc.table(headers, rows, -1)
}

// SeverityTable is Table with the Sev/Severity/Highest column painted in that rating's color.
func (doc *Doc) SeverityTable(headers []string, rows [][]string) {
	column := -1
	for index, header := range headers {
		switch strings.ToLower(strings.TrimSpace(header)) {
		case "sev", "severity", "highest":
			column = index
		}
	}
	doc.table(headers, rows, column)
}

func (doc *Doc) table(headers []string, rows [][]string, severityColumn int) {
	if len(headers) == 0 {
		return
	}
	widths := tableColumnWidths(headers)
	doc.pdf.SetAutoPageBreak(false, 18)
	defer doc.pdf.SetAutoPageBreak(true, 18)
	doc.writeTableHeader(headers, widths)
	for index, row := range rows {
		cells := make([]string, len(headers))
		copy(cells, row)
		height := doc.tableRowHeight(cells, widths, false)
		if doc.pdf.GetY()+height > pageBottom() {
			doc.pdf.AddPage()
			doc.writeTableHeader(headers, widths)
		}
		severity := ""
		if severityColumn >= 0 && severityColumn < len(cells) {
			severity = cells[severityColumn]
		}
		doc.paintTableRow(cells, widths, height, false, severityColumn, severity, index)
	}
	doc.pdf.Ln(2)
}

const (
	tableLineHeight = 3.8
	tableCellPad    = 1.0
)

func tableColumnWidths(headers []string) []float64 {
	weights := make([]float64, len(headers))
	var total float64
	for index, header := range headers {
		switch strings.ToLower(strings.TrimSpace(header)) {
		case "title", "definition", "response", "meaning", "reason", "value":
			weights[index] = 3.2
		case "asset", "assets", "target", "resource":
			weights[index] = 2.4
		case "domain", "category", "collector", "usage":
			weights[index] = 2.0
		case "id", "sev", "severity", "cvss", "status", "count", "expl.", "http", "cost", "highest":
			weights[index] = 0.9
		case "#", "no.", "field":
			weights[index] = 0.7
		default:
			weights[index] = 1.2
		}
		total += weights[index]
	}
	widths := make([]float64, len(headers))
	for index, weight := range weights {
		widths[index] = contentWidth * weight / total
	}
	return widths
}

func (doc *Doc) writeTableHeader(headers []string, widths []float64) {
	height := doc.tableRowHeight(headers, widths, true)
	if doc.pdf.GetY()+height > pageBottom() {
		doc.pdf.AddPage()
	}
	doc.paintTableRow(headers, widths, height, true, -1, "", 0)
}

func (doc *Doc) tableRowHeight(cells []string, widths []float64, header bool) float64 {
	if header {
		doc.pdf.SetFont("Helvetica", "B", 7)
	} else {
		doc.pdf.SetFont("Helvetica", "", 7)
	}
	height := tableLineHeight + 2*tableCellPad
	for index, width := range widths {
		value := ""
		if index < len(cells) {
			value = cells[index]
		}
		lines := doc.wrap(value, width-1.6)
		if needed := float64(len(lines))*tableLineHeight + 2*tableCellPad; needed > height {
			height = needed
		}
	}
	return height
}

func (doc *Doc) paintTableRow(cells []string, widths []float64, height float64, header bool, severityColumn int, severity string, rowIndex int) {
	left, _, _, _ := doc.pdf.GetMargins()
	_, y := doc.pdf.GetXY()
	x := left
	washR, washG, washB := severityWash(severity)
	for index, width := range widths {
		value := ""
		if index < len(cells) {
			value = cells[index]
		}
		fill := false
		doc.pdf.SetTextColor(23, 32, 51)
		switch {
		case header:
			doc.pdf.SetFillColor(17, 24, 39)
			doc.pdf.SetTextColor(255, 255, 255)
			doc.pdf.SetFont("Helvetica", "B", 7)
			fill = true
		case severityColumn >= 0 && index == severityColumn && severity != "":
			r, g, b := severityRGB(severity)
			doc.pdf.SetFillColor(r, g, b)
			doc.pdf.SetTextColor(255, 255, 255)
			doc.pdf.SetFont("Helvetica", "B", 7)
			fill = true
		case severity != "":
			doc.pdf.SetFillColor(washR, washG, washB)
			doc.pdf.SetFont("Helvetica", "", 7)
			fill = true
		case rowIndex%2 == 1:
			doc.pdf.SetFillColor(247, 250, 252)
			doc.pdf.SetFont("Helvetica", "", 7)
			fill = true
		default:
			doc.pdf.SetFont("Helvetica", "", 7)
		}
		style := "D"
		if fill {
			style = "DF"
		}
		doc.pdf.Rect(x, y, width, height, style)
		cy := y + tableCellPad
		for _, line := range doc.wrap(value, width-1.6) {
			doc.pdf.SetXY(x+0.8, cy)
			doc.pdf.CellFormat(width-1.6, tableLineHeight, line, "", 0, "L", false, 0, "")
			cy += tableLineHeight
		}
		x += width
	}
	doc.pdf.SetXY(left, y+height)
	doc.pdf.SetTextColor(23, 32, 51)
}

func pageBottom() float64 {
	return 297.0 - 18.0
}

// GroupBanner draws a severity-tinted section strip used above grouped findings.
func (doc *Doc) GroupBanner(severity, text string) {
	text = safe(text)
	if text == "" {
		return
	}
	const height = 8.0
	doc.ensure(height + 3)
	left, _, _, _ := doc.pdf.GetMargins()
	_, y := doc.pdf.GetXY()
	r, g, b := severityRGB(severity)
	wr, wg, wb := severityWash(severity)
	doc.pdf.SetFillColor(wr, wg, wb)
	doc.pdf.Rect(left, y, contentWidth, height, "F")
	doc.pdf.SetFillColor(r, g, b)
	doc.pdf.Rect(left, y, 2.4, height, "F")
	doc.pdf.SetTextColor(r, g, b)
	doc.pdf.SetFont("Helvetica", "B", 10)
	doc.pdf.SetXY(left+6, y+1.6)
	doc.pdf.CellFormat(contentWidth-8, 5, text, "", 0, "L", false, 0, "")
	doc.pdf.SetXY(left, y+height+2)
	doc.pdf.SetTextColor(23, 32, 51)
}

// FindingCard draws one numbered pentest finding: colored header plus a Field/Value table.
func (doc *Doc) FindingCard(number int, id, severity, title string, flags []string, fields [][]string) {
	left, _, _, _ := doc.pdf.GetMargins()
	r, g, b := severityRGB(severity)
	kicker := fmt.Sprintf("%d. %s  %s", number, strings.ToUpper(safe(id)), strings.ToUpper(safe(severity)))
	for _, flag := range flags {
		flag = strings.TrimSpace(flag)
		if flag != "" {
			kicker += "    " + strings.ToUpper(safe(flag))
		}
	}
	doc.pdf.SetFont("Helvetica", "B", 10)
	kickerLines := doc.wrap(kicker, contentWidth-8)
	doc.pdf.SetFont("Helvetica", "B", 11)
	titleLines := doc.wrap(title, contentWidth-8)
	headerHeight := 3.0 + float64(len(kickerLines))*5.0 + float64(len(titleLines))*5.4 + 3.0
	if doc.pdf.GetY()+headerHeight+24 > pageBottom() {
		doc.pdf.AddPage()
	}
	_, y := doc.pdf.GetXY()
	doc.pdf.SetFillColor(r, g, b)
	doc.pdf.Rect(left, y, contentWidth, headerHeight, "F")
	doc.pdf.SetFillColor(maxInt(0, r-35), maxInt(0, g-35), maxInt(0, b-35))
	doc.pdf.Rect(left, y, 2.4, headerHeight, "F")
	doc.pdf.SetTextColor(255, 255, 255)
	cy := y + 3.0
	doc.pdf.SetFont("Helvetica", "B", 10)
	for _, line := range kickerLines {
		doc.pdf.SetXY(left+6, cy)
		doc.pdf.CellFormat(contentWidth-8, 5, line, "", 0, "L", false, 0, "")
		cy += 5
	}
	doc.pdf.SetFont("Helvetica", "B", 11)
	for _, line := range titleLines {
		doc.pdf.SetXY(left+6, cy)
		doc.pdf.CellFormat(contentWidth-8, 5.4, line, "", 0, "L", false, 0, "")
		cy += 5.4
	}
	doc.pdf.SetXY(left, y+headerHeight)
	doc.pdf.SetTextColor(23, 32, 51)
	if len(fields) > 0 {
		doc.FieldTable(fields)
	}
	doc.pdf.Ln(4)
}

// FieldTable is a two-column label/value table used inside finding cards.
func (doc *Doc) FieldTable(rows [][]string) {
	if len(rows) == 0 {
		return
	}
	widths := []float64{46, contentWidth - 46}
	headers := []string{"Field", "Value"}
	doc.pdf.SetAutoPageBreak(false, 18)
	defer doc.pdf.SetAutoPageBreak(true, 18)
	doc.writeTableHeader(headers, widths)
	for _, row := range rows {
		cells := []string{"", ""}
		copy(cells, row)
		height := doc.fieldRowHeight(cells, widths)
		if doc.pdf.GetY()+height > pageBottom() {
			doc.pdf.AddPage()
			doc.writeTableHeader(headers, widths)
		}
		doc.paintFieldRow(cells, widths, height)
	}
}

func (doc *Doc) fieldRowHeight(cells []string, widths []float64) float64 {
	height := tableLineHeight + 2*tableCellPad
	for index, width := range widths {
		value := ""
		if index < len(cells) {
			value = cells[index]
		}
		if index == 0 {
			doc.pdf.SetFont("Helvetica", "B", 7)
		} else {
			doc.pdf.SetFont("Helvetica", "", 8)
		}
		lines := doc.wrap(value, width-1.6)
		if needed := float64(len(lines))*tableLineHeight + 2*tableCellPad; needed > height {
			height = needed
		}
	}
	return height
}

func (doc *Doc) paintFieldRow(cells []string, widths []float64, height float64) {
	left, _, _, _ := doc.pdf.GetMargins()
	_, y := doc.pdf.GetXY()
	x := left
	for index, width := range widths {
		value := ""
		if index < len(cells) {
			value = cells[index]
		}
		if index == 0 {
			doc.pdf.SetFillColor(236, 242, 247)
			doc.pdf.Rect(x, y, width, height, "DF")
			doc.pdf.SetFont("Helvetica", "B", 7)
			doc.pdf.SetTextColor(55, 65, 81)
		} else {
			doc.pdf.SetFillColor(255, 255, 255)
			doc.pdf.Rect(x, y, width, height, "D")
			doc.pdf.SetFont("Helvetica", "", 8)
			doc.pdf.SetTextColor(23, 32, 51)
		}
		cy := y + tableCellPad
		for _, line := range doc.wrap(value, width-1.6) {
			doc.pdf.SetXY(x+0.8, cy)
			doc.pdf.CellFormat(width-1.6, tableLineHeight, line, "", 0, "L", false, 0, "")
			cy += tableLineHeight
		}
		x += width
	}
	doc.pdf.SetXY(left, y+height)
	doc.pdf.SetTextColor(23, 32, 51)
}

func (doc *Doc) Error() error {
	if doc.pdf.Err() {
		return fmt.Errorf("write PDF report: %s", doc.pdf.Error())
	}
	return nil
}

func (doc *Doc) Write(output io.Writer) error {
	if err := doc.Error(); err != nil {
		return err
	}
	return doc.pdf.Output(output)
}

func (doc *Doc) ensure(height float64) {
	_, _, _, bottom := doc.pdf.GetMargins()
	if doc.pdf.GetY()+height > 297-bottom {
		doc.pdf.AddPage()
	}
}

func severityRGB(severity string) (int, int, int) {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 180, 35, 24
	case "HIGH":
		return 194, 65, 12
	case "MEDIUM":
		return 161, 98, 7
	case "LOW":
		return 3, 105, 161
	case "OK", "HEALTHY", "PERFECT":
		return 21, 128, 61
	default:
		return 71, 85, 105
	}
}

func severityWash(severity string) (int, int, int) {
	r, g, b := severityRGB(severity)
	return (r + 255*7) / 8, (g + 255*7) / 8, (b + 255*7) / 8
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func safe(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, character := range value {
		switch character {
		case '\n', '\r', '\t':
			builder.WriteByte(' ')
		case '—', '–':
			builder.WriteByte('-')
		case '’', '‘', '‚':
			builder.WriteByte('\'')
		case '“', '”':
			builder.WriteByte('"')
		case '·':
			builder.WriteString(" - ")
		default:
			if character < 32 || character == 127 {
				continue
			}
			if character > 255 {
				if unicode.IsLetter(character) || unicode.IsNumber(character) {
					builder.WriteByte('?')
					continue
				}
				continue
			}
			builder.WriteRune(character)
		}
	}
	return strings.TrimSpace(strings.Join(strings.Fields(builder.String()), " "))
}

func (doc *Doc) wrap(text string, width float64) []string {
	text = safe(text)
	if width <= 1 {
		return []string{""}
	}
	if text == "" {
		return []string{""}
	}
	var lines []string
	var current string
	flush := func() {
		if current == "" {
			return
		}
		lines = append(lines, current)
		current = ""
	}
	for _, word := range strings.Fields(text) {
		for doc.pdf.GetStringWidth(word) > width {
			flush()
			fitted := doc.fit(word, width)
			if fitted == "" {
				break
			}
			lines = append(lines, fitted)
			word = strings.TrimPrefix(word, fitted)
		}
		if word == "" {
			continue
		}
		candidate := word
		if current != "" {
			candidate = current + " " + word
		}
		if doc.pdf.GetStringWidth(candidate) <= width {
			current = candidate
			continue
		}
		flush()
		current = word
	}
	flush()
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func (doc *Doc) fit(text string, width float64) string {
	if text == "" || doc.pdf.GetStringWidth(text) <= width {
		return text
	}
	runes := []rune(text)
	low, high := 1, len(runes)
	for low < high {
		mid := (low + high + 1) / 2
		if doc.pdf.GetStringWidth(string(runes[:mid])) <= width {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return string(runes[:low])
}

// WriteCWD writes a 0600 timestamped file in the working directory, then renames
// the hidden temporary name to prefix-without-dot plus ext.
func WriteCWD(hiddenPrefix, ext, verb string, write func(io.Writer) error) (path string, err error) {
	temporary, err := os.CreateTemp(".", hiddenPrefix+"*.tmp")
	if err != nil {
		return "", fmt.Errorf("create timestamped %s report: %w", verb, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		return "", fmt.Errorf("secure timestamped %s report: %w", verb, err)
	}
	if err = write(temporary); err != nil {
		return "", err
	}
	if err = temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync timestamped %s report: %w", verb, err)
	}
	if err = temporary.Close(); err != nil {
		return "", fmt.Errorf("close timestamped %s report: %w", verb, err)
	}
	base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(temporaryPath), "."), ".tmp") + ext
	finalPath := filepath.Join(filepath.Dir(temporaryPath), base)
	if err = os.Rename(temporaryPath, finalPath); err != nil {
		return "", fmt.Errorf("activate timestamped %s report: %w", verb, err)
	}
	absolute, absoluteErr := filepath.Abs(finalPath)
	if absoluteErr != nil {
		return finalPath, nil
	}
	return absolute, nil
}
