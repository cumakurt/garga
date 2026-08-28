package pdfdoc

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteCWDCreatesPrivateFile(t *testing.T) {
	t.Chdir(t.TempDir())
	path, err := WriteCWD(".garga-test-20260827T120000.000Z-", ".pdf", "test", func(output io.Writer) error {
		_, err := output.Write([]byte("%PDF-1.4 test-report"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) == "" || !strings.HasPrefix(filepath.Base(path), "garga-test-20260827T120000.000Z-") || !strings.HasSuffix(path, ".pdf") {
		t.Fatalf("path = %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %o", info.Mode().Perm())
	}
}

func TestSafeNormalizesLatinText(t *testing.T) {
	t.Parallel()
	got := safe("hello—world\nnext")
	if got != "hello-world next" {
		t.Fatalf("safe() = %q", got)
	}
}

func TestTableWrapsFindingRegisterWithoutOverflow(t *testing.T) {
	headers := []string{"#", "ID", "Severity", "Title", "Asset", "CVSS", "Status"}
	row := []string{
		"1",
		"F-001",
		"CRITICAL",
		"Elasticsearch likely allows unauthenticated cluster administration",
		"http://192.168.1.64:9200/",
		"-",
		"Open",
	}
	doc := New("test", "Confidential", "footer")
	doc.Table(headers, [][]string{row})
	var output bytes.Buffer
	if err := doc.Write(&output); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(output.Bytes(), []byte("%PDF")) {
		t.Fatal("table PDF was not written")
	}

	measure := New("test", "Confidential", "footer")
	measure.pdf.SetFont(reportFont, "", 7)
	widths := tableColumnWidths(headers)
	for index, cell := range row {
		limit := widths[index] - 1.6
		lines := measure.wrap(cell, limit)
		if len(lines) == 0 {
			t.Fatalf("column %d produced no lines", index)
		}
		for _, line := range lines {
			if measure.pdf.GetStringWidth(line) > limit+0.05 {
				t.Fatalf("column %d line %q is %g mm wide, limit %g", index, line, measure.pdf.GetStringWidth(line), limit)
			}
		}
	}
	if len(measure.wrap(row[3], widths[3]-1.6)) < 2 {
		t.Fatal("expected the findings title to wrap onto more than one line")
	}
	statusLines := measure.wrap("Open / EXPLOITABLE", widths[6]-1.6)
	if !containsLine(statusLines, "EXPLOITABLE") {
		t.Fatalf("status label was split across characters: %#v", statusLines)
	}
}

func TestPDFPreservesTurkishText(t *testing.T) {
	const turkishText = "ç Ç ğ Ğ ı İ ö Ö ş Ş ü Ü"
	doc := New("Türkçe güvenlik raporu", "Gizli", "İstanbul")
	doc.Para(turkishText)

	var output bytes.Buffer
	if err := doc.Write(&output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte{0xE7, ' ', 0xC7, ' ', 0xF0, ' ', 0xD0}) {
		t.Fatal("PDF content does not contain the expected CP1254 Turkish glyph sequence")
	}

	pdfToText, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is required for PDF Unicode extraction verification")
	}
	path := filepath.Join(t.TempDir(), "turkish.pdf")
	if err := os.WriteFile(path, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	extracted, err := exec.Command(pdfToText, path, "-").CombinedOutput()
	if err != nil {
		t.Fatalf("extract PDF text: %v: %s", err, extracted)
	}
	normalized := strings.NewReplacer(" ", "", "\n", "", "\r", "", "\f", "").Replace(string(extracted))
	if !strings.Contains(normalized, strings.ReplaceAll(turkishText, " ", "")) {
		t.Fatalf("extracted text = %q, want it to contain %q", extracted, turkishText)
	}
}

func containsLine(lines []string, expected string) bool {
	for _, line := range lines {
		if line == expected {
			return true
		}
	}
	return false
}

func TestFindingCardRendersNumberedFieldTable(t *testing.T) {
	doc := New("test", "Confidential", "footer")
	doc.FindingCard(1, "F-001", "CRITICAL", "Elasticsearch likely allows unauthenticated cluster administration", []string{"EXPLOITABLE"}, [][]string{
		{"Asset", "http://192.0.2.10:9200/"},
		{"Impact", "Anonymous clients can administer the cluster."},
	})
	var output bytes.Buffer
	if err := doc.Write(&output); err != nil {
		t.Fatal(err)
	}
	body := output.String()
	for _, needle := range []string{"1. F-001", "CRITICAL", "EXPLOITABLE", "Field", "Asset", "http://192.0.2.10:9200/"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("finding card missing %q", needle)
		}
	}
}

func TestFindingCardSplitsLongFieldAcrossPagesWithoutLosingContent(t *testing.T) {
	const finalMarker = "END-OF-LONG-FINDING-EVIDENCE"
	value := strings.Repeat("bounded evidence remains readable across page boundaries ", 450) + finalMarker
	doc := New("test", "Confidential", "footer")
	doc.FindingCard(1, "F-001", "HIGH", "Long evidence boundary", nil, [][]string{{"Evidence", value}})
	var output bytes.Buffer
	if err := doc.Write(&output); err != nil {
		t.Fatal(err)
	}
	body := output.String()
	if !strings.Contains(body, finalMarker) {
		t.Fatal("long field lost its final content")
	}
	if pages := strings.Count(body, "/Type /Page\n"); pages < 2 {
		t.Fatalf("PDF pages = %d, want at least 2", pages)
	}
}
