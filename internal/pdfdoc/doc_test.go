package pdfdoc

import (
	"bytes"
	"io"
	"os"
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
	headers := []string{"ID", "Sev", "Title", "Asset", "CVSS", "Status"}
	row := []string{
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
	measure.pdf.SetFont("Helvetica", "", 7)
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
	if len(measure.wrap(row[2], widths[2]-1.6)) < 2 {
		t.Fatal("expected the findings title to wrap onto more than one line")
	}
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
