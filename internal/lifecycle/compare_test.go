package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/model"
)

func TestCompareClassifiesFindingLifecycleAndRiskChanges(t *testing.T) {
	t.Parallel()

	baseline := []model.Finding{
		lifecycleFinding("a", model.SeverityMedium, "potential", false, 5),
		lifecycleFinding("b", model.SeverityLow, "potential", false, 2),
		lifecycleFinding("c", model.SeverityHigh, "applicable", true, 9),
		lifecycleFinding("d", model.SeverityMedium, "potential", false, 5),
	}
	current := []model.Finding{
		lifecycleFinding("a", model.SeverityHigh, "applicable", true, 9),
		lifecycleFinding("c", model.SeverityMedium, "potential", false, 4),
		lifecycleFinding("d", model.SeverityMedium, "potential", false, 5),
		lifecycleFinding("e", model.SeverityCritical, "applicable", true, 10),
	}

	result, err := Compare(context.Background(), lifecycleJSONL(t, baseline), lifecycleJSONL(t, current))
	if err != nil {
		t.Fatalf("Compare() error = %v", err)
	}
	wantSummary := Summary{New: 1, Resolved: 1, Unchanged: 1, Regressed: 1, Improved: 1, Total: 5}
	if result.Summary != wantSummary {
		t.Fatalf("summary = %#v, want %#v", result.Summary, wantSummary)
	}
	wantStatuses := map[string]Status{
		"a": StatusRegressed,
		"b": StatusResolved,
		"c": StatusImproved,
		"d": StatusUnchanged,
		"e": StatusNew,
	}
	for _, change := range result.Changes {
		if change.Status != wantStatuses[change.ID] {
			t.Errorf("change %s status = %q, want %q", change.ID, change.Status, wantStatuses[change.ID])
		}
		if (change.Status == StatusRegressed || change.Status == StatusImproved) && len(change.Reasons) == 0 {
			t.Errorf("change %s has no risk reasons", change.ID)
		}
	}
	if result.Changes[0].ID != "a" || result.Changes[len(result.Changes)-1].ID != "e" {
		t.Fatalf("changes are not deterministically ordered: %#v", result.Changes)
	}
}

func TestCompareBuildsMissingStableID(t *testing.T) {
	t.Parallel()

	finding := lifecycleFinding("", model.SeverityMedium, "potential", false, 5)
	finding.CheckID = "garga.example"
	finding.Resource = "index-a"
	result, err := Compare(context.Background(), strings.NewReader(""), lifecycleJSONL(t, []model.Finding{finding}))
	if err != nil {
		t.Fatalf("Compare() error = %v", err)
	}
	want := model.FindingID(finding.CheckID, finding.Target, finding.Resource)
	if len(result.Changes) != 1 || result.Changes[0].ID != want || result.Changes[0].Current.ID != want {
		t.Fatalf("generated ID = %#v, want %q", result.Changes, want)
	}
}

func TestCompareRejectsDuplicateIDAndDoesNotEchoInvalidPayload(t *testing.T) {
	t.Parallel()

	finding := lifecycleFinding("duplicate", model.SeverityLow, "potential", false, 1)
	_, err := Compare(context.Background(), lifecycleJSONL(t, []model.Finding{finding, finding}), strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "duplicate finding id") {
		t.Fatalf("duplicate Compare() error = %v", err)
	}

	const canary = "secret-payload-canary"
	_, err = Compare(context.Background(), strings.NewReader(`{"check_id":`+canary+`}`+"\n"), strings.NewReader(""))
	if err == nil {
		t.Fatal("invalid Compare() error = nil")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("Compare() echoed invalid payload: %v", err)
	}
}

func TestWriteLifecycleFormats(t *testing.T) {
	t.Parallel()

	report := Report{
		SchemaVersion: SchemaVersion,
		Summary:       Summary{New: 1, Total: 1},
		Changes: []Change{{
			SchemaVersion: SchemaVersion,
			ID:            "a",
			Status:        StatusNew,
			Current:       findingPointer(lifecycleFinding("a", model.SeverityHigh, "applicable", true, 9)),
		}},
	}
	for _, format := range []Format{FormatConsole, FormatJSON, FormatJSONL} {
		var first bytes.Buffer
		var second bytes.Buffer
		if err := Write(&first, format, report); err != nil {
			t.Fatalf("Write(%s) error = %v", format, err)
		}
		if err := Write(&second, format, report); err != nil {
			t.Fatalf("Write(%s) second error = %v", format, err)
		}
		if !bytes.Equal(first.Bytes(), second.Bytes()) {
			t.Errorf("Write(%s) is not deterministic", format)
		}
		if !strings.Contains(first.String(), "a") {
			t.Errorf("Write(%s) missing finding ID: %s", format, first.String())
		}
	}
}

func lifecycleFinding(id string, severity model.Severity, applicability string, kev bool, priority float64) model.Finding {
	return model.Finding{
		SchemaVersion:  model.FindingSchemaVersion,
		ID:             id,
		CheckID:        "garga.lifecycle.test",
		Title:          "Lifecycle test finding",
		Target:         model.Endpoint{Scheme: model.SchemeHTTPS, Host: "es.example.com", Port: 9200},
		Product:        "Elasticsearch",
		Severity:       severity,
		Confidence:     model.ConfidenceHigh,
		Applicability:  applicability,
		KnownExploited: kev,
		PriorityScore:  &priority,
	}
}

func lifecycleJSONL(t *testing.T, findings []model.Finding) *bytes.Reader {
	t.Helper()
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	for _, finding := range findings {
		if err := encoder.Encode(finding); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}
	return bytes.NewReader(output.Bytes())
}
