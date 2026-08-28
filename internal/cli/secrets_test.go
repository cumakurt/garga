package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/secrets"
)

func TestSecretsHelpListsRequiredFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"secrets", "--help"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("exit = %d stderr=%q", exitCode, stderr.String())
	}
	help := stdout.String()
	for _, flag := range []string{"--target", "--targets", "--user", "--password-env", "--api-key-env", "--bearer-token-env", "--ca-cert", "--client-cert", "--client-key", "--insecure", "--timeout", "--concurrency", "--rate-limit", "--sample-size", "--max-documents", "--indices", "--exclude-indices", "--output", "--format", "--min-confidence", "--verbose", "--deep-scan", "--deep-sample-size", "--deep-max-documents", "--deep-max-field-bytes", "--deep-max-depth"} {
		if !strings.Contains(help, flag) {
			t.Errorf("help missing %s", flag)
		}
	}
	if cmd, _, err := NewRootCommand(BuildInfo{}).Find([]string{"secrets"}); err != nil || cmd.Flags().Lookup("password") != nil {
		t.Fatal("secrets registered a --password flag")
	}
}

func TestSecretsCommandMasksConsoleAndWritesPDF(t *testing.T) {
	reportDirectory := t.TempDir()
	t.Chdir(reportDirectory)
	password := "fake-password-garga-test-ONLY"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodDelete || request.Method == http.MethodPut || request.Method == http.MethodPatch {
			t.Errorf("write method %s %s", request.Method, request.URL.Path)
		}
		switch request.URL.Path {
		case "/":
			_, _ = io.WriteString(writer, `{"cluster_name":"cli-test","version":{"number":"8.19.0"}}`)
		case "/_security/_authenticate":
			_, _ = io.WriteString(writer, `{"username":"garga-test"}`)
		case "/_cat/indices":
			_, _ = io.WriteString(writer, `[{"index":"app-logs","status":"open"}]`)
		case "/_alias", "/_data_stream":
			_, _ = io.WriteString(writer, `{}`)
		case "/app-logs/_mapping":
			_, _ = io.WriteString(writer, `{"app-logs":{"mappings":{"properties":{"password":{"type":"keyword"}}}}}`)
		case "/app-logs/_search":
			_, _ = io.WriteString(writer, `{"hits":{"hits":[{"_id":"1","_source":{"password":"fake-password-garga-test-ONLY"},"sort":["1"]}]}}`)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Setenv("GARGA_SECRETS_TEST_PASSWORD", password)
	var stdout, stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"secrets", "--target", server.URL, "--user", "garga-test", "--password-env", "GARGA_SECRETS_TEST_PASSWORD", "--allow-plaintext-auth", "--format", "json", "--rate-limit", "50"},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit = %d stderr=%q stdout=%q", exitCode, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), password) {
		t.Fatal("stdout leaked password")
	}
	if strings.Contains(stderr.String(), password) {
		t.Fatal("stderr leaked password")
	}
	var document struct {
		Findings []struct {
			MaskedPreview string `json:"masked_preview"`
			Secret        string `json:"secret"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("decode stdout: %v\n%s", err, stdout.String())
	}
	if len(document.Findings) == 0 {
		t.Fatalf("no findings: %s", stdout.String())
	}
	if document.Findings[0].Secret != "" {
		t.Fatal("JSON finding included secret field")
	}
	artifacts, err := filepath.Glob(filepath.Join(reportDirectory, "garga-secrets-*.pdf"))
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("pdf artifacts = %v err=%v", artifacts, err)
	}
	payload, err := os.ReadFile(artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(password)) {
		t.Fatal("PDF did not contain the full password")
	}
}

func TestSecretsDeepFlagsRequireDeepScan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"secrets", "--target", "http://127.0.0.1:9200", "--deep-sample-size", "200"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit = %d stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--deep-scan") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestSecretsJSONIncludesScanMode(t *testing.T) {
	reportDirectory := t.TempDir()
	t.Chdir(reportDirectory)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			_, _ = io.WriteString(writer, `{"cluster_name":"cli-test","version":{"number":"8.19.0"}}`)
		case "/_security/_authenticate":
			_, _ = io.WriteString(writer, `{"username":"garga-test"}`)
		case "/_cat/indices":
			_, _ = io.WriteString(writer, `[{"index":"app-logs","status":"open"}]`)
		case "/_alias", "/_data_stream":
			_, _ = io.WriteString(writer, `{}`)
		case "/app-logs/_mapping":
			_, _ = io.WriteString(writer, `{"app-logs":{"mappings":{"properties":{"username":{"type":"keyword"},"password":{"type":"keyword"}}}}}`)
		case "/app-logs/_search":
			_, _ = io.WriteString(writer, `{"hits":{"hits":[{"_id":"1","_source":{"username":"admin","password":"fake-password-garga-test-ONLY"},"sort":["1"]}]}}`)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	t.Setenv("GARGA_SECRETS_TEST_PASSWORD", "fake-password-garga-test-ONLY")
	var stdout, stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"secrets", "--target", server.URL, "--user", "garga-test", "--password-env", "GARGA_SECRETS_TEST_PASSWORD", "--allow-plaintext-auth", "--format", "json", "--rate-limit", "50", "--deep-scan", "--deep-sample-size", "5"},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit = %d stderr=%q stdout=%q", exitCode, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), "fake-password-garga-test-ONLY") {
		t.Fatal("stdout leaked password")
	}
	var document struct {
		Summary struct {
			ScanMode string `json:"scan_mode"`
		} `json:"summary"`
		Findings []struct {
			Category       string            `json:"category"`
			CredentialType string            `json:"credential_type"`
			RelatedFields  []string          `json:"related_fields"`
			MaskedValues   map[string]string `json:"masked_values"`
			Secret         string            `json:"secret"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout.String())
	}
	if document.Summary.ScanMode != "deep" {
		t.Fatalf("scan_mode = %q", document.Summary.ScanMode)
	}
	var pair bool
	for _, finding := range document.Findings {
		if finding.Secret != "" {
			t.Fatal("JSON finding included secret field")
		}
		if finding.CredentialType == "username_password" && len(finding.RelatedFields) == 2 {
			pair = true
			for _, value := range finding.MaskedValues {
				if value == "fake-password-garga-test-ONLY" {
					t.Fatal("masked_values leaked password")
				}
			}
		}
	}
	if !pair {
		t.Fatalf("missing credential pair: %s", stdout.String())
	}
}

func TestSecretsGenerateWritesOnlyTestIndex(t *testing.T) {
	reportDirectory := t.TempDir()
	t.Chdir(reportDirectory)
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.Path)
		if request.Method != http.MethodPut {
			t.Errorf("generator used %s", request.Method)
		}
		if !strings.HasPrefix(request.URL.Path, "/"+secrets.TestIndex+"/_doc/") {
			t.Errorf("generator wrote %s", request.URL.Path)
		}
		writer.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(writer, `{"result":"created"}`)
	}))
	defer server.Close()
	t.Setenv("GARGA_SECRETS_TEST_PASSWORD", "fake-password-garga-test-ONLY")
	var stdout, stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"secrets", "generate", "--target", server.URL, "--user", "garga-test", "--password-env", "GARGA_SECRETS_TEST_PASSWORD", "--allow-plaintext-auth", "--rate-limit", "50"},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit = %d stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), secrets.TestIndex) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if len(paths) == 0 {
		t.Fatal("generator sent no documents")
	}
}
