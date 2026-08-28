package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/credential/detect"
)

func TestAuthDetectHelpDocumentsModes(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-detect", "--help"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	help := stdout.String()
	for _, fragment := range []string{
		"--mode", "stuffing", "spraying", "brute-force", "dictionary",
		"--wordlist", "--charset", "--credentials-file", "--users-file",
		"--spray-delay", "process listings",
	} {
		if !strings.Contains(help, fragment) {
			t.Fatalf("help missing %q: %s", fragment, help)
		}
	}
	if strings.Contains(help, "--password string") {
		t.Fatalf("help advertised a command-line password flag: %s", help)
	}
}

func TestAuthDetectDoesNotRegisterPasswordFlag(t *testing.T) {
	t.Parallel()

	root := NewRootCommand(BuildInfo{})
	cmd, _, err := root.Find([]string{"auth-detect"})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if cmd.Flags().Lookup("password") != nil {
		t.Fatal("auth-detect registered a --password flag")
	}
}

func TestScanSourcesDoNotCallDetectEngine(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{"scan*.go", "fingerprint*.go", "vuln*.go"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("Glob(%s) error = %v", pattern, err)
		}
		for _, filename := range matches {
			content, readErr := os.ReadFile(filename)
			if readErr != nil {
				t.Fatalf("ReadFile(%s) error = %v", filename, readErr)
			}
			text := string(content)
			if strings.Contains(text, "internal/credential/detect") || strings.Contains(text, "runAuthDetect") {
				t.Fatalf("%s references the credential detection engine", filename)
			}
		}
	}
}

func TestAuthDetectStuffingStopsOnSuccess(t *testing.T) {
	const canary = "credential-canary"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		count := requests.Add(1)
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/_security/_authenticate") {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		if count == 1 {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"error":"`+canary+`"}`)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, `{"username":"bob"}`)
	}))
	defer server.Close()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")

	input := "basic alice " + canary + "-1\nbasic bob " + canary + "-2\n"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-detect", server.URL, "--mode", "stuffing", "--credentials-stdin"},
		BuildInfo{Version: "test"},
		strings.NewReader(input),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
	output := stdout.String()
	if !strings.Contains(output, string(credential.OutcomeValid)) || !strings.Contains(output, "mode=stuffing") {
		t.Fatalf("stdout = %q", output)
	}
	if !strings.Contains(output, "reason="+string(detect.StopSuccess)) {
		t.Fatalf("stdout missing stop reason: %q", output)
	}
	if strings.Contains(output, canary) || strings.Contains(stderr.String(), canary) {
		t.Fatalf("output leaked canary")
	}
}

func TestAuthDetectSprayingUsesPasswordOuterLoop(t *testing.T) {
	const canary = "credential-canary"
	var usernames []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, _, ok := request.BasicAuth()
		if !ok {
			t.Fatal("missing basic auth")
		}
		usernames = append(usernames, username)
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, `{"error":"`+canary+`"}`)
	}))
	defer server.Close()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")

	input := `@users
alice
bob
@passwords
p1
p2
`
	var stdout bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-detect", server.URL, "--mode", "spraying", "--spray-input-stdin", "--max-attempts", "4"},
		BuildInfo{Version: "test"},
		strings.NewReader(input),
		&stdout,
		&bytes.Buffer{},
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d", exitCode)
	}
	want := []string{"alice", "bob", "alice", "bob"}
	if len(usernames) != len(want) {
		t.Fatalf("usernames = %#v, want %#v", usernames, want)
	}
	for index, username := range usernames {
		if username != want[index] {
			t.Fatalf("usernames[%d] = %q, want %q", index, username, want[index])
		}
	}
}

func TestAuthDetectBruteForceRequiresUsername(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-detect", "http://127.0.0.1:9200", "--mode", "brute-force", "--passwords-stdin"},
		BuildInfo{},
		strings.NewReader("password\n"),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
}

func TestAuthDetectStuffingAcceptsColonDump(t *testing.T) {
	const canary = "credential-canary"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "alice" || password != canary {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")

	var stdout bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-detect", server.URL, "--mode", "stuffing", "--credentials-stdin"},
		BuildInfo{Version: "test"},
		strings.NewReader("alice:"+canary+"\n"),
		&stdout,
		&bytes.Buffer{},
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d stdout=%q", exitCode, stdout.String())
	}
	if !strings.Contains(stdout.String(), "usernames=alice") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stdout.String(), canary) {
		t.Fatal("stdout leaked canary")
	}
}

func TestAuthDetectDictionaryWordlist(t *testing.T) {
	const canary = "credential-canary"
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		count := attempts.Add(1)
		username, password, ok := request.BasicAuth()
		if !ok || username != "elastic" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if password == canary+"-ok" {
			writer.WriteHeader(http.StatusOK)
			return
		}
		if count > 4 {
			t.Errorf("unexpected extra attempt %d", count)
		}
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")

	wordlist := filepath.Join(t.TempDir(), "wordlist.txt")
	if err := os.WriteFile(wordlist, []byte("wrong\n"+canary+"-ok\nlater\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-detect", server.URL, "--mode", "dictionary", "--username", "elastic", "--wordlist", wordlist},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&bytes.Buffer{},
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d stdout=%q", exitCode, stdout.String())
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
	if !strings.Contains(stdout.String(), "mode=dictionary") || !strings.Contains(stdout.String(), "reason=success") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAuthDetectBruteForceCharset(t *testing.T) {
	var usernames []string
	var passwords []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok {
			t.Fatal("missing basic auth")
		}
		usernames = append(usernames, username)
		passwords = append(passwords, password)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")

	var stdout bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{
			"auth-detect", server.URL,
			"--mode", "brute-force",
			"--username", "elastic",
			"--charset", "ab",
			"--min-length", "1",
			"--max-length", "1",
			"--max-attempts", "2",
		},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&bytes.Buffer{},
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d stdout=%q", exitCode, stdout.String())
	}
	if len(usernames) != 2 || usernames[0] != "elastic" || usernames[1] != "elastic" {
		t.Fatalf("usernames = %#v", usernames)
	}
	if len(passwords) != 2 || passwords[0] != "a" || passwords[1] != "b" {
		t.Fatalf("passwords = %#v", passwords)
	}
	if !strings.Contains(stdout.String(), "mode=brute-force") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAuthDetectSprayingFromFiles(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok {
			t.Fatal("missing basic auth")
		}
		seen = append(seen, username+":"+password)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")

	dir := t.TempDir()
	usersFile := filepath.Join(dir, "users.txt")
	passwordsFile := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(usersFile, []byte("alice\nbob\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(users) error = %v", err)
	}
	if err := os.WriteFile(passwordsFile, []byte("p1\np2\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(passwords) error = %v", err)
	}

	exitCode := Execute(
		context.Background(),
		[]string{
			"auth-detect", server.URL,
			"--mode", "spraying",
			"--users-file", usersFile,
			"--passwords-file", passwordsFile,
			"--max-attempts", "4",
		},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&bytes.Buffer{},
		&bytes.Buffer{},
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d", exitCode)
	}
	want := []string{"alice:p1", "bob:p1", "alice:p2", "bob:p2"}
	if len(seen) != len(want) {
		t.Fatalf("seen = %#v, want %#v", seen, want)
	}
	for index, expected := range want {
		if seen[index] != expected {
			t.Fatalf("seen[%d] = %q, want %q", index, seen[index], expected)
		}
	}
}

func TestAuthDetectDictionaryRejectsCharset(t *testing.T) {
	t.Parallel()

	exitCode := Execute(
		context.Background(),
		[]string{"auth-detect", "http://127.0.0.1:9200", "--mode", "dictionary", "--username", "elastic", "--charset", "ab"},
		BuildInfo{},
		strings.NewReader(""),
		&bytes.Buffer{},
		&bytes.Buffer{},
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d", exitCode)
	}
}
