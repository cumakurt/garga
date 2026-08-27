package integration

import (
	"os"
	"strings"
	"testing"
)

func requireIntegration(t *testing.T) {
	t.Helper()
	if !integrationEnabled() {
		t.Skip("set GARGA_INTEGRATION=1 to run Elasticsearch container tests")
	}
}

func TestIntegrationStaysOptIn(t *testing.T) {
	t.Parallel()
	if os.Getenv(integrationEnv) == "1" {
		t.Skip("opt-in gate is enabled in this process")
	}
	if integrationEnabled() {
		t.Fatal("integrationEnabled() = true without GARGA_INTEGRATION=1")
	}
}

func TestMatrixPinsMatchSupportPolicy(t *testing.T) {
	t.Parallel()

	want := []struct {
		version string
		auth    bool
		tls     bool
		legacy  bool
	}{
		{"8.19.19", false, false, false},
		{"8.19.19", true, false, false},
		{"8.19.19", true, true, false},
		{"9.3.8", false, false, false},
		{"9.3.8", true, false, false},
		{"9.3.8", true, true, false},
		{"9.4.4", false, false, false},
		{"9.4.4", true, false, false},
		{"9.4.4", true, true, false},
		{"7.17.23", false, false, true},
	}
	lanes := matrixLanes()
	if len(lanes) != len(want) {
		t.Fatalf("matrix size = %d, want %d", len(lanes), len(want))
	}
	for index, lane := range lanes {
		got := want[index]
		if lane.Version != got.version || lane.Auth != got.auth || lane.TLS != got.tls || lane.Legacy != got.legacy {
			t.Fatalf("lane[%d] = %#v, want %#v", index, lane, got)
		}
		if lane.Image != imageRepository+":"+lane.Version {
			t.Fatalf("lane[%d] image = %q", index, lane.Image)
		}
		if strings.Contains(lane.name(), " ") {
			t.Fatalf("lane name contains space: %q", lane.name())
		}
	}
}

func TestGenerateTLSMaterial(t *testing.T) {
	t.Parallel()
	material, err := generateTLSMaterial()
	if err != nil {
		t.Fatalf("generateTLSMaterial() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(material.Dir) })
	if material.RootCAs == nil {
		t.Fatal("missing RootCAs")
	}
	keyInfo, err := os.Stat(material.Dir + "/http.key")
	if err != nil {
		t.Fatalf("http.key: %v", err)
	}
	if keyInfo.Mode().Perm()&0o004 != 0 {
		t.Fatalf("http.key is world-readable: %s", keyInfo.Mode())
	}
	for _, name := range []string{"ca.crt", "http.crt", "http.key"} {
		if _, err := os.Stat(material.Dir + "/" + name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestRedactClusterDiagnostics(t *testing.T) {
	t.Parallel()

	password := "garga-integration-canary"
	header := "Basic dXNlcjpwYXNz"
	logs := "Password for the elastic user is: " + password + "\nAuthorization: " + header + "\nstarted"
	got := redactDiagnostics(logs, []string{password, header})
	if strings.Contains(got, password) || strings.Contains(got, header) {
		t.Fatalf("diagnostics leaked secret material: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("diagnostics = %q, want [redacted] markers", got)
	}
	if !strings.Contains(got, "started") {
		t.Fatalf("diagnostics dropped non-secret text: %q", got)
	}
}

func TestParseResetPassword(t *testing.T) {
	t.Parallel()
	got := parseResetPassword("Password for the [elastic] user successfully reset.\nNew value: Garga-Int-canary!\n")
	if got != "Garga-Int-canary!" {
		t.Fatalf("parseResetPassword() = %q", got)
	}
	if parseResetPassword("no password here") != "" {
		t.Fatal("expected empty parse")
	}
}

func TestClusterStatusReady(t *testing.T) {
	t.Parallel()
	if !clusterStatusReady([]byte(`{"cluster_name":"docker-cluster","status":"yellow"}`)) {
		t.Fatal("yellow cluster should be ready")
	}
	if !clusterStatusReady([]byte(`{"status":"green","timed_out":false}`)) {
		t.Fatal("green cluster should be ready")
	}
	if clusterStatusReady([]byte(`{"status":"red"}`)) {
		t.Fatal("red cluster should not be ready")
	}
}
