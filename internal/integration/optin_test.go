package integration

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
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
		{"8.19.20", false, false, false},
		{"8.19.20", true, false, false},
		{"8.19.20", true, true, false},
		{"9.4.5", false, false, false},
		{"9.4.5", true, false, false},
		{"9.4.5", true, true, false},
		{"9.5.2", false, false, false},
		{"9.5.2", true, false, false},
		{"9.5.2", true, true, false},
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

func TestClusterStatusGreen(t *testing.T) {
	t.Parallel()
	if !clusterStatusGreen([]byte(`{"status":"green","timed_out":false}`)) {
		t.Fatal("green cluster should satisfy authenticated readiness")
	}
	if clusterStatusGreen([]byte(`{"status":"yellow"}`)) {
		t.Fatal("yellow cluster should not satisfy authenticated readiness")
	}
}

func TestAuthenticatedReadinessRequiresSecurityIndex(t *testing.T) {
	t.Parallel()

	var securityReady atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != elasticUsername || password != "test-password" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/_security/_authenticate":
			if !securityReady.Load() {
				writer.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = writer.Write([]byte(`{"username":"elastic"}`))
		case "/":
			_, _ = writer.Write([]byte(`{"version":{"number":"8.19.20"}}`))
		case "/_cluster/health":
			_, _ = writer.Write([]byte(`{"status":"green"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	host, rawPort, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("parse test server address: %v", err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatalf("parse test server port: %v", err)
	}
	cluster := &esCluster{
		Lane:     newLane("8.19.20", true, false, false),
		Port:     port,
		Password: "test-password",
	}
	if host != cluster.endpointHost() {
		t.Fatalf("test server host = %q, want %q", host, cluster.endpointHost())
	}

	if err := probeReady(cluster); err == nil || err.Error() != "security authentication status 503" {
		t.Fatalf("probeReady() before security index = %v", err)
	}
	securityReady.Store(true)
	if err := probeReady(cluster); err != nil {
		t.Fatalf("probeReady() after security index: %v", err)
	}
}
