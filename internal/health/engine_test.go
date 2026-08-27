package health

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/credential"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	basemodel "github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/target"
)

func TestRunRefusesCredentialsOverHTTPWithoutOverride(t *testing.T) {
	t.Parallel()
	secret, err := credential.NewBasic("elastic", []byte("credential-canary"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	_, err = Run(context.Background(), Options{
		Config: config.Defaults(), Endpoint: basemodel.Endpoint{Scheme: basemodel.SchemeHTTP, Host: "127.0.0.1", Port: 9200}, Secret: secret,
	})
	var healthError *Error
	if !errors.As(err, &healthError) || healthError.Kind != ErrorConfiguration {
		t.Fatalf("Run() error = %#v, want configuration error", err)
	}
}

func TestRunReportsPlaintextAuthOverrideAsCritical(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status, payload := engineFixture(request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, payload)
	}))
	defer server.Close()
	secret, err := credential.NewBasic("elastic", []byte("credential-canary"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	parsed, err := target.Parse(server.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := target.Endpoint(parsed)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), Options{
		Config: config.Defaults(), Endpoint: endpoint, Secret: secret, AllowPlaintextAuth: true, ScannerVersion: "test",
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	found := false
	for _, finding := range result.Report.Findings {
		if finding.RootCause == "plaintext_auth_override" && finding.Severity == healthmodel.SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("findings = %#v, want plaintext_auth_override CRITICAL", result.Report.Findings)
	}
}

func engineFixture(path string) (int, string) {
	switch path {
	case "/":
		return http.StatusOK, `{"cluster_name":"fixture","cluster_uuid":"uuid","version":{"number":"8.19.19","build_flavor":"default"},"tagline":"You Know, for Search"}`
	case "/_cluster/health":
		return http.StatusOK, `{"status":"green","number_of_nodes":3,"number_of_data_nodes":3,"active_shards_percent_as_number":100,"unassigned_shards":0}`
	case "/_cluster/stats":
		return http.StatusOK, `{"indices":{"count":0,"shards":{"total":0},"docs":{"count":0},"store":{"size_in_bytes":0}},"nodes":{"count":{"total":3,"data":3}}}`
	case "/_nodes/_all/os,process,jvm":
		return http.StatusOK, `{"nodes":{"node-1":{"name":"data-1","roles":["master","data_hot"]},"node-2":{"name":"data-2","roles":["master","data_hot"]},"node-3":{"name":"data-3","roles":["master","data_hot"]}}}`
	case "/_nodes/stats/jvm,os,process,fs,thread_pool,breaker,indices,indexing_pressure":
		return http.StatusOK, `{"nodes":{"node-1":{"name":"data-1","roles":["master","data_hot"],"fs":{"total":{"total_in_bytes":100,"available_in_bytes":50}}},"node-2":{"name":"data-2","roles":["master","data_hot"],"fs":{"total":{"total_in_bytes":100,"available_in_bytes":50}}},"node-3":{"name":"data-3","roles":["master","data_hot"],"fs":{"total":{"total_in_bytes":100,"available_in_bytes":50}}}}}`
	case "/_cat/indices", "/_cat/shards":
		return http.StatusOK, `[]`
	case "/_security/_authenticate":
		return http.StatusOK, `{"username":"elastic","authentication_type":"realm"}`
	default:
		return http.StatusOK, `{}`
	}
}
