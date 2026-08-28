package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/capability"
	"github.com/cumakurt/garga/internal/checks"
	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/health"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
	"github.com/cumakurt/garga/internal/transport"
)

func TestElasticsearchIntegrationMatrix(t *testing.T) {
	requireIntegration(t)
	lanes := selectedLanes()
	if len(lanes) == 0 {
		t.Fatalf("GARGA_INTEGRATION_VERSION=%q matched no matrix lanes", requestedVersion())
	}
	for _, lane := range lanes {
		t.Run(lane.name(), func(t *testing.T) {
			cluster := startCluster(t, lane)
			assessCluster(t, cluster)
			assessHealthEngine(t, cluster)
		})
	}
}

func assessHealthEngine(t *testing.T, cluster *esCluster) {
	t.Helper()

	cfg := config.Defaults()
	cfg.Scanner.RequestTimeout = 10 * time.Second
	cfg.Scanner.Retries = 0
	cfg.Health.RequestsPerSecond = 100

	var secret *credential.Secret
	if cluster.Lane.Auth {
		var err error
		secret, err = credential.NewBasic(elasticUsername, []byte(cluster.Password))
		if err != nil {
			t.Fatalf("assessment credential: %v", err)
		}
		defer secret.Destroy()
		cluster.secrets = append(cluster.secrets, secretTokens(secret)...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := health.Run(ctx, health.Options{
		Config: cfg, Endpoint: cluster.endpoint(), Secret: secret, Deep: true,
		Insecure: cluster.Lane.TLS, AllowPlaintextAuth: cluster.Lane.Auth && !cluster.Lane.TLS,
		UserAgent: "garga/integration", ScannerVersion: "integration", AssessmentMode: true,
	})
	if err != nil {
		t.Fatalf("contextual assessment: %s\n%s", cluster.redact(err.Error()), cluster.diagnostics())
	}
	if !result.Report.Metadata.AssessmentMode || !result.Report.Metadata.DeepScanEnabled {
		t.Fatalf("assessment metadata = %#v", result.Report.Metadata)
	}
	if result.Report.Cluster.Version.Number != cluster.Lane.Version || result.Report.Summary.Nodes < 1 {
		t.Fatalf("assessment cluster version=%q nodes=%d, want %q and at least one node",
			result.Report.Cluster.Version.Number, result.Report.Summary.Nodes, cluster.Lane.Version)
	}
	if result.Report.Summary.CheckCoverage.Available != 39 {
		t.Fatalf("assessment check coverage available=%d, want 39", result.Report.Summary.CheckCoverage.Available)
	}
	if !collectorSucceeded(result.Report.Metadata.Collectors, "nodes_info") {
		t.Fatalf("assessment did not collect node runtime inventory: %#v", result.Report.Metadata.Collectors)
	}
	encoded, err := json.Marshal(result.Report)
	if err != nil {
		t.Fatalf("marshal assessment report: %v", err)
	}
	for _, token := range cluster.secrets {
		if token != "" && strings.Contains(string(encoded), token) {
			t.Fatal("assessment report contains credential material")
		}
	}
}

func collectorSucceeded(results []healthmodel.CollectorResult, name string) bool {
	for _, result := range results {
		if result.Name == name {
			return result.Status == "success"
		}
	}
	return false
}

func assessCluster(t *testing.T, cluster *esCluster) {
	t.Helper()
	factory, err := newClusterFactory(cluster)
	if err != nil {
		t.Fatalf("transport factory: %v\n%s", err, cluster.diagnostics())
	}
	t.Cleanup(factory.CloseIdleConnections)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	prober, err := probe.NewHTTP(factory.Client())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	endpoint := cluster.endpoint()
	root, err := prober.Probe(ctx, endpoint)
	if err != nil {
		t.Fatalf("root probe: %v\n%s", cluster.redact(err.Error()), cluster.diagnostics())
	}

	fpOptions, err := fingerprint.OptionsFromConfig(config.Defaults())
	if err != nil {
		t.Fatalf("fingerprint options: %v", err)
	}
	engine, err := fingerprint.New(fpOptions)
	if err != nil {
		t.Fatalf("fingerprint engine: %v", err)
	}

	var identity fingerprint.Result
	if cluster.Lane.Auth {
		if root.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous root status = %d, want 401 headers=%v", root.StatusCode, headerNames(root))
		}
		identity = engine.Analyze(root)
		if identity.Detected {
			t.Fatalf("anonymous 401 unexpectedly detected product=%q score=%d headers=%v",
				identity.Product, identity.Score, headerNames(root))
		}
	} else {
		identity = engine.Analyze(root)
		if !identity.Detected || identity.Product != "Elasticsearch" {
			t.Fatalf("fingerprint detected=%t product=%q score=%d class=%s status=%d headers=%v",
				identity.Detected, identity.Product, identity.Score, identity.Classification, root.StatusCode, headerNames(root))
		}
		if identity.Version != cluster.Lane.Version {
			t.Fatalf("fingerprint version = %q, want %q status=%d", identity.Version, cluster.Lane.Version, root.StatusCode)
		}
	}

	if cluster.Lane.Auth {
		verifyValidCredential(t, ctx, factory.Client(), cluster, endpoint)
		authenticated, authErr := authenticatedRoot(ctx, factory.Client(), cluster)
		if authErr != nil {
			t.Fatalf("authenticated root: %v", cluster.redact(authErr.Error()))
		}
		identity = engine.Analyze(authenticated)
		if !identity.Detected || identity.Product != "Elasticsearch" || identity.Version != cluster.Lane.Version {
			t.Fatalf("authenticated fingerprint detected=%t product=%q version=%q score=%d headers=%v",
				identity.Detected, identity.Product, identity.Version, identity.Score, headerNames(authenticated))
		}
		verifyInvalidCredential(t, ctx, factory.Client(), cluster, endpoint)
	} else {
		verifySecurityUnavailable(t, ctx, factory.Client(), cluster, endpoint)
	}

	detector, err := capability.New(prober)
	if err != nil {
		t.Fatalf("capability detector: %v", err)
	}
	caps, err := detector.Discover(ctx, endpoint, identity, root)
	if err != nil {
		t.Fatalf("capability discover: %v", cluster.redact(err.Error()))
	}

	if cluster.Lane.Auth {
		if caps.IsAvailable(capability.NameAnonymous) {
			t.Fatalf("anonymous capability available on authenticated lane\n%s", cluster.diagnostics())
		}
		if !caps.Exists(capability.NameSecurity) {
			t.Fatalf("security capability missing on authenticated lane availability=%s\n%s",
				caps.AvailabilityOf(capability.NameSecurity), cluster.diagnostics())
		}
		if !caps.Exists(capability.NameBasicAuth) && root.StatusCode != http.StatusOK {
			t.Fatalf("basic_auth capability missing availability=%s status=%d\n%s",
				caps.AvailabilityOf(capability.NameBasicAuth), root.StatusCode, cluster.diagnostics())
		}
	} else {
		if !caps.IsAvailable(capability.NameAnonymous) {
			t.Fatalf("anonymous capability missing on anonymous lane availability=%s status=%d\n%s",
				caps.AvailabilityOf(capability.NameAnonymous), root.StatusCode, cluster.diagnostics())
		}
		if !caps.Suppresses(capability.NameSecurity) {
			t.Fatalf("security capability = %s, want unsupported on anonymous lane\n%s",
				caps.AvailabilityOf(capability.NameSecurity), cluster.diagnostics())
		}
	}

	findings := checks.DefaultRegistry().Evaluate(checks.Input{
		Endpoint:     endpoint,
		Fingerprint:  identity,
		Capabilities: caps,
	})
	ids := findingIDs(findings)
	if cluster.Lane.TLS {
		if ids[checks.CheckTLSNotEnabled] {
			t.Fatalf("tls.not_enabled on HTTPS lane: %v", ids)
		}
	} else if !ids[checks.CheckTLSNotEnabled] {
		t.Fatalf("missing tls.not_enabled on HTTP lane: %v", ids)
	}
	if cluster.Lane.Auth {
		if ids[checks.CheckExposureAnonymousAccess] {
			t.Fatalf("anonymous_access on authenticated lane: %v", ids)
		}
		if ids[checks.CheckExposureSecurityUnconfigured] {
			t.Fatalf("security_unconfigured on authenticated lane: %v", ids)
		}
	} else {
		if !ids[checks.CheckExposureAnonymousAccess] {
			t.Fatalf("missing anonymous_access on anonymous lane: %v", ids)
		}
		if !ids[checks.CheckExposureSecurityUnconfigured] {
			t.Fatalf("missing security_unconfigured on anonymous lane: %v", ids)
		}
	}
	if ids[checks.CheckExposurePublicNetwork] {
		t.Fatalf("loopback target classified as public: %v", ids)
	}
}

func probeReady(cluster *esCluster) error {
	factory, err := newClusterFactory(cluster)
	if err != nil {
		return err
	}
	defer factory.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !cluster.Lane.Auth {
		prober, err := probe.NewHTTP(factory.Client())
		if err != nil {
			return err
		}
		result, err := prober.Probe(ctx, cluster.endpoint())
		if err != nil {
			return err
		}
		if result.StatusCode == http.StatusOK {
			return nil
		}
		return fmt.Errorf("ready status %d", result.StatusCode)
	}

	// A successful root request does not prove that the .security index is ready.
	authentication, err := authenticatedGET(ctx, factory.Client(), cluster, "/_security/_authenticate")
	if err != nil {
		return err
	}
	if authentication.StatusCode != http.StatusOK {
		return fmt.Errorf("security authentication status %d", authentication.StatusCode)
	}
	root, err := authenticatedGET(ctx, factory.Client(), cluster, "/")
	if err != nil {
		return err
	}
	if root.StatusCode != http.StatusOK {
		return fmt.Errorf("authenticated root status %d", root.StatusCode)
	}
	health, err := authenticatedGET(ctx, factory.Client(), cluster, "/_cluster/health")
	if err != nil {
		return err
	}
	if health.StatusCode != http.StatusOK {
		return fmt.Errorf("cluster health status %d", health.StatusCode)
	}
	if !clusterStatusGreen(health.Body) {
		return fmt.Errorf("authenticated cluster health is not green")
	}
	return nil
}

func newClusterFactory(cluster *esCluster) (*transport.Factory, error) {
	options, err := transport.OptionsFromConfig(config.Defaults(), "garga/integration")
	if err != nil {
		return nil, err
	}
	options.DisableEnvironmentProxy = true
	options.ConnectTimeout = 2 * time.Second
	options.RequestTimeout = 5 * time.Second
	options.ResponseHeaderTimeout = 5 * time.Second
	options.TLSHandshakeTimeout = 5 * time.Second
	if cluster.Lane.TLS {
		if cluster.Certs.RootCAs == nil {
			return nil, fmt.Errorf("tls lane missing certificate pool")
		}
		options.RootCAs = cluster.Certs.RootCAs
	}
	return transport.NewFactory(options)
}

func (cluster *esCluster) endpoint() model.Endpoint {
	scheme := model.SchemeHTTP
	if cluster.Lane.TLS {
		scheme = model.SchemeHTTPS
	}
	return model.Endpoint{Scheme: scheme, Host: cluster.endpointHost(), Port: cluster.Port, Path: "/"}
}

func findingIDs(findings []model.Finding) map[string]bool {
	ids := make(map[string]bool, len(findings))
	for _, finding := range findings {
		ids[finding.CheckID] = true
	}
	return ids
}

func secretTokens(secret *credential.Secret) []string {
	if secret == nil {
		return nil
	}
	header, err := secret.AuthorizationHeader()
	if err != nil {
		return nil
	}
	return []string{header}
}

func newVerifier(t *testing.T, client *transport.Client) *credential.Verifier {
	t.Helper()
	verifier, err := credential.NewVerifier(client)
	if err != nil {
		t.Fatalf("credential verifier: %v", err)
	}
	return verifier
}

func verifyValidCredential(t *testing.T, ctx context.Context, client *transport.Client, cluster *esCluster, endpoint model.Endpoint) {
	t.Helper()
	secret, err := credential.NewBasic(elasticUsername, []byte(cluster.Password))
	if err != nil {
		t.Fatalf("basic secret: %v", err)
	}
	defer secret.Destroy()
	cluster.secrets = append(cluster.secrets, secretTokens(secret)...)
	result, verifyErr := newVerifier(t, client).Verify(ctx, endpoint, secret)
	if verifyErr != nil {
		t.Fatalf("auth-check valid path: %v", cluster.redact(verifyErr.Error()))
	}
	if result.Outcome != credential.OutcomeValid {
		t.Fatalf("auth-check outcome = %s status=%d, want valid", result.Outcome, result.StatusCode)
	}
}

func verifyInvalidCredential(t *testing.T, ctx context.Context, client *transport.Client, cluster *esCluster, endpoint model.Endpoint) {
	t.Helper()
	wrongPassword := "Garga-Int-wrong-canary!"
	cluster.secrets = append(cluster.secrets, wrongPassword)
	wrong, err := credential.NewBasic(elasticUsername, []byte(wrongPassword))
	if err != nil {
		t.Fatalf("wrong secret: %v", err)
	}
	defer wrong.Destroy()
	cluster.secrets = append(cluster.secrets, secretTokens(wrong)...)
	denied, deniedErr := newVerifier(t, client).Verify(ctx, endpoint, wrong)
	if deniedErr != nil {
		t.Fatalf("auth-check invalid path: %v", cluster.redact(deniedErr.Error()))
	}
	if denied.Outcome != credential.OutcomeInvalid {
		t.Fatalf("wrong password outcome = %s status=%d, want invalid", denied.Outcome, denied.StatusCode)
	}
}

func verifySecurityUnavailable(t *testing.T, ctx context.Context, client *transport.Client, cluster *esCluster, endpoint model.Endpoint) {
	t.Helper()
	unusedPassword := "Garga-Int-unused-canary!"
	cluster.secrets = append(cluster.secrets, unusedPassword)
	placeholder, err := credential.NewBasic(elasticUsername, []byte(unusedPassword))
	if err != nil {
		t.Fatalf("placeholder secret: %v", err)
	}
	defer placeholder.Destroy()
	cluster.secrets = append(cluster.secrets, secretTokens(placeholder)...)
	result, verifyErr := newVerifier(t, client).Verify(ctx, endpoint, placeholder)
	if verifyErr != nil {
		t.Fatalf("auth-check security_unavailable path: %v", cluster.redact(verifyErr.Error()))
	}
	if result.Outcome != credential.OutcomeSecurityUnavailable {
		t.Fatalf("anonymous lane auth-check outcome = %s status=%d, want security_unavailable",
			result.Outcome, result.StatusCode)
	}
}

func authenticatedRoot(ctx context.Context, client *transport.Client, cluster *esCluster) (probe.Result, error) {
	response, err := authenticatedGET(ctx, client, cluster, "/")
	if err != nil {
		return probe.Result{}, err
	}
	if response.StatusCode != http.StatusOK {
		return probe.Result{}, fmt.Errorf("authenticated root status %d", response.StatusCode)
	}
	return probeResultFromHTTP(response), nil
}

func authenticatedGET(ctx context.Context, client *transport.Client, cluster *esCluster, path string) (transport.Response, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		return transport.Response{}, fmt.Errorf("harness path is invalid")
	}
	secret, err := credential.NewBasic(elasticUsername, []byte(cluster.Password))
	if err != nil {
		return transport.Response{}, err
	}
	defer secret.Destroy()
	endpoint := cluster.endpoint()
	endpoint.Path = path
	rawURL, err := endpoint.URL()
	if err != nil {
		return transport.Response{}, err
	}
	header, err := secret.AuthorizationHeader()
	if err != nil {
		return transport.Response{}, err
	}
	request, err := transport.NewRequest(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return transport.Response{}, fmt.Errorf("%s", credential.Redact(err.Error(), secret))
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", header)
	response, err := client.Do(request)
	if err != nil {
		return transport.Response{}, fmt.Errorf("%s", credential.Redact(err.Error(), secret))
	}
	return response, nil
}

func probeResultFromHTTP(response transport.Response) probe.Result {
	names := []string{"Content-Type", "Server", "Warning", "Www-Authenticate", "X-Elastic-Product"}
	headers := make([]probe.HeaderField, 0, len(names))
	for _, name := range names {
		values := response.Header.Values(name)
		if len(values) == 0 {
			continue
		}
		headers = append(headers, probe.HeaderField{Name: name, Values: append([]string(nil), values...)})
	}
	return probe.Result{
		Request:    probe.RequestMetadata{Method: http.MethodGet, Resource: probe.ResourceRoot},
		StatusCode: response.StatusCode,
		Protocol:   response.Protocol,
		Headers:    headers,
		Body:       append([]byte(nil), response.Body...),
	}
}

func headerNames(result probe.Result) []string {
	names := make([]string, 0, len(result.Headers))
	for _, field := range result.Headers {
		names = append(names, field.Name)
	}
	return names
}
