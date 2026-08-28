package secrets

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/credential"
)

func TestSyntheticDocumentsCoverDetectors(t *testing.T) {
	t.Parallel()
	limits := walkLimits{
		maxDepth:       DefaultMaxDepth,
		maxArrayItems:  DefaultMaxArrayItems,
		maxObjectSize:  DefaultMaxObjectSize,
		maxFieldBytes:  DefaultMaxFieldBytes,
		entropyEnabled: true,
	}
	seen := map[string]int{}
	for _, document := range SyntheticDocuments() {
		for _, item := range walkDocument(document.Source, limits) {
			seen[item.Detector]++
		}
	}
	required := []string{
		"aws-access-key",
		"aws-secret-access-key",
		"aws-session-token",
		"google-api-key",
		"azure-storage-key",
		"azure-client-secret",
		"github-pat",
		"github-fine-grained-pat",
		"gitlab-pat",
		"slack-token",
		"slack-webhook",
		"jwt",
		"pem-private-key",
		"pgp-private-key",
		"postgres-url",
		"mysql-url",
		"mongodb-url",
		"redis-url",
		"mssql-url",
		"elasticsearch-url",
		"jdbc-url",
		"kubernetes-sa-token",
		"docker-auth",
		"password-hash",
		"authorization-header",
		"env-assignment",
		"ldap-bind",
		"smtp-credential",
		"credential-pair",
		"sensitive-field",
		"entropy",
	}
	var missing []string
	for _, detector := range required {
		if seen[detector] == 0 {
			missing = append(missing, detector)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("synthetic corpus missing detectors %v; seen=%v", missing, seen)
	}
}

func TestFalsePositiveDocumentsStayLowRisk(t *testing.T) {
	t.Parallel()
	limits := walkLimits{
		maxDepth:       DefaultMaxDepth,
		maxArrayItems:  DefaultMaxArrayItems,
		maxObjectSize:  DefaultMaxObjectSize,
		maxFieldBytes:  DefaultMaxFieldBytes,
		entropyEnabled: true,
	}
	for _, document := range FalsePositiveDocuments() {
		for _, item := range walkDocument(document.Source, limits) {
			if item.Severity == SeverityCritical || item.Severity == SeverityHigh {
				t.Fatalf("%s produced high-severity hit %+v", document.ID, item)
			}
			if item.Category != "material.public" && confidenceRank(item.Confidence) >= confidenceRank(ConfidenceHigh) && item.Detector != "public-material" {
				t.Fatalf("%s produced high-confidence hit %+v", document.ID, item)
			}
		}
	}
}

func TestGoogleAPIKeyLength(t *testing.T) {
	t.Parallel()
	key := "AIza" + "SyDl" + strings.Repeat("A", 31)
	if rest := strings.TrimPrefix(key, "AIza"); len(rest) != 35 {
		t.Fatalf("google api key suffix length = %d, want 35", len(rest))
	}
}

func TestWriteClientRejectsCrossOriginRedirect(t *testing.T) {
	t.Parallel()
	var destinationHits atomic.Int32
	var leakedAuth atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		destinationHits.Add(1)
		if request.Header.Get("Authorization") != "" {
			leakedAuth.Store(true)
		}
		_, _ = io.Copy(io.Discard, request.Body)
		writer.WriteHeader(http.StatusCreated)
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+request.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	parsed, err := parseTargets([]string{origin.URL})
	if err != nil || len(parsed) != 1 {
		t.Fatalf("parseTargets() = %v %v", parsed, err)
	}
	secret, err := credential.NewBearer([]byte(plaintextCanary))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	client, err := newWriteClient(parsed[0].endpoint, secret, Options{
		AllowPlaintextAuth: true,
		RequestTimeout:     time.Second,
		RateLimit:          100,
	}, "garga/test")
	if err != nil {
		t.Fatal(err)
	}
	defer client.http.CloseIdleConnections()
	err = client.putJSON(context.Background(), "/"+TestIndex+"/_doc/redirect", []byte(`{"n":1}`))
	if err == nil {
		t.Fatal("write client followed a cross-origin redirect")
	}
	if destinationHits.Load() != 0 {
		t.Fatalf("destination received %d requests", destinationHits.Load())
	}
	if leakedAuth.Load() {
		t.Fatal("destination received Authorization")
	}
}
