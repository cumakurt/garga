package secrets

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/credential"
)

func TestESClientStripsAuthorizationOnCrossOriginRedirect(t *testing.T) {
	t.Parallel()
	received := make(chan string, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Header.Get("Authorization")
		_, _ = io.WriteString(writer, `{"cluster_name":"destination","version":{"number":"9.1.0"}}`)
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusFound)
	}))
	defer origin.Close()

	parsed, err := parseTargets([]string{origin.URL})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := credential.NewBearer([]byte(plaintextCanary))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	client, err := newESClient(parsed[0].endpoint, secret, Options{
		AllowPlaintextAuth: true,
		RequestTimeout:     time.Second,
		RateLimit:          100,
	}, "garga/test")
	if err != nil {
		t.Fatal(err)
	}
	defer client.http.CloseIdleConnections()
	var root map[string]any
	if err := client.getJSON(context.Background(), "/", nil, &root); err != nil {
		t.Fatal(err)
	}
	if authorization := <-received; authorization != "" {
		t.Fatalf("redirect destination received Authorization header: %q", authorization)
	}
}
