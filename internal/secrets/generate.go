package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/ratelimit"
)

// TestIndex is the synthetic dataset index used by the local generator.
const TestIndex = "garga-sensitive-test"

const syntheticNote = "SYNTHETIC TEST DATA ONLY - NOT A REAL CREDENTIAL"

// SyntheticDocument is one clearly fake document for local testing.
type SyntheticDocument struct {
	ID     string
	Source map[string]any
}

func synthetic(id string, fields map[string]any) SyntheticDocument {
	source := map[string]any{
		"dataset": TestIndex,
		"note":    syntheticNote,
	}
	for key, value := range fields {
		source[key] = value
	}
	return SyntheticDocument{ID: id, Source: source}
}

//nolint:gosec // This local test-data generator intentionally contains recognizable fake credential patterns.
func SyntheticDocuments() []SyntheticDocument {
	return []SyntheticDocument{
		synthetic("password-field", map[string]any{
			"username": "garga-test-user",
			"password": "fake-password-garga-test-ONLY",
		}),
		synthetic("api-key-field", map[string]any{
			"user":    "garga-api-user",
			"api_key": "garga-test-api-key-NOT-REAL-ABCDEF",
		}),
		synthetic("aws-keys", map[string]any{
			"aws_access_key_id":     "AKIA" + "IOSFODNN7EXAMPLE",
			"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
		}),
		synthetic("aws-session", map[string]any{
			"session_token": "IQoJ" + strings.Repeat("A", 80),
		}),
		synthetic("gcp-api-key", map[string]any{
			"google_api_key": "AIza" + "SyDl" + strings.Repeat("A", 31),
		}),
		synthetic("azure-storage", map[string]any{
			"connection_string": "DefaultEndpointsProtocol=https;AccountName=gargatest;AccountKey=" + strings.Repeat("A", 44) + ";EndpointSuffix=core.windows.net",
		}),
		synthetic("azure-client-secret", map[string]any{
			"config": "azure_client_secret=garga-azure-client-secret-NOT-REAL",
		}),
		synthetic("github-token", map[string]any{
			"token": "ghp_000000000000000000000000000000000000",
		}),
		synthetic("github-fine-grained", map[string]any{
			"token": "github_pat_" + "11GARGATESTONLY0000000",
		}),
		synthetic("gitlab-token", map[string]any{
			"gitlab_token": "glpat-" + strings.Repeat("A", 20),
		}),
		synthetic("slack-token", map[string]any{
			"slack_token": "xoxb-1234567890-gargaTestNotReal",
		}),
		synthetic("slack-webhook", map[string]any{
			"message": "https://hooks.slack.com/services/T00000000/B00000000/gargaTestNotReal000000000000",
		}),
		synthetic("jwt", map[string]any{
			"authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJnYXJnYS10ZXN0IiwiZGF0YXNldCI6ImdhcmdhLXNlbnNpdGl2ZS10ZXN0In0.garga-test-signature-NOT-REAL",
		}),
		synthetic("basic-auth-header", map[string]any{
			"headers": "Authorization: Basic Z2FyZ2E6ZmFrZS1wYXNzd29yZC1PTkxZ",
		}),
		synthetic("rsa-private-key", map[string]any{
			"private_key": fakePEM("RSA"),
		}),
		synthetic("openssh-private-key", map[string]any{
			"ssh_key": fakePEM("OPENSSH"),
		}),
		synthetic("pgp-private-key", map[string]any{
			"private_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: garga-test\nlQEY fake-pgp-material-NOT-A-REAL-KEY\n-----END PGP PRIVATE KEY BLOCK-----",
		}),
		synthetic("postgres-url", map[string]any{
			"connection_string": fakePostgresURL(),
		}),
		synthetic("mysql-url", map[string]any{
			"dsn": "mysql://garga_test:FakePasswordOnly@localhost:3306/garga_test",
		}),
		synthetic("mongodb-url", map[string]any{
			"dsn": "mongodb://garga_test:FakePasswordOnly@localhost:27017/garga_test",
		}),
		synthetic("redis-url", map[string]any{
			"dsn": "redis://garga_test:FakePasswordOnly@localhost:6379/0",
		}),
		synthetic("mssql-url", map[string]any{
			"dsn": "mssql://garga_test:FakePasswordOnly@localhost:1433/garga_test",
		}),
		synthetic("elasticsearch-url", map[string]any{
			"connection_string": "https://garga_test:FakePasswordOnly@localhost:9200/",
		}),
		synthetic("jdbc-url", map[string]any{
			"jdbc": "jdbc:postgresql://localhost:5432/garga_test?user=garga_test&password=FakePasswordOnly",
		}),
		synthetic("oauth", map[string]any{
			"client_id":     "garga-test-client",
			"client_secret": fakeOAuthSecret(),
		}),
		synthetic("password-hash-bcrypt", map[string]any{
			"password_hash": "$2a$10$gargaTestFakeBcryptHashValueNotARealPasswordHashXX",
		}),
		synthetic("password-hash-argon2", map[string]any{
			"password_hash": "$argon2id$v=19$m=65536,t=2,p=1$gargaTestSalt$gargaTestHashNotReal",
		}),
		synthetic("password-hash-pbkdf2", map[string]any{
			"password_hash": "$pbkdf2-sha256$29000$gargaTestSalt$gargaTestHashNotRealXXXX",
		}),
		synthetic("password-hash-scrypt", map[string]any{
			"password_hash": "$scrypt$ln=16,r=8,p=1$gargaTestSalt$gargaTestHashNotReal",
		}),
		synthetic("password-hash-sha512crypt", map[string]any{
			"password_hash": "$6$gargaTestSalt$gargaTestSha512CryptHashNotARealPassword",
		}),
		synthetic("password-hash-ntlm", map[string]any{
			"password_hash": "aabbccddeeff00112233445566778899",
		}),
		synthetic("password-hash-md5crypt", map[string]any{
			"password_hash": "$1$gargaTest$gargaMD5CryptHashNotRealXXX",
		}),
		synthetic("nested-services", map[string]any{
			"services": []any{
				map[string]any{"username": "svc-garga", "password": "nested-fake-password-ONLY"},
			},
		}),
		synthetic("camel-case-secret", map[string]any{
			"clientSecret": "gargaCamelCaseSecret-NOT-REAL-0123456789",
		}),
		synthetic("kebab-case-key", map[string]any{
			"api-key": "garga-kebab-api-key-NOT-REAL-ABCDEF",
		}),
		synthetic("env-log", map[string]any{
			"message": "startup config dump\nAPI_KEY=garga-test-api-key-NOT-REAL\nTOKEN=garga-test-token-NOT-REAL",
		}),
		synthetic("ldap-bind", map[string]any{
			"config": "binddn=cn=admin,dc=garga,dc=test\nbindpw=garga-ldap-password-ONLY",
		}),
		synthetic("smtp-auth", map[string]any{
			"config": "smtp_user=garga-test\nsmtp_password=garga-smtp-password-ONLY",
		}),
		synthetic("accounts-array", map[string]any{
			"accounts": []any{
				map[string]any{"username": "garga-user-1", "password": "fake-password-one-ONLY"},
				map[string]any{"username": "garga-user-2", "password": "fake-password-two-ONLY"},
			},
		}),
		synthetic("env-db-block", map[string]any{
			"config": "DB_USER=garga-test\nDB_PASSWORD=fake-password-garga-test-ONLY\n",
		}),
		synthetic("docker-auth", map[string]any{
			"config": `{"auths":{"https://index.docker.io/v1/":{"auth":"Z2FyZ2E6ZmFrZS1PTkxZ"}}}`,
		}),
		synthetic("kubernetes-sa", map[string]any{
			"token": "eyJhbGciOiJub25lIn0.kubernetes.io/serviceaccount.garga-k8s-NOT-REAL",
		}),
		synthetic("high-entropy-secret", map[string]any{
			"encryption_key": "s9f8a7d6s5f4a3d2s1f0a9d8s7f6a5d4s3f2garga",
		}),
	}
}

func fakePEM(kind string) string {
	return "-----BEGIN " + kind + " PRIVATE KEY-----\nMIIEowIBAAKCAQEA0gargaTESTONLYFAKEKEY\n-----END " + kind + " PRIVATE KEY-----"
}

func fakePostgresURL() string {
	return "postgres://garga_test:" + "FakePasswordOnly" + "@localhost:5432/garga_test"
}

func fakeOAuthSecret() string {
	return "garga-test-oauth-secret-" + "NOT-REAL-0123456789"
}

func FalsePositiveDocuments() []SyntheticDocument {
	return []SyntheticDocument{
		synthetic("uuid", map[string]any{
			"note":       "SYNTHETIC FALSE-POSITIVE FIXTURE",
			"request_id": "550e8400-e29b-41d4-a716-446655440000",
		}),
		synthetic("sha256", map[string]any{
			"note":     "SYNTHETIC FALSE-POSITIVE FIXTURE",
			"checksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		}),
		synthetic("document-id", map[string]any{
			"note": "SYNTHETIC FALSE-POSITIVE FIXTURE",
			"id":   "a1b2c3d4e5f6789012345678abcdef01",
		}),
		synthetic("public-cert", map[string]any{
			"note":        "SYNTHETIC FALSE-POSITIVE FIXTURE",
			"certificate": "-----BEGIN CERTIFICATE-----\nMIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL\n-----END CERTIFICATE-----",
		}),
		synthetic("public-key", map[string]any{
			"note":       "SYNTHETIC FALSE-POSITIVE FIXTURE",
			"username":   "garga-test-user",
			"public_key": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMFAKE\n-----END PUBLIC KEY-----",
		}),
		synthetic("monkey", map[string]any{
			"note":   "SYNTHETIC FALSE-POSITIVE FIXTURE",
			"animal": "monkey",
			"trace":  "log-identifier-abc-not-a-secret",
		}),
	}
}

// Generate writes synthetic test documents to the dedicated local test index.
func Generate(ctx context.Context, endpoint model.Endpoint, secret *credential.Secret, options Options, userAgent string) (int, error) {
	options = options.withDefaults()
	if !validIndexName(TestIndex) {
		return 0, fmt.Errorf("synthetic index name is invalid")
	}
	writer, err := newWriteClient(endpoint, secret, options, userAgent)
	if err != nil {
		return 0, err
	}
	defer writer.http.CloseIdleConnections()
	count := 0
	for _, document := range append(SyntheticDocuments(), FalsePositiveDocuments()...) {
		if ctx.Err() != nil {
			return count, ctx.Err()
		}
		body, err := json.Marshal(document.Source)
		if err != nil {
			return count, err
		}
		path := "/" + url.PathEscape(TestIndex) + "/_doc/" + url.PathEscape(document.ID)
		if err := writer.putJSON(ctx, path, body); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

type writeClient struct {
	http      *http.Client
	endpoint  model.Endpoint
	secret    *credential.Secret
	limiter   *ratelimit.Limiter
	userAgent string
}

func newWriteClient(endpoint model.Endpoint, secret *credential.Secret, options Options, userAgent string) (*writeClient, error) {
	if _, err := endpoint.URL(); err != nil {
		return nil, err
	}
	if secret != nil && endpoint.Scheme != model.SchemeHTTPS && !options.AllowPlaintextAuth {
		return nil, fmt.Errorf("refusing to send credentials over HTTP; use https or --allow-plaintext-auth")
	}
	tlsConf, err := tlsConfig(options)
	if err != nil {
		return nil, err
	}
	limiter, err := ratelimit.New(options.RateLimit, options.RateLimit)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = "garga/dev"
	}
	return &writeClient{
		http: &http.Client{
			Timeout: options.RequestTimeout,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: options.RequestTimeout,
				TLSClientConfig:       tlsConf,
			},
		},
		endpoint:  endpoint,
		secret:    secret,
		limiter:   limiter,
		userAgent: userAgent,
	}, nil
}

func (client *writeClient) putJSON(ctx context.Context, path string, body []byte) error {
	if !strings.HasPrefix(path, "/"+TestIndex+"/") {
		return fmt.Errorf("generator may only write to %s", TestIndex)
	}
	base, err := client.endpoint.URL()
	if err != nil {
		return err
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return err
	}
	parsed.Path = strings.TrimSuffix(parsed.EscapedPath(), "/") + path
	parsed.RawQuery = ""
	if err := client.limiter.Wait(ctx, client.endpoint.Host); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", client.userAgent)
	if client.secret != nil {
		header, headerErr := client.secret.AuthorizationHeader()
		if headerErr != nil {
			return headerErr
		}
		request.Header.Set("Authorization", header)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("PUT %s returned HTTP %d", path, response.StatusCode)
	}
	return nil
}
