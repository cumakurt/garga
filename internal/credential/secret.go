package credential

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	maxUsernameBytes = 256
	maxSecretBytes   = 4096
	redacted         = "[redacted]"
)

// Kind identifies one explicit authentication mechanism.
type Kind string

const (
	KindBasic  Kind = "basic"
	KindAPIKey Kind = "api_key"
	KindBearer Kind = "bearer"
)

// Secret holds one explicit credential and never formats its raw value.
type Secret struct {
	kind     Kind
	username string
	secret   []byte
	header   string
}

// NewBasic creates a Basic Auth secret. The username is identity, not a password.
func NewBasic(username string, password []byte) (*Secret, error) {
	username = strings.TrimSpace(username)
	if err := validateUsername(username); err != nil {
		zero(password)
		return nil, err
	}
	if err := validateSecret(password); err != nil {
		zero(password)
		return nil, err
	}
	cloned := bytes.Clone(password)
	zero(password)
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+string(cloned)))
	return &Secret{kind: KindBasic, username: username, secret: cloned, header: header}, nil
}

// NewAPIKey creates an API key secret. id:key material is encoded; other values are sent as-is.
func NewAPIKey(apiKey []byte) (*Secret, error) {
	if err := validateSecret(apiKey); err != nil {
		zero(apiKey)
		return nil, err
	}
	cloned := bytes.Clone(apiKey)
	zero(apiKey)
	encoded := string(cloned)
	if strings.Contains(encoded, ":") {
		encoded = base64.StdEncoding.EncodeToString(cloned)
	}
	return &Secret{kind: KindAPIKey, secret: cloned, header: "ApiKey " + encoded}, nil
}

// NewBearer creates a Bearer token credential for an explicitly authenticated request.
func NewBearer(token []byte) (*Secret, error) {
	if err := validateSecret(token); err != nil {
		zero(token)
		return nil, err
	}
	cloned := bytes.Clone(token)
	zero(token)
	return &Secret{kind: KindBearer, secret: cloned, header: "Bearer " + string(cloned)}, nil
}

func (secret *Secret) Kind() Kind {
	if secret == nil {
		return ""
	}
	return secret.kind
}

// Username returns the Basic Auth identity. It is not a secret and is empty for API keys.
func (secret *Secret) Username() string {
	if secret == nil || secret.kind != KindBasic {
		return ""
	}
	return secret.username
}

// AuthorizationHeader returns the HTTP Authorization value.
func (secret *Secret) AuthorizationHeader() (string, error) {
	if secret == nil || secret.header == "" {
		return "", fmt.Errorf("credential is not initialized")
	}
	return secret.header, nil
}

// Destroy overwrites secret material. The value must not be used afterward.
func (secret *Secret) Destroy() {
	if secret == nil {
		return
	}
	zero(secret.secret)
	secret.secret = nil
	secret.header = ""
	secret.username = ""
}

func (secret *Secret) String() string {
	return secret.redactedIdentity()
}

func (secret *Secret) GoString() string {
	return secret.redactedIdentity()
}

func (secret *Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(secret.redactedIdentity())
}

func (secret *Secret) redactedIdentity() string {
	if secret == nil {
		return "credential:" + redacted
	}
	switch secret.kind {
	case KindBasic:
		return "credential:basic"
	case KindAPIKey:
		return "credential:api_key"
	case KindBearer:
		return "credential:bearer"
	default:
		return "credential:" + redacted
	}
}

func (secret *Secret) tokens() []string {
	if secret == nil {
		return nil
	}
	tokens := make([]string, 0, 3)
	if len(secret.secret) > 0 {
		tokens = append(tokens, string(secret.secret))
	}
	if secret.header != "" {
		tokens = append(tokens, secret.header)
		if _, value, found := strings.Cut(secret.header, " "); found && value != "" {
			tokens = append(tokens, value)
		}
	}
	return tokens
}

func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("basic auth username is required")
	}
	if len(username) > maxUsernameBytes || !utf8.ValidString(username) {
		return fmt.Errorf("basic auth username is invalid")
	}
	if strings.Contains(username, ":") {
		return fmt.Errorf("basic auth username must not contain a colon")
	}
	for _, character := range username {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("basic auth username is invalid")
		}
	}
	return nil
}

func validateSecret(value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("credential secret is required")
	}
	if len(value) > maxSecretBytes {
		return fmt.Errorf("credential secret exceeds %d bytes", maxSecretBytes)
	}
	if !utf8.Valid(value) {
		return fmt.Errorf("credential secret is invalid")
	}
	for _, character := range string(value) {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("credential secret is invalid")
		}
	}
	return nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
