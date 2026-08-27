package audit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/cumakurt/garga/internal/credential"
)

// ParseCredentials reads an explicit credential list. Secrets are not taken from argv.
//
// Supported lines:
//
//	basic USERNAME PASSWORD
//	api_key KEY
//
// The password is the remainder of the line after the username, so it may contain spaces.
// Blank lines and `#` comments are ignored. The list is fully parsed before any request.
func ParseCredentials(reader io.Reader) ([]*credential.Secret, error) {
	if reader == nil {
		return nil, fmt.Errorf("parse credential list: input is required")
	}

	limited := io.LimitReader(reader, int64(maxListBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("parse credential list: read input")
	}
	if len(data) > maxListBytes {
		zero(data)
		return nil, fmt.Errorf("parse credential list: input exceeds %d bytes", maxListBytes)
	}

	secrets := make([]*credential.Secret, 0, 4)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64), maxLineBytes+1)
	defer zero(data)

	for scanner.Scan() {
		line := scanner.Bytes()
		secret, skip, parseErr := parseCredentialLine(line)
		zero(line)
		if parseErr != nil {
			destroySecrets(secrets)
			return nil, parseErr
		}
		if skip {
			continue
		}
		if len(secrets) >= maxCredentials {
			destroySecrets(secrets)
			secret.Destroy()
			return nil, fmt.Errorf("parse credential list: at most %d credentials are allowed", maxCredentials)
		}
		secrets = append(secrets, secret)
	}
	if err := scanner.Err(); err != nil {
		destroySecrets(secrets)
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("parse credential list: line exceeds %d bytes", maxLineBytes)
		}
		return nil, fmt.Errorf("parse credential list: read input")
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("parse credential list: at least one credential is required")
	}
	return secrets, nil
}

func parseCredentialLine(line []byte) (*credential.Secret, bool, error) {
	if !utf8.Valid(line) {
		return nil, false, fmt.Errorf("parse credential list: line is not valid UTF-8")
	}
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, true, nil
	}
	kind, rest, ok := cutField(trimmed)
	if !ok {
		return nil, false, fmt.Errorf("parse credential list: credential line is invalid")
	}
	switch kind {
	case "basic":
		username, password, ok := cutField(rest)
		if !ok || password == "" {
			return nil, false, fmt.Errorf("parse credential list: basic credential requires a username and password")
		}
		secret, err := credential.NewBasic(username, []byte(password))
		if err != nil {
			return nil, false, fmt.Errorf("parse credential list: invalid basic credential")
		}
		return secret, false, nil
	case "api_key":
		if rest == "" {
			return nil, false, fmt.Errorf("parse credential list: API key is required")
		}
		secret, err := credential.NewAPIKey([]byte(rest))
		if err != nil {
			return nil, false, fmt.Errorf("parse credential list: invalid API key")
		}
		return secret, false, nil
	default:
		return nil, false, fmt.Errorf("parse credential list: credential kind is not supported")
	}
}

func cutField(value string) (string, string, bool) {
	value = strings.TrimLeft(value, " \t")
	if value == "" {
		return "", "", false
	}
	index := strings.IndexAny(value, " \t")
	if index < 0 {
		return value, "", true
	}
	return value[:index], strings.TrimLeft(value[index+1:], " \t"), true
}

func destroySecrets(secrets []*credential.Secret) {
	for _, secret := range secrets {
		secret.Destroy()
	}
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
