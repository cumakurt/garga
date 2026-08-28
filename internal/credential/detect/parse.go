package detect

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

// ParseUsers reads one username per line from stdin.
func ParseUsers(reader io.Reader) ([]string, error) {
	return parseLines(reader, maxUsersListBytes, maxUsers, "username", func(line string) (string, bool, error) {
		username := strings.TrimSpace(line)
		if username == "" {
			return "", false, fmt.Errorf("parse username list: username is required")
		}
		return username, true, nil
	})
}

// ParsePasswords reads one password per line from stdin. The password is the remainder of the line.
func ParsePasswords(reader io.Reader) ([][]byte, error) {
	lines, err := parseLines(reader, maxPasswordsBytes, maxPasswords, "password", func(line string) (string, bool, error) {
		password := strings.TrimSpace(line)
		if password == "" {
			return "", false, fmt.Errorf("parse password list: password is required")
		}
		return password, true, nil
	})
	if err != nil {
		return nil, err
	}
	passwords := make([][]byte, 0, len(lines))
	for _, line := range lines {
		passwords = append(passwords, []byte(line))
	}
	return passwords, nil
}

// ParsePairs reads explicit username+password pairs for credential stuffing.
//
// Supported lines:
//
//	basic USERNAME PASSWORD
//
// Blank lines and `#` comments are ignored.
func ParsePairs(reader io.Reader) ([]*credential.Secret, error) {
	if reader == nil {
		return nil, fmt.Errorf("parse credential pair list: input is required")
	}

	limited := io.LimitReader(reader, int64(maxPairsListBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("parse credential pair list: read input")
	}
	if len(data) > maxPairsListBytes {
		zero(data)
		return nil, fmt.Errorf("parse credential pair list: input exceeds %d bytes", maxPairsListBytes)
	}

	secrets := make([]*credential.Secret, 0, 4)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64), maxLineBytes+1)
	defer zero(data)

	for scanner.Scan() {
		line := scanner.Bytes()
		secret, skip, parseErr := parsePairLine(line)
		zero(line)
		if parseErr != nil {
			destroySecrets(secrets)
			return nil, parseErr
		}
		if skip {
			continue
		}
		if len(secrets) >= maxPairs {
			destroySecrets(secrets)
			secret.Destroy()
			return nil, fmt.Errorf("parse credential pair list: at most %d pairs are allowed", maxPairs)
		}
		secrets = append(secrets, secret)
	}
	if err := scanner.Err(); err != nil {
		destroySecrets(secrets)
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("parse credential pair list: line exceeds %d bytes", maxLineBytes)
		}
		return nil, fmt.Errorf("parse credential pair list: read input")
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("parse credential pair list: at least one credential pair is required")
	}
	return secrets, nil
}

func parsePairLine(line []byte) (*credential.Secret, bool, error) {
	if !utf8.Valid(line) {
		return nil, false, fmt.Errorf("parse credential pair list: line is not valid UTF-8")
	}
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, true, nil
	}
	username, password, err := splitPair(trimmed)
	if err != nil {
		return nil, false, err
	}
	secret, secretErr := credential.NewBasic(username, []byte(password))
	if secretErr != nil {
		return nil, false, fmt.Errorf("parse credential pair list: invalid basic credential")
	}
	return secret, false, nil
}

// splitPair accepts leak-style dumps and the explicit basic form:
//
//	basic USERNAME PASSWORD
//	USERNAME:PASSWORD
//	USERNAME,PASSWORD
//	USERNAME PASSWORD
func splitPair(trimmed string) (string, string, error) {
	kind, rest, ok := cutField(trimmed)
	if ok {
		switch kind {
		case "api_key", "bearer":
			return "", "", fmt.Errorf("parse credential pair list: only basic credential pairs are supported")
		case "basic":
			username, password, cutOK := cutField(rest)
			if !cutOK || password == "" {
				return "", "", fmt.Errorf("parse credential pair list: basic credential requires a username and password")
			}
			return username, password, nil
		}
	}
	if username, password, cutOK := strings.Cut(trimmed, ":"); cutOK {
		username = strings.TrimSpace(username)
		password = strings.TrimSpace(password)
		if username != "" && password != "" {
			return username, password, nil
		}
	}
	if username, password, cutOK := strings.Cut(trimmed, ","); cutOK {
		username = strings.TrimSpace(username)
		password = strings.TrimSpace(password)
		if username != "" && password != "" {
			return username, password, nil
		}
	}
	username, password, ok := cutField(trimmed)
	if ok && password != "" {
		return username, password, nil
	}
	return "", "", fmt.Errorf("parse credential pair list: credential line is invalid")
}

func parseLines[T any](
	reader io.Reader,
	maxBytes int,
	maxItems int,
	itemName string,
	parse func(string) (T, bool, error),
) ([]T, error) {
	if reader == nil {
		return nil, fmt.Errorf("parse %s list: input is required", itemName)
	}
	limited := io.LimitReader(reader, int64(maxBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("parse %s list: read input", itemName)
	}
	if len(data) > maxBytes {
		zero(data)
		return nil, fmt.Errorf("parse %s list: input exceeds %d bytes", itemName, maxBytes)
	}

	items := make([]T, 0, 4)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64), maxLineBytes+1)
	defer zero(data)

	for scanner.Scan() {
		line := scanner.Bytes()
		if !utf8.Valid(line) {
			return nil, fmt.Errorf("parse %s list: line is not valid UTF-8", itemName)
		}
		trimmed := strings.TrimSpace(string(line))
		zero(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		item, keep, parseErr := parse(trimmed)
		if parseErr != nil {
			return nil, parseErr
		}
		if !keep {
			continue
		}
		if len(items) >= maxItems {
			return nil, fmt.Errorf("parse %s list: at most %d entries are allowed", itemName, maxItems)
		}
		items = append(items, item)
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("parse %s list: line exceeds %d bytes", itemName, maxLineBytes)
		}
		return nil, fmt.Errorf("parse %s list: read input", itemName)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("parse %s list: at least one entry is required", itemName)
	}
	return items, nil
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
