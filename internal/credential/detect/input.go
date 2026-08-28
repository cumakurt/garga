package detect

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	sectionUsers     = "@users"
	sectionPasswords = "@passwords"
)

// ParseStructuredSprayInput reads usernames and passwords from one stdin stream.
//
// Format:
//
//	@users
//	elastic
//	admin
//	@passwords
//	password
//	changeme
//
// Blank lines and `#` comments are ignored outside section headers.
func ParseStructuredSprayInput(reader io.Reader) ([]string, [][]byte, error) {
	if reader == nil {
		return nil, nil, fmt.Errorf("parse spray input: input is required")
	}
	maxBytes := maxUsersListBytes + maxPasswordsBytes
	limited := io.LimitReader(reader, int64(maxBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, fmt.Errorf("parse spray input: read input")
	}
	if len(data) > maxBytes {
		zero(data)
		return nil, nil, fmt.Errorf("parse spray input: input exceeds %d bytes", maxBytes)
	}
	defer zero(data)

	section := ""
	users := make([]string, 0, 4)
	passwords := make([][]byte, 0, 4)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64), maxLineBytes+1)

	for scanner.Scan() {
		line := scanner.Bytes()
		if !utf8.Valid(line) {
			return nil, nil, fmt.Errorf("parse spray input: line is not valid UTF-8")
		}
		trimmed := strings.TrimSpace(string(line))
		zero(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		switch trimmed {
		case sectionUsers:
			section = sectionUsers
			continue
		case sectionPasswords:
			section = sectionPasswords
			continue
		}
		switch section {
		case sectionUsers:
			if len(users) >= maxUsers {
				return nil, nil, fmt.Errorf("parse spray input: at most %d usernames are allowed", maxUsers)
			}
			users = append(users, trimmed)
		case sectionPasswords:
			if len(passwords) >= maxPasswords {
				return nil, nil, fmt.Errorf("parse spray input: at most %d passwords are allowed", maxPasswords)
			}
			passwords = append(passwords, []byte(trimmed))
		default:
			return nil, nil, fmt.Errorf("parse spray input: input must start with %s", sectionUsers)
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, nil, fmt.Errorf("parse spray input: line exceeds %d bytes", maxLineBytes)
		}
		return nil, nil, fmt.Errorf("parse spray input: read input")
	}
	if len(users) == 0 {
		return nil, nil, fmt.Errorf("parse spray input: at least one username is required")
	}
	if len(passwords) == 0 {
		return nil, nil, fmt.Errorf("parse spray input: at least one password is required")
	}
	return users, passwords, nil
}
