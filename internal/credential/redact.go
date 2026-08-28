package credential

import "strings"

// Redact removes known secret material from text.
//
// Tokens shorter than 4 bytes are replaced only when the entire text equals the
// token. Substring replacement of single-character charset candidates would
// destroy reports and status lines.
func Redact(text string, secret *Secret) string {
	if secret == nil || text == "" {
		return text
	}
	for _, token := range secret.tokens() {
		if token == "" {
			continue
		}
		if len(token) < minRedactTokenBytes && text != token {
			continue
		}
		text = strings.ReplaceAll(text, token, redacted)
	}
	return text
}

func redactError(err error, secret *Secret) error {
	if err == nil {
		return nil
	}
	message := Redact(err.Error(), secret)
	if message == err.Error() {
		return err
	}
	return redactedError{message: message, cause: err}
}

type redactedError struct {
	message string
	cause   error
}

func (err redactedError) Error() string { return err.message }

func (err redactedError) Unwrap() error { return err.cause }
