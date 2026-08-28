package secrets

import (
	"strings"
)

type hashKind struct {
	prefix string
	name   string
}

var passwordHashKinds = []hashKind{
	{prefix: "$2a$", name: "bcrypt"},
	{prefix: "$2b$", name: "bcrypt"},
	{prefix: "$2y$", name: "bcrypt"},
	{prefix: "$argon2id$", name: "argon2id"},
	{prefix: "$argon2i$", name: "argon2i"},
	{prefix: "$argon2d$", name: "argon2d"},
	{prefix: "$pbkdf2", name: "pbkdf2"},
	{prefix: "$scrypt$", name: "scrypt"},
	{prefix: "$5$", name: "sha256crypt"},
	{prefix: "$6$", name: "sha512crypt"},
	{prefix: "$1$", name: "md5crypt"},
	{prefix: "$md5$", name: "md5crypt"},
}

func classifyPasswordHash(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	for _, kind := range passwordHashKinds {
		if strings.HasPrefix(trimmed, kind.prefix) && len(trimmed) >= len(kind.prefix)+8 {
			return kind.name
		}
	}
	return ""
}

func looksLikeNTLM(value string) bool {
	if len(value) != 32 {
		return false
	}
	return looksLikeHex(value)
}

func detectPasswordHash(value string, semantics FieldSemantics) []hit {
	kind := classifyPasswordHash(value)
	if kind == "" {
		if semantics.HashHint && looksLikeNTLM(value) {
			kind = "ntlm"
		} else if semantics.HashHint && looksLikeHex(value) && (len(value) == 40 || len(value) == 64 || len(value) == 128) {
			switch len(value) {
			case 40:
				kind = "sha1"
			case 64:
				kind = "sha256"
			case 128:
				kind = "sha512"
			}
		} else {
			return nil
		}
	} else if !semantics.HashHint && !semantics.Sensitive && !passwordContext(semantics) {
		return nil
	}
	return []hit{{
		Category:   "credential.password_hash",
		Detector:   "password-hash",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Reason:     "Password hash detected (" + kind + ")",
		Masked:     passwordHashPreview + " (" + kind + ")",
		Suppress:   true,
	}}
}

func passwordContext(semantics FieldSemantics) bool {
	if semantics.HashHint {
		return true
	}
	return tokenEquals(semantics.Tokens, "password") || tokenEquals(semantics.Tokens, "passwd") ||
		tokenEquals(semantics.Tokens, "pwd") || tokenEquals(semantics.Tokens, "pass") ||
		tokenEquals(semantics.Tokens, "hash") && semantics.Sensitive
}
