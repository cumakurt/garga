package secrets

import (
	"strings"
	"unicode"
)

// FieldSemantics describes mapping/document field intent after name analysis.
type FieldSemantics struct {
	Path       string
	Name       string
	Normalized string
	Tokens     []string
	ESType     string
	Severity   Severity
	Category   string
	Sensitive  bool
	HashHint   bool
	IDLike     bool
	TextLike   bool
}

type fieldRule struct {
	tokens   []string
	joined   string
	severity Severity
	category string
	hashHint bool
}

var criticalFieldRules = []fieldRule{
	{tokens: []string{"password"}, severity: SeverityCritical, category: "credential.password"},
	{tokens: []string{"passwd"}, severity: SeverityCritical, category: "credential.password"},
	{tokens: []string{"pwd"}, severity: SeverityCritical, category: "credential.password"},
	{tokens: []string{"pass"}, severity: SeverityCritical, category: "credential.password"},
	{tokens: []string{"client", "secret"}, severity: SeverityCritical, category: "credential.oauth"},
	{tokens: []string{"api", "key"}, severity: SeverityCritical, category: "credential.api_key"},
	{tokens: []string{"apikey"}, severity: SeverityCritical, category: "credential.api_key"},
	{tokens: []string{"access", "key"}, severity: SeverityCritical, category: "credential.cloud"},
	{tokens: []string{"secret", "key"}, severity: SeverityCritical, category: "credential.cloud"},
	{tokens: []string{"secret", "access", "key"}, severity: SeverityCritical, category: "credential.cloud"},
	{tokens: []string{"private", "key"}, severity: SeverityCritical, category: "credential.private_key"},
	{tokens: []string{"ssh", "key"}, severity: SeverityCritical, category: "credential.private_key"},
	{tokens: []string{"encryption", "key"}, severity: SeverityCritical, category: "credential.encryption_key"},
	{tokens: []string{"signing", "key"}, severity: SeverityCritical, category: "credential.signing_key"},
	{tokens: []string{"hmac", "secret"}, severity: SeverityCritical, category: "credential.hmac"},
	{tokens: []string{"webhook", "secret"}, severity: SeverityCritical, category: "credential.webhook"},
	{tokens: []string{"smtp", "password"}, severity: SeverityCritical, category: "credential.smtp"},
	{tokens: []string{"db", "password"}, severity: SeverityCritical, category: "credential.database"},
	{tokens: []string{"database", "password"}, severity: SeverityCritical, category: "credential.database"},
	{tokens: []string{"ldap", "password"}, severity: SeverityCritical, category: "credential.ldap"},
	{tokens: []string{"connection", "string"}, severity: SeverityCritical, category: "credential.connection_string"},
	{tokens: []string{"dsn"}, severity: SeverityCritical, category: "credential.connection_string"},
	{tokens: []string{"jdbc"}, severity: SeverityHigh, category: "credential.connection_string"},
}

var highFieldRules = []fieldRule{
	{tokens: []string{"access", "token"}, severity: SeverityHigh, category: "credential.access_token"},
	{tokens: []string{"refresh", "token"}, severity: SeverityHigh, category: "credential.refresh_token"},
	{tokens: []string{"bearer"}, severity: SeverityHigh, category: "credential.bearer"},
	{tokens: []string{"authorization"}, severity: SeverityHigh, category: "credential.authorization"},
	{tokens: []string{"auth"}, severity: SeverityHigh, category: "credential.authorization"},
	{tokens: []string{"token"}, severity: SeverityHigh, category: "credential.token"},
	{tokens: []string{"jwt"}, severity: SeverityHigh, category: "credential.jwt"},
	{tokens: []string{"credential"}, severity: SeverityHigh, category: "credential.generic"},
	{tokens: []string{"credentials"}, severity: SeverityHigh, category: "credential.generic"},
	{tokens: []string{"secret"}, severity: SeverityHigh, category: "credential.application_secret"},
	{tokens: []string{"session"}, severity: SeverityHigh, category: "credential.session"},
	{tokens: []string{"cookie"}, severity: SeverityHigh, category: "credential.session"},
}

var mediumFieldRules = []fieldRule{
	{tokens: []string{"username"}, severity: SeverityMedium, category: "identity.username"},
	{tokens: []string{"user"}, severity: SeverityMedium, category: "identity.username"},
	{tokens: []string{"login"}, severity: SeverityMedium, category: "identity.username"},
	{tokens: []string{"client", "id"}, severity: SeverityMedium, category: "identity.client_id"},
	{tokens: []string{"email"}, severity: SeverityLow, category: "identity.email"},
	{tokens: []string{"password", "hash"}, severity: SeverityMedium, category: "credential.password_hash", hashHint: true},
	{tokens: []string{"passwd", "hash"}, severity: SeverityMedium, category: "credential.password_hash", hashHint: true},
	{tokens: []string{"pwd", "hash"}, severity: SeverityMedium, category: "credential.password_hash", hashHint: true},
}

var idLikeTokens = map[string]struct{}{
	"id": {}, "uuid": {}, "guid": {}, "request": {}, "trace": {}, "span": {},
	"checksum": {}, "etag": {}, "hash": {}, "digest": {}, "fingerprint": {},
}

var textLikeNames = map[string]struct{}{
	"message": {}, "log": {}, "logs": {}, "body": {}, "stack": {}, "stacktrace": {},
	"config": {}, "configuration": {}, "error": {}, "headers": {}, "header": {},
	"request": {}, "response": {}, "payload": {}, "content": {}, "raw": {},
	"dump": {}, "env": {}, "environment": {},
}

func init() {
	for index := range criticalFieldRules {
		criticalFieldRules[index].joined = strings.Join(criticalFieldRules[index].tokens, "")
	}
	for index := range highFieldRules {
		highFieldRules[index].joined = strings.Join(highFieldRules[index].tokens, "")
	}
	for index := range mediumFieldRules {
		mediumFieldRules[index].joined = strings.Join(mediumFieldRules[index].tokens, "")
	}
}

// AnalyzeField scores a dotted field path using token-boundary matching.
func AnalyzeField(path string) FieldSemantics {
	name := fieldName(path)
	tokens := tokenizeField(name)
	semantics := FieldSemantics{
		Path:       path,
		Name:       name,
		Normalized: strings.Join(tokens, ""),
		Tokens:     tokens,
		Severity:   SeverityInfo,
		IDLike:     isIDLike(name, tokens),
		TextLike:   isTextLike(name, tokens),
	}
	if rule, ok := matchFieldRule(tokens, semantics.Normalized, criticalFieldRules); ok {
		return applyFieldRule(semantics, rule)
	}
	if rule, ok := matchFieldRule(tokens, semantics.Normalized, highFieldRules); ok {
		return applyFieldRule(semantics, rule)
	}
	if rule, ok := matchFieldRule(tokens, semantics.Normalized, mediumFieldRules); ok {
		return applyFieldRule(semantics, rule)
	}
	return semantics
}

func applyFieldRule(semantics FieldSemantics, rule fieldRule) FieldSemantics {
	semantics.Sensitive = true
	semantics.Severity = rule.severity
	semantics.Category = rule.category
	semantics.HashHint = rule.hashHint || semantics.HashHint
	if rule.hashHint {
		semantics.IDLike = false
	}
	return semantics
}

func matchFieldRule(tokens []string, joined string, rules []fieldRule) (fieldRule, bool) {
	for _, rule := range rules {
		if len(rule.tokens) == 1 {
			if tokenEquals(tokens, rule.tokens[0]) || joined == rule.joined {
				return rule, true
			}
			continue
		}
		if containsTokenSequence(tokens, rule.tokens) || joined == rule.joined {
			return rule, true
		}
	}
	return fieldRule{}, false
}

func tokenEquals(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}

func containsTokenSequence(tokens, want []string) bool {
	if len(want) == 0 || len(tokens) < len(want) {
		return false
	}
	for start := 0; start <= len(tokens)-len(want); start++ {
		matched := true
		for offset, item := range want {
			if tokens[start+offset] != item {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func fieldName(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	parts := strings.Split(path, ".")
	name := parts[len(parts)-1]
	if bracket := strings.IndexByte(name, '['); bracket >= 0 {
		name = name[:bracket]
	}
	return name
}

func tokenizeField(name string) []string {
	if name == "" {
		return nil
	}
	replaced := strings.NewReplacer("-", " ", "_", " ", ".", " ", "/", " ").Replace(name)
	var tokens []string
	for _, part := range strings.Fields(replaced) {
		tokens = append(tokens, splitCamel(part)...)
	}
	return tokens
}

func splitCamel(value string) []string {
	if value == "" {
		return nil
	}
	var (
		tokens  []string
		current strings.Builder
		runes   = []rune(value)
	)
	flush := func() {
		if current.Len() == 0 {
			return
		}
		tokens = append(tokens, strings.ToLower(current.String()))
		current.Reset()
	}
	for index, character := range runes {
		if unicode.IsUpper(character) && index > 0 {
			prev := runes[index-1]
			nextLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
			if unicode.IsLower(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		current.WriteRune(character)
	}
	flush()
	return tokens
}

func isIDLike(name string, tokens []string) bool {
	normalized := strings.ToLower(strings.Trim(name, "_"))
	switch normalized {
	case "id", "_id", "uuid", "guid", "request_id", "requestid", "trace_id", "traceid",
		"span_id", "spanid", "document_id", "doc_id", "checksum", "etag", "digest":
		return true
	}
	if tokenEquals(tokens, "password") || tokenEquals(tokens, "passwd") || tokenEquals(tokens, "pwd") {
		return false
	}
	if len(tokens) == 0 {
		return false
	}
	last := tokens[len(tokens)-1]
	_, known := idLikeTokens[last]
	return known
}

func isTextLike(name string, tokens []string) bool {
	if _, ok := textLikeNames[strings.ToLower(name)]; ok {
		return true
	}
	for _, token := range tokens {
		if _, ok := textLikeNames[token]; ok {
			return true
		}
	}
	return false
}

func mappingPriority(semantics FieldSemantics, generic bool) int {
	if semantics.Sensitive {
		return severityRank(semantics.Severity)
	}
	if semantics.TextLike {
		return 1
	}
	if generic && searchableESType(semantics.ESType) {
		return 1
	}
	return 0
}

func searchableESType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "text", "keyword", "wildcard", "match_only_text", "constant_keyword", "flattened", "annotated_text":
		return true
	default:
		return false
	}
}
