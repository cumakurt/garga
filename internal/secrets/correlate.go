package secrets

import (
	"net/url"
	"strings"
)

const maxPairsPerScope = 16

type scopedField struct {
	Path       string
	Name       string
	ObjectPath string
	Value      string
	Role       FieldRole
	Semantics  FieldSemantics
}

type pairSpec struct {
	lefts          []FieldRole
	rights         []FieldRole
	credentialType string
	category       string
	severity       Severity
	reason         string
}

var pairSpecs = []pairSpec{
	{
		lefts: []FieldRole{RoleDBUser}, rights: []FieldRole{RoleDBPassword, RolePassword},
		credentialType: "database_credentials", category: "credential.database",
		severity: SeverityCritical,
		reason:   "Database user and password detected within the same object",
	},
	{
		lefts: []FieldRole{RoleSMTPUser}, rights: []FieldRole{RoleSMTPPassword, RolePassword},
		credentialType: "smtp_credentials", category: "credential.smtp",
		severity: SeverityCritical,
		reason:   "SMTP user and password detected within the same object",
	},
	{
		lefts: []FieldRole{RoleLDAPUser}, rights: []FieldRole{RoleLDAPPassword, RolePassword},
		credentialType: "ldap_credentials", category: "credential.ldap",
		severity: SeverityCritical,
		reason:   "LDAP user and password detected within the same object",
	},
	{
		lefts: identityFamily(), rights: passwordFamily(),
		credentialType: "username_password", category: "credential.pair",
		severity: SeverityCritical,
		reason:   "Username and password fields detected within the same object",
	},
	{
		lefts: clientIDFamily(), rights: clientSecretFamily(),
		credentialType: "client_credentials", category: "credential.client",
		severity: SeverityCritical,
		reason:   "Client identifier and client secret detected within the same object",
	},
	{
		lefts: []FieldRole{RoleAccessKey}, rights: []FieldRole{RoleSecretKey},
		credentialType: "access_key_pair", category: "credential.access_key_pair",
		severity: SeverityCritical,
		reason:   "Access key and secret key detected within the same object",
	},
	{
		lefts: []FieldRole{RoleAPIKey}, rights: []FieldRole{RoleAPISecret, RoleSecret},
		credentialType: "api_credentials", category: "credential.api_pair",
		severity: SeverityCritical,
		reason:   "API key and API secret detected within the same object",
	},
	{
		lefts: []FieldRole{RoleKey}, rights: []FieldRole{RoleSecret},
		credentialType: "key_secret", category: "credential.pair",
		severity: SeverityCritical,
		reason:   "Key and secret fields detected within the same object",
	},
	{
		lefts: identityFamily(), rights: []FieldRole{RoleToken, RoleAccessToken, RoleAPIKey},
		credentialType: "username_token", category: "credential.token_pair",
		severity: SeverityHigh,
		reason:   "Username and token fields detected within the same object",
	},
	{
		lefts: clientIDFamily(), rights: []FieldRole{RoleToken, RoleAccessToken},
		credentialType: "client_token", category: "credential.token_pair",
		severity: SeverityHigh,
		reason:   "Client identifier and token detected within the same object",
	},
	{
		lefts: []FieldRole{RoleAccessToken}, rights: []FieldRole{RoleRefreshToken},
		credentialType: "token_pair", category: "credential.token_pair",
		severity: SeverityCritical,
		reason:   "Access token and refresh token detected within the same object",
	},
}

// CorrelateScope finds credential pairs among sibling fields of one object.
// It does not look at other documents, other array elements, or parent objects.
func CorrelateScope(fields []scopedField, objectPath string, broad bool) []hit {
	if len(fields) < 2 {
		return nil
	}
	classified := make([]scopedField, 0, len(fields))
	buckets := make(map[FieldRole][]int, 8)
	for _, field := range fields {
		if strings.TrimSpace(field.Value) == "" {
			continue
		}
		field.Role = ClassifyFieldRole(field.Path, broad)
		if field.Role == RoleNone || field.Role == RolePublic || field.Role == RoleHash {
			continue
		}
		field.Semantics = AnalyzeField(field.Path)
		index := len(classified)
		classified = append(classified, field)
		buckets[field.Role] = append(buckets[field.Role], index)
	}
	if len(classified) < 2 {
		return nil
	}

	var hits []hit
	seen := make(map[string]struct{}, 8)
	for _, spec := range pairSpecs {
		if len(hits) >= maxPairsPerScope {
			break
		}
		lefts := collectBucket(classified, buckets, spec.lefts)
		rights := collectBucket(classified, buckets, spec.rights)
		if len(lefts) == 0 || len(rights) == 0 {
			continue
		}
		for _, left := range lefts {
			for _, right := range rights {
				if left.Path == right.Path {
					continue
				}
				confidence, ok := pairConfidence(left, right, spec)
				if !ok {
					continue
				}
				key := left.Path + "\x00" + right.Path
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				hits = append(hits, newPairHit(objectPath, left, right, spec, confidence))
				if len(hits) >= maxPairsPerScope {
					return hits
				}
				break
			}
		}
	}
	return hits
}

func collectBucket(fields []scopedField, buckets map[FieldRole][]int, roles []FieldRole) []scopedField {
	var out []scopedField
	seen := make(map[int]struct{}, len(roles))
	for _, role := range roles {
		for _, index := range buckets[role] {
			if _, exists := seen[index]; exists {
				continue
			}
			seen[index] = struct{}{}
			out = append(out, fields[index])
		}
	}
	return out
}

func pairConfidence(left, right scopedField, spec pairSpec) (Confidence, bool) {
	if looksLikePublicMaterial(left.Value) || looksLikePublicMaterial(right.Value) {
		return "", false
	}
	if !looksLikeIdentityValue(left.Value) || !looksLikeSecretValue(right.Value) {
		return "", false
	}
	if spec.credentialType == "key_secret" && !highEntropySecret(right.Value) && !looksLikeKnownSecretFormat(right.Value) {
		return "", false
	}
	if spec.credentialType == "username_token" && !looksLikeSecretValue(right.Value) {
		return "", false
	}
	if looksLikeKnownSecretFormat(right.Value) || (spec.credentialType == "access_key_pair" && strings.HasPrefix(strings.TrimSpace(left.Value), "AKIA")) {
		return ConfidenceConfirmed, true
	}
	if highEntropySecret(right.Value) || right.Semantics.Sensitive {
		return ConfidenceHigh, true
	}
	if spec.severity == SeverityCritical && looksLikeSecretValue(right.Value) {
		return ConfidenceHigh, true
	}
	return ConfidenceMedium, true
}

func looksLikeIdentityValue(value string) bool {
	return strings.TrimSpace(value) != ""
}

func looksLikeSecretValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 4 {
		return false
	}
	if looksLikeUUID(trimmed) || looksLikePublicMaterial(trimmed) {
		return false
	}
	return classifyPasswordHash(trimmed) == ""
}

func looksLikeKnownSecretFormat(value string) bool {
	hits := detectKnownPatterns(value, FieldSemantics{})
	for _, item := range hits {
		if strings.HasPrefix(item.Category, "credential.") {
			return true
		}
	}
	return false
}

func newPairHit(objectPath string, left, right scopedField, spec pairSpec, confidence Confidence) hit {
	credentialType := spec.credentialType
	switch {
	case left.Role == RoleDBUser || right.Role == RoleDBPassword:
		credentialType = "database_credentials"
		spec.category = "credential.database"
	case left.Role == RoleSMTPUser || right.Role == RoleSMTPPassword:
		credentialType = "smtp_credentials"
		spec.category = "credential.smtp"
	case left.Role == RoleLDAPUser || right.Role == RoleLDAPPassword:
		credentialType = "ldap_credentials"
		spec.category = "credential.ldap"
	}
	leftLabel := rolePreviewLabel(left.Role)
	rightLabel := rolePreviewLabel(right.Role)
	masked := map[string]string{
		leftLabel:  Mask(left.Value),
		rightLabel: Mask(right.Value),
	}
	fieldPath := objectPath
	if fieldPath == "" {
		fieldPath = left.Path
	}
	return hit{
		Category:       spec.category,
		Detector:       "credential-pair",
		Severity:       spec.severity,
		Confidence:     confidence,
		Reason:         spec.reason,
		Masked:         leftLabel + "=" + masked[leftLabel] + " " + rightLabel + "=" + masked[rightLabel],
		Suppress:       true,
		FieldPath:      fieldPath,
		ObjectPath:     objectPath,
		RelatedFields:  []string{left.Path, right.Path},
		CredentialType: credentialType,
		MaskedValues:   masked,
	}
}

func rolePreviewLabel(role FieldRole) string {
	switch role {
	case RolePassword, RoleDBPassword, RoleSMTPPassword, RoleLDAPPassword, RoleSecret, RoleClientSecret, RoleAPISecret, RoleSecretKey, RoleConsumerSecret, RoleOAuthClientSecret:
		return "password"
	case RoleClientID, RoleOAuthClientID, RoleConsumerKey:
		return "client_id"
	case RoleAccessKey:
		return "access_key"
	case RoleAPIKey:
		return "api_key"
	case RoleToken, RoleAccessToken, RoleRefreshToken:
		return "token"
	default:
		return "username"
	}
}

func correlateTextBlock(value, path string, broad bool) []hit {
	if !strings.Contains(value, "\n") || (!strings.Contains(value, "=") && !strings.ContainsAny(value, ":")) {
		return nil
	}
	fields := parseAssignmentFields(value, path)
	return CorrelateScope(fields, path, broad)
}

const maxAssignmentFields = 256

func parseAssignmentFields(value, path string) []scopedField {
	var fields []scopedField
	for _, line := range strings.Split(value, "\n") {
		if len(fields) >= maxAssignmentFields {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "export ") {
			line = strings.TrimSpace(line[7:])
		}
		separator := strings.IndexAny(line, ":=")
		if separator <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:separator])
		raw := strings.Trim(strings.TrimSpace(line[separator+1:]), `"'`)
		if name == "" || raw == "" {
			continue
		}
		if strings.ContainsAny(name, " \t{}[]") {
			continue
		}
		fields = append(fields, scopedField{
			Path:       joinPath(path, name),
			Name:       name,
			ObjectPath: path,
			Value:      raw,
		})
	}
	return fields
}

func enrichConnectionString(item hit, raw string) hit {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || parsed.User == nil {
		return item
	}
	username := parsed.User.Username()
	password, hasPassword := parsed.User.Password()
	if !hasPassword || password == "" {
		return item
	}
	item.CredentialType = "connection_string"
	item.RelatedFields = []string{item.FieldPath}
	item.MaskedValues = map[string]string{
		"scheme":   parsed.Scheme,
		"username": Mask(username),
		"password": Mask(password),
		"host":     parsed.Host,
	}
	item.Reason = "Connection string with embedded username and password"
	return item
}

func enrichAuthorizationHeader(item hit, scheme string) hit {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	switch scheme {
	case "basic":
		item.Category = "credential.http.basic"
		item.CredentialType = "http_basic"
	case "bearer":
		item.Category = "credential.http.bearer"
		item.CredentialType = "http_bearer"
	}
	item.MaskedValues = map[string]string{"scheme": scheme, "credential": item.Masked}
	return item
}
