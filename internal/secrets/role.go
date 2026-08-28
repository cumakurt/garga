package secrets

import "strings"

// FieldRole is a semantic bucket used by the correlation engine.
type FieldRole string

const (
	RoleNone              FieldRole = ""
	RoleIdentity          FieldRole = "identity"
	RolePassword          FieldRole = "password"
	RoleClientID          FieldRole = "client_id"
	RoleClientSecret      FieldRole = "client_secret"
	RoleAccessKey         FieldRole = "access_key"
	RoleSecretKey         FieldRole = "secret_key"
	RoleAPIKey            FieldRole = "api_key"
	RoleAPISecret         FieldRole = "api_secret"
	RoleKey               FieldRole = "key"
	RoleSecret            FieldRole = "secret"
	RoleConsumerKey       FieldRole = "consumer_key"
	RoleConsumerSecret    FieldRole = "consumer_secret"
	RoleOAuthClientID     FieldRole = "oauth_client_id"
	RoleOAuthClientSecret FieldRole = "oauth_client_secret" //nolint:gosec // Semantic field-role name, not a credential.
	RoleDBUser            FieldRole = "database_user"
	RoleDBPassword        FieldRole = "database_password"
	RoleSMTPUser          FieldRole = "smtp_user"
	RoleSMTPPassword      FieldRole = "smtp_password"
	RoleLDAPUser          FieldRole = "ldap_user"
	RoleLDAPPassword      FieldRole = "ldap_password"
	RoleToken             FieldRole = "token"
	RoleAccessToken       FieldRole = "access_token"
	RoleRefreshToken      FieldRole = "refresh_token"
	RoleHash              FieldRole = "hash"
	RolePublic            FieldRole = "public"
)

type roleRule struct {
	tokens   []string
	role     FieldRole
	deepOnly bool
}

// Central alias list. Longer token sequences are matched first.
var roleRules = []roleRule{
	{tokens: []string{"aws", "secret", "access", "key"}, role: RoleSecretKey},
	{tokens: []string{"aws", "access", "key", "id"}, role: RoleAccessKey},
	{tokens: []string{"secret", "access", "key"}, role: RoleSecretKey},
	{tokens: []string{"oauth", "client", "secret"}, role: RoleOAuthClientSecret},
	{tokens: []string{"oauth", "client", "id"}, role: RoleOAuthClientID},
	{tokens: []string{"consumer", "secret"}, role: RoleConsumerSecret},
	{tokens: []string{"consumer", "key"}, role: RoleConsumerKey},
	{tokens: []string{"client", "secret"}, role: RoleClientSecret},
	{tokens: []string{"client", "id"}, role: RoleClientID},
	{tokens: []string{"api", "secret"}, role: RoleAPISecret},
	{tokens: []string{"api", "key"}, role: RoleAPIKey},
	{tokens: []string{"access", "key"}, role: RoleAccessKey},
	{tokens: []string{"secret", "key"}, role: RoleSecretKey},
	{tokens: []string{"access", "token"}, role: RoleAccessToken},
	{tokens: []string{"refresh", "token"}, role: RoleRefreshToken},
	{tokens: []string{"database", "password"}, role: RoleDBPassword},
	{tokens: []string{"database", "user"}, role: RoleDBUser},
	{tokens: []string{"db", "password"}, role: RoleDBPassword},
	{tokens: []string{"db", "user"}, role: RoleDBUser},
	{tokens: []string{"smtp", "password"}, role: RoleSMTPPassword},
	{tokens: []string{"smtp", "pass"}, role: RoleSMTPPassword},
	{tokens: []string{"smtp", "user"}, role: RoleSMTPUser},
	{tokens: []string{"ldap", "password"}, role: RoleLDAPPassword},
	{tokens: []string{"ldap", "user"}, role: RoleLDAPUser},
	{tokens: []string{"elastic", "password"}, role: RolePassword},
	{tokens: []string{"elastic", "user"}, role: RoleIdentity},
	{tokens: []string{"redis", "password"}, role: RolePassword},
	{tokens: []string{"redis", "user"}, role: RoleIdentity},
	{tokens: []string{"mongodb", "password"}, role: RolePassword},
	{tokens: []string{"mongodb", "user"}, role: RoleIdentity},
	{tokens: []string{"mongo", "password"}, role: RolePassword},
	{tokens: []string{"mongo", "user"}, role: RoleIdentity},
	{tokens: []string{"password", "hash"}, role: RoleHash},
	{tokens: []string{"passwd", "hash"}, role: RoleHash},
	{tokens: []string{"pwd", "hash"}, role: RoleHash},
	{tokens: []string{"public", "key"}, role: RolePublic},
	{tokens: []string{"login", "name"}, role: RoleIdentity, deepOnly: true},
	{tokens: []string{"account", "name"}, role: RoleIdentity, deepOnly: true},
	{tokens: []string{"user", "name"}, role: RoleIdentity, deepOnly: true},
	{tokens: []string{"secret", "value"}, role: RoleSecret, deepOnly: true},
	{tokens: []string{"credential", "value"}, role: RoleSecret, deepOnly: true},
	{tokens: []string{"auth", "secret"}, role: RoleSecret, deepOnly: true},
	{tokens: []string{"username"}, role: RoleIdentity},
	{tokens: []string{"user"}, role: RoleIdentity},
	{tokens: []string{"login"}, role: RoleIdentity},
	{tokens: []string{"email"}, role: RoleIdentity},
	{tokens: []string{"account"}, role: RoleIdentity},
	{tokens: []string{"password"}, role: RolePassword},
	{tokens: []string{"passwd"}, role: RolePassword},
	{tokens: []string{"pwd"}, role: RolePassword},
	{tokens: []string{"pass"}, role: RolePassword},
	{tokens: []string{"token"}, role: RoleToken},
	{tokens: []string{"secret"}, role: RoleSecret},
	{tokens: []string{"key"}, role: RoleKey},
	{tokens: []string{"uid"}, role: RoleIdentity, deepOnly: true},
}

func init() {
	sortRoleRules(roleRules)
}

func sortRoleRules(rules []roleRule) {
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			if len(rules[j].tokens) > len(rules[i].tokens) {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}
}

// NormalizeFieldName folds camelCase, PascalCase, snake_case, kebab-case, and
// dotted paths into a space-separated semantic token string.
func NormalizeFieldName(name string) string {
	tokens := tokenizeField(name)
	if len(tokens) == 0 {
		return ""
	}
	return strings.Join(tokens, " ")
}

// ClassifyFieldRole maps a field path to at most one correlation role.
func ClassifyFieldRole(path string, broad bool) FieldRole {
	name := fieldName(path)
	if name == "" {
		name = path
	}
	tokens := tokenizeField(name)
	joined := strings.Join(tokens, "")
	for _, rule := range roleRules {
		if rule.deepOnly && !broad {
			continue
		}
		if len(rule.tokens) == 1 {
			if rule.tokens[0] == "pass" && tokenEquals(tokens, "key") {
				continue
			}
			if rule.tokens[0] == "key" && tokenEquals(tokens, "public") {
				continue
			}
			if tokenEquals(tokens, rule.tokens[0]) || joined == strings.Join(rule.tokens, "") {
				return rule.role
			}
			continue
		}
		if containsTokenSequence(tokens, rule.tokens) || joined == strings.Join(rule.tokens, "") {
			return rule.role
		}
	}
	if isIDLike(name, tokens) {
		return RoleNone
	}
	return RoleNone
}

func identityFamily() []FieldRole {
	return []FieldRole{RoleIdentity, RoleDBUser, RoleSMTPUser, RoleLDAPUser}
}

func passwordFamily() []FieldRole {
	return []FieldRole{RolePassword, RoleDBPassword, RoleSMTPPassword, RoleLDAPPassword, RoleSecret}
}

func clientIDFamily() []FieldRole {
	return []FieldRole{RoleClientID, RoleOAuthClientID, RoleConsumerKey}
}

func clientSecretFamily() []FieldRole {
	return []FieldRole{RoleClientSecret, RoleOAuthClientSecret, RoleConsumerSecret, RoleAPISecret, RoleSecret}
}
