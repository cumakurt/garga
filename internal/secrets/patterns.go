package secrets

import (
	"regexp"
	"strings"
)

type patternDetector struct {
	name       string
	category   string
	severity   Severity
	confidence Confidence
	reason     string
	pattern    *regexp.Regexp
	suppress   bool
	whole      bool
}

var knownPatterns []patternDetector

func init() {
	knownPatterns = []patternDetector{
		{
			name: "aws-access-key", category: "credential.cloud.aws",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:  "AWS Access Key ID",
			pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		},
		{
			name: "aws-secret-access-key", category: "credential.cloud.aws",
			severity: SeverityCritical, confidence: ConfidenceHigh,
			reason:  "AWS Secret Access Key in a secret-named field",
			pattern: regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`),
			whole:   true,
		},
		{
			name: "aws-session-token", category: "credential.cloud.aws",
			severity: SeverityHigh, confidence: ConfidenceHigh,
			reason:  "AWS session token in a token-named field",
			pattern: regexp.MustCompile(`^(IQoJ|FwoGZXIvYXdz)[A-Za-z0-9/+=]{80,}$`),
			whole:   true,
		},
		{
			name: "google-api-key", category: "credential.cloud.gcp",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:  "Google API key",
			pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		},
		{
			name: "github-pat", category: "credential.github",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:  "GitHub personal access token",
			pattern: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		},
		{
			name: "github-fine-grained-pat", category: "credential.github",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:  "GitHub fine-grained personal access token",
			pattern: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
		},
		{
			name: "gitlab-pat", category: "credential.gitlab",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:  "GitLab personal access token",
			pattern: regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20,}`),
		},
		{
			name: "slack-token", category: "credential.slack",
			severity: SeverityHigh, confidence: ConfidenceConfirmed,
			reason:  "Slack token",
			pattern: regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
		},
		{
			name: "slack-webhook", category: "credential.webhook",
			severity: SeverityHigh, confidence: ConfidenceConfirmed,
			reason:  "Slack webhook URL",
			pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+`),
		},
		{
			name: "jwt", category: "credential.jwt",
			severity: SeverityHigh, confidence: ConfidenceConfirmed,
			reason:  "JSON Web Token",
			pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		},
		{
			name: "pem-private-key", category: "credential.private_key",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:   "PEM or OpenSSH private key",
			pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`),
			suppress: true,
		},
		{
			name: "pgp-private-key", category: "credential.private_key",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:   "PGP private key",
			pattern:  regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			suppress: true,
		},
		{
			name: "postgres-url", category: "credential.connection_string",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:  "PostgreSQL connection URL",
			pattern: regexp.MustCompile(`(?i)postgres(?:ql)?://[^\s"']+`),
		},
		{
			name: "mysql-url", category: "credential.connection_string",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:  "MySQL connection URL",
			pattern: regexp.MustCompile(`(?i)mysql://[^\s"']+`),
		},
		{
			name: "mongodb-url", category: "credential.connection_string",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:  "MongoDB connection URL",
			pattern: regexp.MustCompile(`(?i)mongodb(?:\+srv)?://[^\s"']+`),
		},
		{
			name: "redis-url", category: "credential.connection_string",
			severity: SeverityCritical, confidence: ConfidenceConfirmed,
			reason:  "Redis connection URL",
			pattern: regexp.MustCompile(`(?i)rediss?://[^\s"']+`),
		},
		{
			name: "mssql-url", category: "credential.connection_string",
			severity: SeverityHigh, confidence: ConfidenceConfirmed,
			reason:  "MSSQL connection URL",
			pattern: regexp.MustCompile(`(?i)mssql://[^\s"']+`),
		},
		{
			name: "elasticsearch-url", category: "credential.connection_string",
			severity: SeverityHigh, confidence: ConfidenceHigh,
			reason:  "Elasticsearch URL with userinfo",
			pattern: regexp.MustCompile(`(?i)(?:elasticsearch|https?)://[^/\s:]+:[^@\s]+@`),
		},
		{
			name: "jdbc-url", category: "credential.connection_string",
			severity: SeverityHigh, confidence: ConfidenceHigh,
			reason:  "JDBC URL",
			pattern: regexp.MustCompile(`(?i)jdbc:[a-z0-9]+:[^\s"']+`),
		},
		{
			name: "azure-storage-key", category: "credential.cloud.azure",
			severity: SeverityCritical, confidence: ConfidenceHigh,
			reason:  "Azure storage account key",
			pattern: regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+/=]{40,}`),
		},
		{
			name: "azure-client-secret", category: "credential.cloud.azure",
			severity: SeverityCritical, confidence: ConfidenceHigh,
			reason:  "Azure client secret assignment",
			pattern: regexp.MustCompile(`(?i)(?:azure_)?client_secret\s*[:=]\s*\S+`),
		},
		{
			name: "kubernetes-sa-token", category: "credential.kubernetes",
			severity: SeverityCritical, confidence: ConfidenceHigh,
			reason:  "Kubernetes service account token material",
			pattern: regexp.MustCompile(`(?i)kubernetes\.io/serviceaccount`),
		},
		{
			name: "docker-auth", category: "credential.docker",
			severity: SeverityHigh, confidence: ConfidenceHigh,
			reason:  "Docker registry auth configuration",
			pattern: regexp.MustCompile(`(?i)"auths"\s*:\s*\{`),
		},
	}
}

var (
	envAssignment       = regexp.MustCompile(`(?m)(?i)^(?:export\s+)?(PASSWORD|PASSWD|SECRET|API[_-]?KEY|TOKEN|ACCESS[_-]?TOKEN|CLIENT[_-]?SECRET|PRIVATE[_-]?KEY|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\s*=\s*\S+`)
	textAssignment      = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|apikey|api[_-]?key|secret|access[_-]?token|refresh[_-]?token|authorization)\s*[:=]\s*([^\s"'\\]+)`)
	authorizationHeader = regexp.MustCompile(`(?i)Authorization\s*:\s*(Bearer|Basic)\s+(\S+)`)
	userinfoURL         = regexp.MustCompile(`(?i)(?:https?|elasticsearch|ldaps?|smtp|redis|mongodb)://[^/\s:]+:[^@\s]+@`)
	ldapBind            = regexp.MustCompile(`(?i)\b(?:bind(?:dn|pw)|ldap(?:_user|_password|_bind))\s*[:=]\s*\S+`)
	smtpAuth            = regexp.MustCompile(`(?i)\b(?:smtp_(?:user|password|pass)|mail\.smtp\.password)\s*[:=]\s*\S+`)
	publicKeyHeader     = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PUBLIC KEY-----`)
	certificateHeader   = regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)
)

func isJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	return strings.HasPrefix(parts[0], "eyJ") && strings.HasPrefix(parts[1], "eyJ") && len(parts[2]) >= 8
}

func looksLikePrivateKey(value string) bool {
	return strings.Contains(value, "BEGIN") && strings.Contains(value, "PRIVATE KEY")
}

func looksLikePublicMaterial(value string) bool {
	return publicKeyHeader.MatchString(value) || certificateHeader.MatchString(value)
}

func detectKnownPatterns(value string, semantics FieldSemantics) []hit {
	var hits []hit
	for _, detector := range knownPatterns {
		if detector.name == "aws-secret-access-key" && !awsSecretField(semantics) {
			continue
		}
		if detector.name == "aws-session-token" && !tokenField(semantics) {
			continue
		}
		if detector.whole {
			if detector.pattern.MatchString(strings.TrimSpace(value)) {
				hits = append(hits, patternHit(detector, value))
			}
			continue
		}
		if loc := detector.pattern.FindStringIndex(value); loc != nil {
			matched := value[loc[0]:loc[1]]
			item := patternHit(detector, matched)
			if detector.category == "credential.connection_string" {
				item = enrichConnectionString(item, matched)
			}
			hits = append(hits, item)
		}
	}
	return hits
}

func patternHit(detector patternDetector, matched string) hit {
	preview := Mask(matched)
	secret := matched
	if detector.suppress {
		preview = privateKeyPreview
		secret = ""
	}
	return hit{
		Category:   detector.category,
		Detector:   detector.name,
		Severity:   detector.severity,
		Confidence: detector.confidence,
		Reason:     detector.reason,
		Raw:        secret,
		Masked:     preview,
		Suppress:   detector.suppress,
	}
}

func awsSecretField(semantics FieldSemantics) bool {
	if !semantics.Sensitive {
		return false
	}
	switch semantics.Category {
	case "credential.cloud", "credential.application_secret", "credential.generic":
		return true
	}
	return tokenEquals(semantics.Tokens, "secret") || containsTokenSequence(semantics.Tokens, []string{"secret", "key"})
}

func tokenField(semantics FieldSemantics) bool {
	return semantics.Category == "credential.token" || tokenEquals(semantics.Tokens, "token") || tokenEquals(semantics.Tokens, "session")
}
