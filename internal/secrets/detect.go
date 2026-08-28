package secrets

import (
	"strings"
)

type hit struct {
	Category       string
	Detector       string
	Severity       Severity
	Confidence     Confidence
	Reason         string
	Raw            string
	Masked         string
	Suppress       bool
	FieldPath      string
	ObjectPath     string
	RelatedFields  []string
	CredentialType string
	MaskedValues   map[string]string
}

func detectValue(value string, semantics FieldSemantics, maxFieldBytes int) []hit {
	if value == "" {
		return nil
	}
	truncated, cut := truncateField(value, maxFieldBytes)
	if cut {
		value = truncated
	}
	if looksLikePublicMaterial(value) && !looksLikePrivateKey(value) {
		return []hit{{
			Category:   "material.public",
			Detector:   "public-material",
			Severity:   SeverityInfo,
			Confidence: ConfidenceConfirmed,
			Reason:     "Public certificate or public key (not a secret)",
			Masked:     "Public key or certificate detected",
			Suppress:   true,
		}}
	}
	var hits []hit
	hits = append(hits, detectKnownPatterns(value, semantics)...)
	hits = append(hits, detectPasswordHash(value, semantics)...)
	hits = append(hits, detectTextSecrets(value, semantics)...)
	hits = append(hits, detectGeneric(value, semantics)...)
	if semantics.Sensitive && !semantics.IDLike && !hasCredentialHit(hits) && looksLikeCredentialValue(value, semantics) {
		hits = append(hits, hit{
			Category:   firstNonEmpty(semantics.Category, "credential.generic"),
			Detector:   "sensitive-field",
			Severity:   raiseTo(semantics.Severity, SeverityMedium),
			Confidence: ConfidenceHigh,
			Reason:     "Sensitive field name + credential-like value",
			Raw:        value,
			Masked:     Mask(value),
		})
	}
	return uniqueHits(hits)
}

func detectGeneric(value string, semantics FieldSemantics) []hit {
	if semantics.IDLike || looksLikeUUID(value) || looksLikePublicMaterial(value) {
		return nil
	}
	if !highEntropySecret(value) {
		return nil
	}
	if looksLikeHex(value) && (len(value) == 32 || len(value) == 40 || len(value) == 64 || len(value) == 128) && !semantics.Sensitive {
		return nil
	}
	confidence := ConfidenceLow
	severity := SeverityLow
	reason := "High-entropy string without a known secret format"
	if semantics.Sensitive {
		confidence = ConfidenceHigh
		severity = raiseTo(semantics.Severity, SeverityHigh)
		reason = "Sensitive field name + high-entropy value"
	} else if semantics.TextLike {
		confidence = ConfidenceMedium
		severity = SeverityMedium
		reason = "High-entropy value in a text/configuration field"
	}
	return []hit{{
		Category:   firstNonEmpty(semantics.Category, "possible-secret"),
		Detector:   "entropy",
		Severity:   severity,
		Confidence: confidence,
		Reason:     reason,
		Raw:        value,
		Masked:     Mask(value),
	}}
}

func looksLikeCredentialValue(value string, semantics FieldSemantics) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 4 {
		return semantics.Severity == SeverityCritical && len(trimmed) > 0
	}
	if looksLikeUUID(trimmed) {
		return false
	}
	switch semantics.Category {
	case "identity.username", "identity.email", "identity.client_id":
		return false
	}
	return classifyPasswordHash(trimmed) == ""
}

func detectTextSecrets(value string, semantics FieldSemantics) []hit {
	if !semantics.TextLike && !strings.Contains(value, "\n") && !strings.Contains(value, "=") && !strings.Contains(value, "Authorization") {
		return nil
	}
	var hits []hit
	if loc := authorizationHeader.FindStringSubmatch(value); len(loc) == 3 {
		scheme := strings.ToLower(loc[1])
		category := "credential.http.bearer"
		if scheme == "basic" {
			category = "credential.http.basic"
		}
		item := hit{
			Category:   category,
			Detector:   "authorization-header",
			Severity:   SeverityCritical,
			Confidence: ConfidenceConfirmed,
			Reason:     "HTTP Authorization header",
			Raw:        loc[0],
			Masked:     Mask(loc[0]),
		}
		hits = append(hits, enrichAuthorizationHeader(item, scheme))
	}
	if match := envAssignment.FindString(value); match != "" {
		hits = append(hits, hit{
			Category:   "credential.env",
			Detector:   "env-assignment",
			Severity:   SeverityCritical,
			Confidence: ConfidenceHigh,
			Reason:     ".env-style secret assignment",
			Raw:        match,
			Masked:     maskAssignment(match),
		})
	}
	if match := userinfoURL.FindString(value); match != "" {
		item := hit{
			Category:   "credential.connection_string",
			Detector:   "userinfo-url",
			Severity:   SeverityCritical,
			Confidence: ConfidenceConfirmed,
			Reason:     "URL with username:password userinfo",
			Raw:        match,
			Masked:     Mask(match),
		}
		hits = append(hits, enrichConnectionString(item, match))
	}
	if match := ldapBind.FindString(value); match != "" {
		hits = append(hits, hit{
			Category:   "credential.ldap",
			Detector:   "ldap-bind",
			Severity:   SeverityHigh,
			Confidence: ConfidenceHigh,
			Reason:     "LDAP bind credential assignment",
			Raw:        match,
			Masked:     maskAssignment(match),
		})
	}
	if match := smtpAuth.FindString(value); match != "" {
		hits = append(hits, hit{
			Category:   "credential.smtp",
			Detector:   "smtp-credential",
			Severity:   SeverityHigh,
			Confidence: ConfidenceHigh,
			Reason:     "SMTP credential assignment",
			Raw:        match,
			Masked:     maskAssignment(match),
		})
	}
	if !hasCredentialHit(hits) {
		if groups := textAssignment.FindStringSubmatch(value); len(groups) == 3 {
			hits = append(hits, hit{
				Category:   "credential.generic",
				Detector:   "text-assignment",
				Severity:   SeverityHigh,
				Confidence: ConfidenceMedium,
				Reason:     "Secret assignment in text content",
				Raw:        groups[0],
				Masked:     maskAssignment(groups[0]),
			})
		}
	}
	return hits
}

func maskAssignment(value string) string {
	index := strings.IndexAny(value, ":=")
	if index < 0 {
		return Mask(value)
	}
	return value[:index+1] + Mask(strings.TrimSpace(value[index+1:]))
}

func hasCredentialHit(hits []hit) bool {
	for _, item := range hits {
		if strings.HasPrefix(item.Category, "credential.") || item.Category == "possible-secret" {
			return true
		}
	}
	return false
}

func uniqueHits(hits []hit) []hit {
	if len(hits) < 2 {
		return hits
	}
	seen := make(map[string]struct{}, len(hits))
	out := make([]hit, 0, len(hits))
	for _, item := range hits {
		key := item.Detector + "\x00" + item.Category + "\x00" + item.Masked
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func raiseTo(current, minimum Severity) Severity {
	if severityRank(current) >= severityRank(minimum) {
		return current
	}
	return minimum
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
