package normalize

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/cumakurt/garga/internal/health/collector"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	basemodel "github.com/cumakurt/garga/internal/model"
)

func parseSecurity(responses collector.ResponseSet, endpoint basemodel.Endpoint, usedCredential bool, snapshot *healthmodel.ClusterSnapshot) {
	security := &snapshot.Security
	security.CredentialsUsed = usedCredential
	security.HTTPSEnabled = endpoint.Scheme == basemodel.SchemeHTTPS
	for _, result := range responses.Collectors {
		if result.Name != "authenticate" {
			continue
		}
		security.AuthenticationStatus = result.HTTPStatus
		switch result.HTTPStatus {
		case http.StatusOK:
			security.Authenticated = true
		case http.StatusUnauthorized:
			security.Authenticated = false
		}
	}
	if response, ok := responses.Responses["authenticate"]; ok {
		root := decodeObject(response.Body)
		username := strings.ToLower(stringValue(root["username"]))
		authenticationType := strings.ToLower(stringValue(root["authentication_type"]))
		anonymousIdentity := username == "_anonymous" || authenticationType == "anonymous"
		if anonymousIdentity || (!usedCredential && response.StatusCode == http.StatusOK) {
			security.AnonymousAccess = true
			security.Authenticated = false
		}
	}

	root := responses.Responses["root"]
	if root.TLS != nil && root.TLS.Certificate != nil {
		certificate := root.TLS.Certificate
		remaining := int(certificate.NotAfter.Sub(snapshot.Timestamp).Hours() / 24)
		security.Certificate = &healthmodel.Certificate{
			Subject: certificate.Subject, Issuer: certificate.Issuer, ValidFrom: certificate.NotBefore.UTC(), ValidUntil: certificate.NotAfter.UTC(),
			RemainingDays: remaining, HostnameValid: certificate.HostnameValid, SelfSigned: certificate.SelfSigned,
		}
	}

	settingsRoot := decodeObject(responseBody(responses, "nodes_settings"))
	var httpValues, transportValues, anonymousValues []bool
	for id, raw := range mapObject(settingsRoot, "nodes") {
		nodeObject, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		settings := securitySettings(mapObject(nodeObject, "settings"))
		for position := range snapshot.Nodes {
			if snapshot.Nodes[position].ID == id {
				snapshot.Nodes[position].SecuritySettings = settings
				break
			}
		}
		if value, ok := booleanSetting(settings, "xpack.security.http.ssl.enabled"); ok {
			httpValues = append(httpValues, value)
		}
		if value, ok := booleanSetting(settings, "xpack.security.transport.ssl.enabled"); ok {
			transportValues = append(transportValues, value)
		}
		configured := false
		for key, value := range settings {
			if strings.HasPrefix(key, "xpack.security.authc.anonymous.") && strings.TrimSpace(value) != "" {
				configured = true
			}
		}
		anonymousValues = append(anonymousValues, configured)
	}
	security.HTTPSSLEnabled = aggregateBoolean(httpValues)
	security.TransportSSLEnabled = aggregateBoolean(transportValues)
	security.AnonymousConfigured = aggregateBoolean(anonymousValues)
}

func booleanSetting(settings map[string]string, key string) (bool, bool) {
	value, ok := settings[key]
	if !ok {
		return false, false
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	return parsed, err == nil
}

func aggregateBoolean(values []bool) *bool {
	if len(values) == 0 {
		return nil
	}
	result := true
	for _, value := range values {
		result = result && value
	}
	return &result
}
