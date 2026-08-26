package capability

import (
	"strings"

	"github.com/cumakurt/garga/internal/probe"
)

func classifyHTTP(status int) Availability {
	switch {
	case status >= 200 && status <= 299:
		return AvailabilityAvailable
	case status == 401 || status == 403:
		return AvailabilityAuthRequired
	case status == 400 || status == 404 || status == 405 || status == 406 || status == 410 || status == 501:
		return AvailabilityUnsupported
	default:
		return AvailabilityUnknown
	}
}

func classifyProbe(name Name, response probe.Result, err error) Capability {
	if err != nil {
		return Capability{Name: name, Availability: AvailabilityError, Detail: "probe_error"}
	}
	availability := classifyHTTP(response.StatusCode)
	return Capability{
		Name:         name,
		Availability: availability,
		StatusCode:   response.StatusCode,
		Detail:       detailFor(availability),
	}
}

func detailFor(availability Availability) string {
	switch availability {
	case AvailabilityAvailable:
		return "anonymous_response"
	case AvailabilityAuthRequired:
		return "authentication_required"
	case AvailabilityUnsupported:
		return "api_unavailable"
	case AvailabilityError:
		return "probe_error"
	default:
		return "inconclusive_response"
	}
}

func advertisedMechanisms(headers []probe.HeaderField) (basicAuth, apiKey bool) {
	for _, field := range headers {
		if !strings.EqualFold(field.Name, "Www-Authenticate") {
			continue
		}
		for _, value := range field.Values {
			lower := strings.ToLower(value)
			if strings.Contains(lower, "apikey") {
				apiKey = true
			}
			if strings.Contains(lower, "basic") && strings.Contains(lower, `realm="security"`) {
				basicAuth = true
			}
		}
	}
	return basicAuth, apiKey
}

func deriveAuthentication(result *Result, sawChallenge, basicAuth, apiKey bool) {
	root := capabilityByName(*result, NameRoot)
	anonymous := Capability{Name: NameAnonymous, Availability: AvailabilityUnknown}
	if result.IsAvailable(NameRoot) || result.IsAvailable(NameHealth) ||
		result.IsAvailable(NameState) || result.IsAvailable(NameNodes) ||
		result.IsAvailable(NameCat) || result.IsAvailable(NameIndices) ||
		result.IsAvailable(NameSecurity) {
		anonymous.Availability = AvailabilityAvailable
		anonymous.StatusCode = firstAvailableStatus(*result)
		anonymous.Detail = "anonymous_response"
	} else if root.Availability == AvailabilityAuthRequired ||
		result.AvailabilityOf(NameSecurity) == AvailabilityAuthRequired {
		anonymous.Availability = AvailabilityAuthRequired
		anonymous.StatusCode = root.StatusCode
		if anonymous.StatusCode == 0 {
			anonymous.StatusCode = capabilityByName(*result, NameSecurity).StatusCode
		}
		anonymous.Detail = "authentication_required"
	} else {
		anonymous.Detail = "inconclusive_response"
	}
	setCapability(result, anonymous)

	setCapability(result, mechanismCapability(NameBasicAuth, sawChallenge, basicAuth))
	setCapability(result, mechanismCapability(NameAPIKey, sawChallenge, apiKey))
}

func firstAvailableStatus(result Result) int {
	for _, name := range []Name{NameRoot, NameHealth, NameState, NameNodes, NameCat, NameIndices, NameSecurity} {
		item := capabilityByName(result, name)
		if item.Availability == AvailabilityAvailable && item.StatusCode != 0 {
			return item.StatusCode
		}
	}
	return 0
}

func mechanismCapability(name Name, sawChallenge, advertised bool) Capability {
	if advertised {
		return Capability{Name: name, Availability: AvailabilityAvailable, Detail: "mechanism_advertised"}
	}
	if sawChallenge {
		return Capability{Name: name, Availability: AvailabilityUnsupported, Detail: "mechanism_not_advertised"}
	}
	return Capability{Name: name, Availability: AvailabilityUnknown, Detail: "inconclusive_response"}
}
