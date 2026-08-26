package capability

import "github.com/cumakurt/garga/internal/fingerprint"

// Name is a stable identifier for one discovered Elasticsearch capability.
type Name string

const (
	NameRoot      Name = "root"
	NameHealth    Name = "health"
	NameState     Name = "state"
	NameNodes     Name = "nodes"
	NameCat       Name = "cat"
	NameIndices   Name = "indices"
	NameSecurity  Name = "security"
	NameAnonymous Name = "anonymous"
	NameBasicAuth Name = "basic_auth"
	NameAPIKey    Name = "api_key"
)

// Availability is the deterministic observation for one capability.
type Availability string

const (
	AvailabilityUnknown      Availability = "unknown"
	AvailabilityAvailable    Availability = "available"
	AvailabilityAuthRequired Availability = "auth_required"
	AvailabilityUnsupported  Availability = "unsupported"
	AvailabilityError        Availability = "error"
)

// Capability is one redacted, product-specific discovery result.
type Capability struct {
	Name         Name
	Availability Availability
	StatusCode   int
	Detail       string
}

// Result reports every catalogued capability in a fixed order.
type Result struct {
	Version            string
	Capabilities       []Capability
	AnonymousSuperuser bool
}

var reportOrder = []Name{
	NameRoot,
	NameHealth,
	NameState,
	NameNodes,
	NameCat,
	NameIndices,
	NameSecurity,
	NameAnonymous,
	NameBasicAuth,
	NameAPIKey,
}

func emptyResult(version string) Result {
	capabilities := make([]Capability, len(reportOrder))
	for index, name := range reportOrder {
		capabilities[index] = Capability{Name: name, Availability: AvailabilityUnknown}
	}
	return Result{Version: version, Capabilities: capabilities}
}

func ineligibleResult(version string) Result {
	result := emptyResult(version)
	for index := range result.Capabilities {
		result.Capabilities[index].Detail = "fingerprint_below_likely"
	}
	return result
}

// AvailabilityOf returns the observed state for name, or unknown when absent.
func (result Result) AvailabilityOf(name Name) Availability {
	for _, capability := range result.Capabilities {
		if capability.Name == name {
			return capability.Availability
		}
	}
	return AvailabilityUnknown
}

// Exists reports whether the named API or mechanism was observed as present.
// Authentication-required APIs exist; unsupported APIs do not.
func (result Result) Exists(name Name) bool {
	switch result.AvailabilityOf(name) {
	case AvailabilityAvailable, AvailabilityAuthRequired:
		return true
	default:
		return false
	}
}

// IsAvailable reports unauthenticated access to the named capability.
func (result Result) IsAvailable(name Name) bool {
	return result.AvailabilityOf(name) == AvailabilityAvailable
}

// Suppresses reports whether dependent checks must skip this capability.
// Only an unsupported API suppresses checks; unknown and error do not.
func (result Result) Suppresses(name Name) bool {
	return result.AvailabilityOf(name) == AvailabilityUnsupported
}

func eligible(identity fingerprint.Result) bool {
	return identity.Classification == fingerprint.ClassificationLikely ||
		identity.Classification == fingerprint.ClassificationConfirmed
}

func setCapability(result *Result, capability Capability) {
	for index := range result.Capabilities {
		if result.Capabilities[index].Name == capability.Name {
			result.Capabilities[index] = capability
			return
		}
	}
}

func capabilityByName(result Result, name Name) Capability {
	for _, capability := range result.Capabilities {
		if capability.Name == name {
			return capability
		}
	}
	return Capability{Name: name, Availability: AvailabilityUnknown}
}
