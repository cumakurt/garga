package checks

import "github.com/cumakurt/garga/internal/capability"

// AccessClass is the anonymous-access depth derived from GET-only evidence.
type AccessClass string

const (
	AccessNone     AccessClass = "none"
	AccessMetadata AccessClass = "metadata"
	AccessRead     AccessClass = "read"
	AccessWrite    AccessClass = "write"
	AccessAdmin    AccessClass = "admin"
)

// AnonymousClassification is one endpoint's anonymous-access decision.
type AnonymousClassification struct {
	Class    AccessClass
	Inferred bool
}

// ClassifyAnonymousAccess maps capability observations to a single access class.
// Write and admin are inferred unless a passive superuser role was observed.
func ClassifyAnonymousAccess(result capability.Result) AnonymousClassification {
	if !result.IsAvailable(capability.NameAnonymous) {
		return AnonymousClassification{Class: AccessNone}
	}
	if result.AnonymousSuperuser {
		return AnonymousClassification{Class: AccessAdmin, Inferred: false}
	}
	if result.Suppresses(capability.NameSecurity) {
		if result.IsAvailable(capability.NameState) || result.IsAvailable(capability.NameNodes) {
			return AnonymousClassification{Class: AccessAdmin, Inferred: true}
		}
		return AnonymousClassification{Class: AccessWrite, Inferred: true}
	}
	if result.IsAvailable(capability.NameIndices) {
		return AnonymousClassification{Class: AccessRead}
	}
	return AnonymousClassification{Class: AccessMetadata}
}
