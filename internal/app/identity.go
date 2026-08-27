package app

import (
	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/model"
)

const identitySchemaVersion = "0.1"
const identityEvent = "fingerprint.identity"

// Identity is one streamed fingerprint decision. It contains no response bodies,
// cluster names, UUIDs, or authentication material.
type Identity struct {
	SchemaVersion  string           `json:"schema_version"`
	Event          string           `json:"event"`
	Target         model.Endpoint   `json:"target"`
	Product        string           `json:"product,omitempty"`
	Version        string           `json:"version,omitempty"`
	Score          int              `json:"score"`
	Classification string           `json:"classification"`
	Detected       bool             `json:"detected"`
	Threshold      int              `json:"threshold"`
	Signals        []IdentitySignal `json:"signals"`
}

// IdentitySignal is one fixed-weight fingerprint observation.
type IdentitySignal struct {
	Name   string `json:"name"`
	Weight int    `json:"weight"`
	Match  bool   `json:"match"`
	Detail string `json:"detail"`
}

func newIdentity(endpoint model.Endpoint, result fingerprint.Result) Identity {
	signals := make([]IdentitySignal, 0, len(result.Signals))
	for _, signal := range result.Signals {
		signals = append(signals, IdentitySignal{
			Name:   signal.Name,
			Weight: signal.Weight,
			Match:  signal.Match,
			Detail: signal.Detail,
		})
	}
	return Identity{
		SchemaVersion:  identitySchemaVersion,
		Event:          identityEvent,
		Target:         endpoint,
		Product:        result.Product,
		Version:        result.Version,
		Score:          result.Score,
		Classification: string(result.Classification),
		Detected:       result.Detected,
		Threshold:      result.Threshold,
		Signals:        signals,
	}
}
