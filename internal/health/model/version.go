package model

import (
	"fmt"
	"strconv"
	"strings"
)

// Version identifies an Elasticsearch release without assuming a specific major line.
type Version struct {
	Number                    string `json:"number"`
	BuildFlavor               string `json:"build_flavor,omitempty"`
	BuildType                 string `json:"build_type,omitempty"`
	BuildHash                 string `json:"build_hash,omitempty"`
	LuceneVersion             string `json:"lucene_version,omitempty"`
	MinimumWireCompatibility  string `json:"minimum_wire_compatibility_version,omitempty"`
	MinimumIndexCompatibility string `json:"minimum_index_compatibility_version,omitempty"`
}

// VersionConstraint declares the inclusive Elasticsearch versions supported by a checker.
// Empty boundaries are unbounded.
type VersionConstraint struct {
	Min string `json:"min,omitempty"`
	Max string `json:"max,omitempty"`
}

// Supports reports whether version is inside the inclusive constraint.
func (constraint VersionConstraint) Supports(version string) bool {
	candidate, ok := parseVersion(version)
	if !ok {
		return false
	}
	if constraint.Min != "" {
		minimum, valid := parseVersion(constraint.Min)
		if !valid || compareVersion(candidate, minimum) < 0 {
			return false
		}
	}
	if constraint.Max != "" {
		maximum, valid := parseVersion(constraint.Max)
		if !valid || compareVersion(candidate, maximum) > 0 {
			return false
		}
	}
	return true
}

// Major returns the Elasticsearch major version, or zero for malformed input.
func (version Version) Major() int {
	parts, ok := parseVersion(version.Number)
	if !ok {
		return 0
	}
	return parts[0]
}

func parseVersion(value string) ([3]int, bool) {
	var result [3]int
	value = strings.TrimSpace(value)
	if value == "" {
		return result, false
	}
	if prefix, _, found := strings.Cut(value, "-"); found {
		value = prefix
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return result, false
	}
	for index, part := range parts {
		parsed, err := strconv.Atoi(part)
		if err != nil || parsed < 0 {
			return result, false
		}
		result[index] = parsed
	}
	return result, true
}

func compareVersion(left, right [3]int) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

// Validate rejects malformed constraints before a scan starts.
func (constraint VersionConstraint) Validate() error {
	var minimum, maximum [3]int
	var hasMinimum, hasMaximum bool
	if constraint.Min != "" {
		minimum, hasMinimum = parseVersion(constraint.Min)
		if !hasMinimum {
			return fmt.Errorf("minimum version is invalid")
		}
	}
	if constraint.Max != "" {
		maximum, hasMaximum = parseVersion(constraint.Max)
		if !hasMaximum {
			return fmt.Errorf("maximum version is invalid")
		}
	}
	if hasMinimum && hasMaximum && compareVersion(minimum, maximum) > 0 {
		return fmt.Errorf("minimum version must not exceed maximum version")
	}
	return nil
}
