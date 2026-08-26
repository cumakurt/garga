package fingerprint

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const maxRootStringBytes = 128

type rootInfo struct {
	tagline             string
	version             string
	hasName             bool
	hasClusterName      bool
	hasClusterUUID      bool
	buildMetadataFields int
	isOpenSearch        bool
}

func parseRoot(body []byte) rootInfo {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var root map[string]json.RawMessage
	if err := decoder.Decode(&root); err != nil || root == nil {
		return rootInfo{}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return rootInfo{}
	}

	info := rootInfo{
		tagline:        readSafeString(root["tagline"]),
		hasName:        readSafeString(root["name"]) != "",
		hasClusterName: readSafeString(root["cluster_name"]) != "",
		hasClusterUUID: readSafeString(root["cluster_uuid"]) != "",
	}

	var versionFields map[string]json.RawMessage
	if err := json.Unmarshal(root["version"], &versionFields); err == nil {
		candidate := readSafeString(versionFields["number"])
		if validVersion(candidate) {
			info.version = candidate
		}
		for _, name := range []string{"build_flavor", "build_type", "build_hash", "build_date"} {
			if readSafeString(versionFields[name]) != "" {
				info.buildMetadataFields++
			}
		}
		if strings.EqualFold(readSafeString(versionFields["distribution"]), "opensearch") {
			info.isOpenSearch = true
		}
	}
	if strings.Contains(strings.ToLower(info.tagline), "opensearch") {
		info.isOpenSearch = true
	}
	return info
}

func readSafeString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" || len(value) > maxRootStringBytes || !utf8.ValidString(value) {
		return ""
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return ""
		}
	}
	return value
}

func validVersion(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	core, suffix, hasSuffix := strings.Cut(value, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	if !hasSuffix {
		return true
	}
	if suffix == "" {
		return false
	}
	lowerSuffix := strings.ToLower(suffix)
	if lowerSuffix == "snapshot" {
		return true
	}
	for _, prefix := range []string{"alpha", "beta", "rc"} {
		if strings.HasPrefix(lowerSuffix, prefix) {
			number := strings.TrimPrefix(lowerSuffix, prefix)
			number = strings.TrimPrefix(number, ".")
			if number == "" {
				return false
			}
			for _, character := range number {
				if character < '0' || character > '9' {
					return false
				}
			}
			return true
		}
	}
	return false
}
