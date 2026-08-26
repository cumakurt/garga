package capability

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const maxRoleNameBytes = 128

func parseAnonymousSuperuser(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var root map[string]json.RawMessage
	if err := decoder.Decode(&root); err != nil || root == nil {
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false
	}

	var roles []string
	if err := json.Unmarshal(root["roles"], &roles); err != nil {
		return false
	}
	for _, role := range roles {
		if role == "" || len(role) > maxRoleNameBytes || !utf8.ValidString(role) {
			continue
		}
		invalid := false
		for _, character := range role {
			if character < 0x20 || character == 0x7f {
				invalid = true
				break
			}
		}
		if invalid {
			continue
		}
		if strings.EqualFold(role, "superuser") {
			return true
		}
	}
	return false
}
