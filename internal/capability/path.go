package capability

import (
	"fmt"
	"strings"
)

const (
	pathHealth  = "/_cluster/health"
	pathState   = "/_cluster/state/version"
	pathNodes   = "/_nodes/_local/http"
	pathCat     = "/_cat/health"
	pathIndices = "/_cat/indices"
	// Authenticate API. GET /_security/user/_authenticate is Get User for that username.
	pathSecurity = "/_security/_authenticate"
)

type probeSpec struct {
	name Name
	path string
}

// extraProbes is the GET-only catalog issued after a likely or confirmed fingerprint.
// Paths are Elasticsearch API suffixes and are joined onto a target base path.
var extraProbes = []probeSpec{
	{NameHealth, pathHealth},
	{NameState, pathState},
	{NameNodes, pathNodes},
	{NameCat, pathCat},
	{NameIndices, pathIndices},
	{NameSecurity, pathSecurity},
}

var allowedAPIPaths = map[string]struct{}{
	pathHealth:   {},
	pathState:    {},
	pathNodes:    {},
	pathCat:      {},
	pathIndices:  {},
	pathSecurity: {},
}

func joinAPIPath(basePath, apiPath string) (string, error) {
	if _, allowed := allowedAPIPaths[apiPath]; !allowed {
		return "", fmt.Errorf("discover capabilities: API path is not allowlisted")
	}
	basePath = strings.TrimSuffix(basePath, "/")
	if basePath == "" {
		return apiPath, nil
	}
	if !strings.HasPrefix(basePath, "/") {
		return "", fmt.Errorf("discover capabilities: base path is invalid")
	}
	if strings.ContainsAny(basePath, "?#") || strings.ContainsAny(apiPath, "?#") {
		return "", fmt.Errorf("discover capabilities: API path must not include a query or fragment")
	}
	return basePath + apiPath, nil
}

// ReadOnlyProbe returns the GET path issued for name, if the catalog makes a request.
func ReadOnlyProbe(name Name) (method, path string, ok bool) {
	for _, spec := range extraProbes {
		if spec.name == name {
			return "GET", spec.path, true
		}
	}
	return "", "", false
}
