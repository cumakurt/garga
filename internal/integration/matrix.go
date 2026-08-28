package integration

import "fmt"
import "os"
import "strings"

type matrixLane struct {
	Version string
	Auth    bool
	TLS     bool
	Legacy  bool
	Image   string
}

func matrixLanes() []matrixLane {
	fullySupported := []string{"8.19.20", "9.4.5", "9.5.2"}
	lanes := make([]matrixLane, 0, len(fullySupported)*3+1)
	for _, version := range fullySupported {
		lanes = append(lanes,
			newLane(version, false, false, false),
			newLane(version, true, false, false),
			newLane(version, true, true, false),
		)
	}
	lanes = append(lanes, newLane("7.17.23", false, false, true))
	return lanes
}

func newLane(version string, auth, tls, legacy bool) matrixLane {
	return matrixLane{
		Version: version,
		Auth:    auth,
		TLS:     tls,
		Legacy:  legacy,
		Image:   imageRepository + ":" + version,
	}
}

func (lane matrixLane) name() string {
	auth := "anon"
	if lane.Auth {
		auth = "auth"
	}
	transport := "http"
	if lane.TLS {
		transport = "https"
	}
	tier := "supported"
	if lane.Legacy {
		tier = "legacy"
	}
	return fmt.Sprintf("%s/%s/%s/%s", lane.Version, tier, auth, transport)
}

func (lane matrixLane) major() int {
	var major int
	_, _ = fmt.Sscanf(lane.Version, "%d", &major)
	return major
}

func selectedLanes() []matrixLane {
	version := requestedVersion()
	filter := strings.TrimSpace(os.Getenv(integrationFilterEnv))
	var selected []matrixLane
	for _, lane := range matrixLanes() {
		if version != "" && lane.Version != version {
			continue
		}
		if filter != "" && !strings.Contains(lane.name(), filter) {
			continue
		}
		selected = append(selected, lane)
	}
	return selected
}
