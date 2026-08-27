package integration

import (
	"os"
	"strings"
)

const (
	integrationEnv        = "GARGA_INTEGRATION"
	integrationVersionEnv = "GARGA_INTEGRATION_VERSION"
	integrationFilterEnv  = "GARGA_INTEGRATION_FILTER"
	imageRepository       = "docker.elastic.co/elasticsearch/elasticsearch"
	elasticUsername       = "elastic"
)

func integrationEnabled() bool {
	return os.Getenv(integrationEnv) == "1"
}

func requestedVersion() string {
	return strings.TrimSpace(os.Getenv(integrationVersionEnv))
}
