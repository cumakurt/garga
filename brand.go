package garga

import (
	_ "embed"
	"encoding/base64"
	"sync"
)

//go:embed garga.png
var logoPNG []byte

var (
	logoOnce   sync.Once
	logoBase64 string
)

// Developer identity shown in standalone HTML and PDF report footers.
const (
	DeveloperName        = "Cuma Kurt"
	DeveloperGitHubURL   = "https://github.com/cumakurt"
	DeveloperLinkedInURL = "https://www.linkedin.com/in/cuma-kurt-34414917/"
)

// LogoPNG returns the embedded project logo for standalone PDF reports.
func LogoPNG() []byte {
	return logoPNG
}

// LogoPNGBase64 returns the embedded project logo as base64 for standalone reports.
func LogoPNGBase64() string {
	logoOnce.Do(func() {
		logoBase64 = base64.StdEncoding.EncodeToString(logoPNG)
	})
	return logoBase64
}
