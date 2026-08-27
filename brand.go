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

// LogoPNGBase64 returns the embedded project logo as base64 for standalone reports.
func LogoPNGBase64() string {
	logoOnce.Do(func() {
		logoBase64 = base64.StdEncoding.EncodeToString(logoPNG)
	})
	return logoBase64
}
