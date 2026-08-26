package model

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Endpoint is a concrete network location with an explicit HTTP scheme and port.
type Endpoint struct {
	Scheme Scheme `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Path   string `json:"path,omitempty"`
}

// URL returns the canonical endpoint URL after validating every component.
func (endpoint Endpoint) URL() (string, error) {
	if endpoint.Scheme != SchemeHTTP && endpoint.Scheme != SchemeHTTPS {
		return "", fmt.Errorf("invalid endpoint: scheme must be http or https")
	}
	if !validEndpointHost(endpoint.Host) {
		return "", fmt.Errorf("invalid endpoint: host is invalid")
	}
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return "", fmt.Errorf("invalid endpoint: port must be between 1 and 65535")
	}
	path := endpoint.Path
	if path == "" {
		path = "/"
	}
	if !validEndpointPath(path) {
		return "", fmt.Errorf("invalid endpoint: path must be an absolute escaped path without a query or fragment")
	}

	host := strings.ReplaceAll(endpoint.Host, "%", "%25")
	authority := net.JoinHostPort(host, strconv.Itoa(endpoint.Port))
	return string(endpoint.Scheme) + "://" + authority + path, nil
}

func validEndpointHost(host string) bool {
	if host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "/?#@[]") {
		return false
	}
	for _, character := range host {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func validEndpointPath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		return false
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	_, err := url.PathUnescape(path)
	return err == nil
}
