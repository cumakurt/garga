package model

import (
	"net"
	"strconv"
	"strings"
)

// Scheme identifies an explicitly requested endpoint protocol.
type Scheme string

const (
	SchemeAuto  Scheme = ""
	SchemeHTTP  Scheme = "http"
	SchemeHTTPS Scheme = "https"
)

// Target is the canonical representation of one scan target.
type Target struct {
	Host       string
	Port       int
	SchemeHint Scheme
	Path       string
	Source     string
}

// String returns the canonical target without source attribution.
func (target Target) String() string {
	host := target.Host
	if target.SchemeHint != SchemeAuto {
		// RFC 6874 requires the percent introducing an IPv6 zone to be escaped in URLs.
		host = strings.ReplaceAll(host, "%", "%25")
	}

	authority := host
	if target.Port != 0 {
		authority = net.JoinHostPort(host, strconv.Itoa(target.Port))
	} else if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}

	if target.SchemeHint == SchemeAuto {
		return authority + target.Path
	}
	return string(target.SchemeHint) + "://" + authority + target.Path
}
