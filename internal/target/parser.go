package target

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/cumakurt/garga/internal/model"
)

const maxTargetInputBytes = 8 * 1024

// ErrCIDRTarget indicates that a target must be handled by the streaming CIDR source.
var ErrCIDRTarget = errors.New("CIDR target requires streaming expansion")

type parseError struct {
	message string
	cause   error
}

func (err *parseError) Error() string {
	return err.message
}

func (err *parseError) Unwrap() error {
	return err.cause
}

// Parse converts one IPv4, IPv6, hostname, host:port, or HTTP(S) URL into a canonical target.
func Parse(rawTarget, source string) (model.Target, error) {
	input := strings.TrimSpace(rawTarget)
	if input == "" {
		return model.Target{}, newParseError("parse target: value is empty", nil)
	}
	if len(input) > maxTargetInputBytes {
		return model.Target{}, newParseError("parse target: value exceeds 8192 bytes", nil)
	}

	if strings.Contains(input, "://") {
		return parseURL(input, source)
	}

	if strings.Contains(input, "/") {
		if _, err := netip.ParsePrefix(input); err == nil {
			return model.Target{}, newParseError(
				"parse target: CIDR targets require streaming expansion",
				ErrCIDRTarget,
			)
		}
		address, _, _ := strings.Cut(input, "/")
		if _, err := netip.ParseAddr(address); err == nil {
			return model.Target{}, newParseError("parse target: invalid CIDR prefix", nil)
		}
		return model.Target{}, newParseError(
			"parse target: a path requires an http or https URL",
			nil,
		)
	}
	if strings.ContainsAny(input, "?#") {
		return model.Target{}, newParseError(
			"parse target: query parameters and fragments require a URL and are not supported",
			nil,
		)
	}

	host, port, bracketed, err := parseAuthority(input)
	if err != nil {
		return model.Target{}, err
	}

	normalizedHost, isIPv6, err := normalizeHost(host)
	if err != nil {
		return model.Target{}, err
	}
	if bracketed && !isIPv6 {
		return model.Target{}, newParseError(
			"parse target: brackets are only valid for IPv6 addresses",
			nil,
		)
	}

	return model.Target{
		Host:       normalizedHost,
		Port:       port,
		SchemeHint: model.SchemeAuto,
		Source:     source,
	}, nil
}

func parseURL(input, source string) (model.Target, error) {
	parsed, err := url.Parse(input)
	if err != nil {
		return model.Target{}, newParseError("parse target: invalid URL", err)
	}

	scheme := model.Scheme(strings.ToLower(parsed.Scheme))
	if scheme != model.SchemeHTTP && scheme != model.SchemeHTTPS {
		return model.Target{}, newParseError(
			"parse target: URL scheme must be http or https",
			nil,
		)
	}
	if parsed.Opaque != "" || parsed.Host == "" {
		return model.Target{}, newParseError("parse target: URL host is required", nil)
	}
	if parsed.User != nil {
		return model.Target{}, newParseError(
			"parse target: URL user information is not allowed",
			nil,
		)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return model.Target{}, newParseError(
			"parse target: URL query parameters are not supported",
			nil,
		)
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" || strings.Contains(input, "#") {
		return model.Target{}, newParseError(
			"parse target: URL fragments are not supported",
			nil,
		)
	}

	normalizedHost, isIPv6, err := normalizeHost(parsed.Hostname())
	if err != nil {
		return model.Target{}, err
	}
	if strings.HasPrefix(parsed.Host, "[") && !isIPv6 {
		return model.Target{}, newParseError(
			"parse target: brackets are only valid for IPv6 addresses",
			nil,
		)
	}

	portText := parsed.Port()
	hasExplicitPort := urlHasExplicitPort(parsed.Host)
	if hasExplicitPort && portText == "" {
		return model.Target{}, newParseError("parse target: URL port is empty", nil)
	}

	port := defaultPort(scheme)
	if portText != "" {
		port, err = parsePortNumber(portText)
		if err != nil {
			return model.Target{}, err
		}
	}

	escapedPath := parsed.EscapedPath()
	if escapedPath == "/" {
		escapedPath = ""
	} else {
		escapedPath = uppercasePercentEscapes(escapedPath)
	}

	return model.Target{
		Host:       normalizedHost,
		Port:       port,
		SchemeHint: scheme,
		Path:       escapedPath,
		Source:     source,
	}, nil
}

func parseAuthority(input string) (host string, port int, bracketed bool, err error) {
	if address, parseErr := netip.ParseAddr(input); parseErr == nil {
		return address.String(), 0, false, nil
	}

	if strings.HasPrefix(input, "[") {
		closingBracket := strings.IndexByte(input, ']')
		if closingBracket < 0 {
			return "", 0, false, newParseError(
				"parse target: IPv6 closing bracket is missing",
				nil,
			)
		}

		host = input[1:closingBracket]
		remainder := input[closingBracket+1:]
		if remainder == "" {
			return host, 0, true, nil
		}
		if !strings.HasPrefix(remainder, ":") || strings.Contains(remainder[1:], ":") {
			return "", 0, false, newParseError(
				"parse target: invalid text after IPv6 closing bracket",
				nil,
			)
		}

		port, err = parsePortNumber(remainder[1:])
		return host, port, true, err
	}

	switch strings.Count(input, ":") {
	case 0:
		return input, 0, false, nil
	case 1:
		host, portText, splitErr := net.SplitHostPort(input)
		if splitErr != nil {
			return "", 0, false, newParseError("parse target: invalid host and port", splitErr)
		}
		port, err = parsePortNumber(portText)
		return host, port, false, err
	default:
		return "", 0, false, newParseError(
			"parse target: an IPv6 address with a port must use brackets",
			nil,
		)
	}
}

func normalizeHost(host string) (normalized string, isIPv6 bool, err error) {
	if host == "" {
		return "", false, newParseError("parse target: host is empty", nil)
	}

	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if zone := address.Zone(); zone != "" && !validIPv6Zone(zone) {
			return "", false, newParseError(
				"parse target: IPv6 zone contains unsupported characters",
				nil,
			)
		}
		return address.String(), address.Is6(), nil
	}
	if strings.Contains(host, ":") {
		return "", false, newParseError("parse target: invalid IPv6 address", nil)
	}

	normalized, err = normalizeHostname(host)
	return normalized, false, err
}

func normalizeHostname(host string) (string, error) {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return "", newParseError("parse target: invalid hostname length", nil)
	}

	onlyDigitsAndDots := true
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", newParseError("parse target: invalid hostname label length", nil)
		}
		if !isASCIIAlphaNumeric(label[0]) || !isASCIIAlphaNumeric(label[len(label)-1]) {
			return "", newParseError(
				"parse target: hostname labels must start and end with a letter or digit",
				nil,
			)
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if character != '-' && !isASCIIAlphaNumeric(character) {
				return "", newParseError(
					"parse target: hostname contains unsupported characters",
					nil,
				)
			}
			if character < '0' || character > '9' {
				onlyDigitsAndDots = false
			}
		}
	}

	if onlyDigitsAndDots {
		return "", newParseError("parse target: invalid IPv4 address", nil)
	}
	return strings.ToLower(host), nil
}

func validIPv6Zone(zone string) bool {
	if zone == "" {
		return false
	}
	for index := 0; index < len(zone); index++ {
		character := zone[index]
		if isASCIIAlphaNumeric(character) {
			continue
		}
		switch character {
		case '-', '.', '_', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}

func urlHasExplicitPort(host string) bool {
	if strings.HasPrefix(host, "[") {
		closingBracket := strings.LastIndexByte(host, ']')
		return closingBracket >= 0 && len(host) > closingBracket+1
	}
	return strings.Contains(host, ":")
}

func defaultPort(scheme model.Scheme) int {
	if scheme == model.SchemeHTTPS {
		return 443
	}
	return 80
}

func uppercasePercentEscapes(path string) string {
	bytes := []byte(path)
	for index := 0; index+2 < len(bytes); index++ {
		if bytes[index] != '%' {
			continue
		}
		if bytes[index+1] >= 'a' && bytes[index+1] <= 'f' {
			bytes[index+1] -= 'a' - 'A'
		}
		if bytes[index+2] >= 'a' && bytes[index+2] <= 'f' {
			bytes[index+2] -= 'a' - 'A'
		}
		index += 2
	}
	return string(bytes)
}

func newParseError(message string, cause error) error {
	return &parseError{message: message, cause: cause}
}
