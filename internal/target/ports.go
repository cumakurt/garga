package target

import (
	"strconv"
	"strings"
)

const (
	MinPort               = 1
	MaxPort               = 65535
	maxPortListInputBytes = 8 * 1024
)

// ParsePorts parses comma-separated ports and inclusive ranges into sorted unique ports.
func ParsePorts(input string) ([]int, error) {
	if strings.TrimSpace(input) == "" {
		return nil, newParseError("parse ports: value is empty", nil)
	}
	if len(input) > maxPortListInputBytes {
		return nil, newParseError("parse ports: value exceeds 8192 bytes", nil)
	}

	selected := make([]bool, MaxPort+1)
	for _, entry := range strings.Split(input, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, newParseError("parse ports: list contains an empty entry", nil)
		}

		if !strings.Contains(entry, "-") {
			port, err := parsePortNumber(entry)
			if err != nil {
				return nil, err
			}
			selected[port] = true
			continue
		}

		if strings.Count(entry, "-") != 1 {
			return nil, newParseError("parse ports: range must contain one hyphen", nil)
		}
		bounds := strings.SplitN(entry, "-", 2)
		first, err := parsePortNumber(strings.TrimSpace(bounds[0]))
		if err != nil {
			return nil, err
		}
		last, err := parsePortNumber(strings.TrimSpace(bounds[1]))
		if err != nil {
			return nil, err
		}
		if first > last {
			return nil, newParseError(
				"parse ports: range start must not exceed range end",
				nil,
			)
		}
		for port := first; port <= last; port++ {
			selected[port] = true
		}
	}

	ports := make([]int, 0)
	for port := MinPort; port <= MaxPort; port++ {
		if selected[port] {
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func parsePortNumber(input string) (int, error) {
	if input == "" {
		return 0, newParseError("parse port: value is empty", nil)
	}
	for index := 0; index < len(input); index++ {
		if input[index] < '0' || input[index] > '9' {
			return 0, newParseError("parse port: value must contain only decimal digits", nil)
		}
	}

	port, err := strconv.Atoi(input)
	if err != nil {
		return 0, newParseError("parse port: decimal value is too large", err)
	}
	if port < MinPort || port > MaxPort {
		return 0, newParseError(
			"parse port: value must be between 1 and "+strconv.Itoa(MaxPort),
			nil,
		)
	}
	return port, nil
}
