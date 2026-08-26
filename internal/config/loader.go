package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const maxConfigFileBytes = 1024 * 1024

var yamlLinePattern = regexp.MustCompile(`(?m)line ([0-9]+)`) // The line number is safe; raw parser messages are not.

// Options selects an optional YAML file and explicit CLI-layer overrides.
type Options struct {
	ConfigPath string
	Overrides  Overrides
}

// Loader resolves configuration without mutating process-global state.
type Loader struct {
	lookupEnv func(string) (string, bool)
}

// NewLoader creates a loader. A nil lookup function uses the process environment.
func NewLoader(lookupEnv func(string) (string, bool)) *Loader {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	return &Loader{lookupEnv: lookupEnv}
}

// Load resolves built-in defaults, YAML, environment, and explicit overrides in that order.
func Load(options Options) (Config, error) {
	return NewLoader(nil).Load(options)
}

// Load resolves configuration using the loader's environment provider.
func (loader *Loader) Load(options Options) (Config, error) {
	cfg := Defaults()
	configPath := strings.TrimSpace(options.ConfigPath)
	if configPath == "" {
		if value, ok := loader.lookupEnv("GARGA_CONFIG"); ok {
			configPath = strings.TrimSpace(value)
		}
	}

	if configPath != "" {
		patch, err := readFilePatch(configPath)
		if err != nil {
			return Config{}, err
		}
		if err := applyFilePatch(&cfg, patch); err != nil {
			return Config{}, err
		}
	}

	if err := loader.applyEnvironment(&cfg); err != nil {
		return Config{}, err
	}
	applyOverrides(&cfg, options.Overrides)

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

type filePatch struct {
	Scanner     *scannerPatch     `yaml:"scanner"`
	Fingerprint *fingerprintPatch `yaml:"fingerprint"`
	Output      *outputPatch      `yaml:"output"`
	Logging     *loggingPatch     `yaml:"logging"`
}

type scannerPatch struct {
	Concurrency       *int     `yaml:"concurrency"`
	RequestsPerSecond *float64 `yaml:"requests_per_second"`
	PerHostRate       *float64 `yaml:"per_host_requests_per_second"`
	ConnectTimeout    *string  `yaml:"connect_timeout"`
	RequestTimeout    *string  `yaml:"request_timeout"`
	Retries           *int     `yaml:"retries"`
	MaxResponseBytes  *int64   `yaml:"max_response_bytes"`
}

type fingerprintPatch struct {
	Threshold *int `yaml:"threshold"`
}

type outputPatch struct {
	Format *string `yaml:"format"`
}

type loggingPatch struct {
	Level *string `yaml:"level"`
}

func readFilePatch(path string) (filePatch, error) {
	file, err := os.Open(path)
	if err != nil {
		return filePatch{}, fmt.Errorf("open configuration file %q: %w", path, err)
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil {
		return filePatch{}, fmt.Errorf("read configuration file %q: %w", path, err)
	}
	if len(contents) > maxConfigFileBytes {
		return filePatch{}, fmt.Errorf("configuration file %q exceeds the %d-byte limit", path, maxConfigFileBytes)
	}
	if len(bytes.TrimSpace(contents)) == 0 {
		return filePatch{}, nil
	}

	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	var patch filePatch
	if err := decoder.Decode(&patch); err != nil {
		return filePatch{}, sanitizedYAMLError(path, err)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return filePatch{}, sanitizedYAMLError(path, err)
		}
		return filePatch{}, fmt.Errorf("configuration file %q must contain exactly one YAML document", path)
	}
	return patch, nil
}

func sanitizedYAMLError(path string, err error) error {
	location := ""
	if match := yamlLinePattern.FindStringSubmatch(err.Error()); len(match) == 2 {
		location = " near line " + match[1]
	}
	return fmt.Errorf("configuration file %q contains invalid YAML or an unsupported field/value%s", path, location)
}

func applyFilePatch(cfg *Config, patch filePatch) error {
	if patch.Scanner != nil {
		if patch.Scanner.Concurrency != nil {
			cfg.Scanner.Concurrency = *patch.Scanner.Concurrency
		}
		if patch.Scanner.RequestsPerSecond != nil {
			cfg.Scanner.RequestsPerSecond = *patch.Scanner.RequestsPerSecond
		}
		if patch.Scanner.PerHostRate != nil {
			cfg.Scanner.PerHostRate = *patch.Scanner.PerHostRate
		}
		if patch.Scanner.ConnectTimeout != nil {
			value, err := parseDuration("scanner.connect_timeout", *patch.Scanner.ConnectTimeout)
			if err != nil {
				return err
			}
			cfg.Scanner.ConnectTimeout = value
		}
		if patch.Scanner.RequestTimeout != nil {
			value, err := parseDuration("scanner.request_timeout", *patch.Scanner.RequestTimeout)
			if err != nil {
				return err
			}
			cfg.Scanner.RequestTimeout = value
		}
		if patch.Scanner.Retries != nil {
			cfg.Scanner.Retries = *patch.Scanner.Retries
		}
		if patch.Scanner.MaxResponseBytes != nil {
			cfg.Scanner.MaxResponseBytes = *patch.Scanner.MaxResponseBytes
		}
	}
	if patch.Fingerprint != nil && patch.Fingerprint.Threshold != nil {
		cfg.Fingerprint.Threshold = *patch.Fingerprint.Threshold
	}
	if patch.Output != nil && patch.Output.Format != nil {
		cfg.Output.Format = parseOutputFormat(*patch.Output.Format)
	}
	if patch.Logging != nil && patch.Logging.Level != nil {
		cfg.Logging.Level = parseLogLevel(*patch.Logging.Level)
	}
	return nil
}

func (loader *Loader) applyEnvironment(cfg *Config) error {
	parsers := []struct {
		name  string
		apply func(string) error
	}{
		{"GARGA_CONCURRENCY", func(value string) error {
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return invalidEnvironment("GARGA_CONCURRENCY", "must be an integer")
			}
			cfg.Scanner.Concurrency = parsed
			return nil
		}},
		{"GARGA_RATE", func(value string) error {
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				return invalidEnvironment("GARGA_RATE", "must be a number")
			}
			cfg.Scanner.RequestsPerSecond = parsed
			return nil
		}},
		{"GARGA_PER_HOST_RATE", func(value string) error {
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				return invalidEnvironment("GARGA_PER_HOST_RATE", "must be a number")
			}
			cfg.Scanner.PerHostRate = parsed
			return nil
		}},
		{"GARGA_CONNECT_TIMEOUT", func(value string) error {
			parsed, err := parseDuration("GARGA_CONNECT_TIMEOUT", value)
			if err != nil {
				return invalidEnvironment("GARGA_CONNECT_TIMEOUT", "must be a duration such as 2s")
			}
			cfg.Scanner.ConnectTimeout = parsed
			return nil
		}},
		{"GARGA_REQUEST_TIMEOUT", func(value string) error {
			parsed, err := parseDuration("GARGA_REQUEST_TIMEOUT", value)
			if err != nil {
				return invalidEnvironment("GARGA_REQUEST_TIMEOUT", "must be a duration such as 5s")
			}
			cfg.Scanner.RequestTimeout = parsed
			return nil
		}},
		{"GARGA_RETRIES", func(value string) error {
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return invalidEnvironment("GARGA_RETRIES", "must be an integer")
			}
			cfg.Scanner.Retries = parsed
			return nil
		}},
		{"GARGA_MAX_RESPONSE_BYTES", func(value string) error {
			parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return invalidEnvironment("GARGA_MAX_RESPONSE_BYTES", "must be an integer byte count")
			}
			cfg.Scanner.MaxResponseBytes = parsed
			return nil
		}},
		{"GARGA_FINGERPRINT_THRESHOLD", func(value string) error {
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return invalidEnvironment("GARGA_FINGERPRINT_THRESHOLD", "must be an integer")
			}
			cfg.Fingerprint.Threshold = parsed
			return nil
		}},
		{"GARGA_OUTPUT_FORMAT", func(value string) error {
			cfg.Output.Format = parseOutputFormat(value)
			return nil
		}},
		{"GARGA_LOG_LEVEL", func(value string) error {
			cfg.Logging.Level = parseLogLevel(value)
			return nil
		}},
	}

	for _, parser := range parsers {
		if value, ok := loader.lookupEnv(parser.name); ok {
			if err := parser.apply(value); err != nil {
				return err
			}
		}
	}
	return nil
}

func invalidEnvironment(name, requirement string) error {
	return fmt.Errorf("invalid environment variable %s: %s", name, requirement)
}

func parseDuration(field, value string) (time.Duration, error) {
	duration, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("invalid configuration: %s must be a duration such as 2s", field)
	}
	return duration, nil
}

func applyOverrides(cfg *Config, overrides Overrides) {
	if overrides.Concurrency != nil {
		cfg.Scanner.Concurrency = *overrides.Concurrency
	}
	if overrides.RequestsPerSecond != nil {
		cfg.Scanner.RequestsPerSecond = *overrides.RequestsPerSecond
	}
	if overrides.PerHostRate != nil {
		cfg.Scanner.PerHostRate = *overrides.PerHostRate
	}
	if overrides.ConnectTimeout != nil {
		cfg.Scanner.ConnectTimeout = *overrides.ConnectTimeout
	}
	if overrides.RequestTimeout != nil {
		cfg.Scanner.RequestTimeout = *overrides.RequestTimeout
	}
	if overrides.Retries != nil {
		cfg.Scanner.Retries = *overrides.Retries
	}
	if overrides.MaxResponseBytes != nil {
		cfg.Scanner.MaxResponseBytes = *overrides.MaxResponseBytes
	}
	if overrides.FingerprintScore != nil {
		cfg.Fingerprint.Threshold = *overrides.FingerprintScore
	}
	if overrides.OutputFormat != nil {
		cfg.Output.Format = parseOutputFormat(string(*overrides.OutputFormat))
	}
	if overrides.LogLevel != nil {
		cfg.Logging.Level = parseLogLevel(string(*overrides.LogLevel))
	}
}
