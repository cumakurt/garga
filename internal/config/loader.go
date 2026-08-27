package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
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
	Health      *healthPatch      `yaml:"health"`
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

type healthPatch struct {
	Profile           *string          `yaml:"profile"`
	Concurrency       *int             `yaml:"concurrency"`
	RequestsPerSecond *float64         `yaml:"requests_per_second"`
	TopN              *int             `yaml:"top_n"`
	MaxResponseBytes  *int64           `yaml:"max_response_bytes"`
	Thresholds        *thresholdsPatch `yaml:"thresholds"`
}

type thresholdsPatch struct {
	JVM                 *percentThresholdPatch   `yaml:"jvm"`
	Memory              *percentThresholdPatch   `yaml:"memory"`
	Disk                *percentThresholdPatch   `yaml:"disk"`
	CPU                 *percentThresholdPatch   `yaml:"cpu"`
	FileDescriptors     *percentThresholdPatch   `yaml:"file_descriptors"`
	DeletedDocuments    *ratioThresholdPatch     `yaml:"deleted_documents"`
	ShardSize           *shardSizeThresholdPatch `yaml:"shard_size"`
	ShardImbalance      *variationThresholdPatch `yaml:"shard_imbalance"`
	DiskImbalance       *variationThresholdPatch `yaml:"disk_imbalance"`
	Certificate         *daysThresholdPatch      `yaml:"certificate"`
	PendingTaskWarning  *string                  `yaml:"pending_task_warning"`
	PendingTaskHigh     *string                  `yaml:"pending_task_high"`
	LongTaskWarning     *string                  `yaml:"long_task_warning"`
	BackupWarning       *string                  `yaml:"backup_warning"`
	BackupHigh          *string                  `yaml:"backup_high"`
	ThreadPoolQueueHigh *int                     `yaml:"thread_pool_queue_high"`
}

type percentThresholdPatch struct {
	Warning  *float64 `yaml:"warning"`
	High     *float64 `yaml:"high"`
	Critical *float64 `yaml:"critical"`
}

type ratioThresholdPatch struct {
	Warning *float64 `yaml:"warning"`
	High    *float64 `yaml:"high"`
}

type shardSizeThresholdPatch struct {
	Small        *string `yaml:"small"`
	LargeWarning *string `yaml:"large_warning"`
	LargeHigh    *string `yaml:"large_high"`
}

type variationThresholdPatch struct {
	Warning *float64 `yaml:"warning"`
	High    *float64 `yaml:"high"`
}

type daysThresholdPatch struct {
	Warning  *int `yaml:"warning"`
	High     *int `yaml:"high"`
	Critical *int `yaml:"critical"`
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
	if patch.Health != nil {
		if err := applyHealthPatch(&cfg.Health, patch.Health); err != nil {
			return err
		}
	}
	if patch.Output != nil && patch.Output.Format != nil {
		cfg.Output.Format = parseOutputFormat(*patch.Output.Format)
	}
	if patch.Logging != nil && patch.Logging.Level != nil {
		cfg.Logging.Level = parseLogLevel(*patch.Logging.Level)
	}
	return nil
}

func applyHealthPatch(health *HealthConfig, patch *healthPatch) error {
	if patch.Profile != nil {
		health.Profile = parseHealthProfile(*patch.Profile)
	}
	if patch.Concurrency != nil {
		health.Concurrency = *patch.Concurrency
	}
	if patch.RequestsPerSecond != nil {
		health.RequestsPerSecond = *patch.RequestsPerSecond
	}
	if patch.TopN != nil {
		health.TopN = *patch.TopN
	}
	if patch.MaxResponseBytes != nil {
		health.MaxResponseBytes = *patch.MaxResponseBytes
	}
	if patch.Thresholds == nil {
		return nil
	}
	thresholds := patch.Thresholds
	applyPercentThreshold(&health.Thresholds.JVM, thresholds.JVM)
	applyPercentThreshold(&health.Thresholds.Memory, thresholds.Memory)
	applyPercentThreshold(&health.Thresholds.Disk, thresholds.Disk)
	applyPercentThreshold(&health.Thresholds.CPU, thresholds.CPU)
	applyPercentThreshold(&health.Thresholds.FileDescriptors, thresholds.FileDescriptors)
	if thresholds.DeletedDocuments != nil {
		if thresholds.DeletedDocuments.Warning != nil {
			health.Thresholds.DeletedDocuments.Warning = *thresholds.DeletedDocuments.Warning
		}
		if thresholds.DeletedDocuments.High != nil {
			health.Thresholds.DeletedDocuments.High = *thresholds.DeletedDocuments.High
		}
	}
	if thresholds.ShardImbalance != nil {
		applyVariationThreshold(&health.Thresholds.ShardImbalance, thresholds.ShardImbalance)
	}
	if thresholds.DiskImbalance != nil {
		applyVariationThreshold(&health.Thresholds.DiskImbalance, thresholds.DiskImbalance)
	}
	if thresholds.Certificate != nil {
		if thresholds.Certificate.Warning != nil {
			health.Thresholds.Certificate.Warning = *thresholds.Certificate.Warning
		}
		if thresholds.Certificate.High != nil {
			health.Thresholds.Certificate.High = *thresholds.Certificate.High
		}
		if thresholds.Certificate.Critical != nil {
			health.Thresholds.Certificate.Critical = *thresholds.Certificate.Critical
		}
	}
	if thresholds.ShardSize != nil {
		parsers := []struct {
			name  string
			value *string
			set   func(int64)
		}{
			{"health.thresholds.shard_size.small", thresholds.ShardSize.Small, func(value int64) { health.Thresholds.ShardSize.Small = value }},
			{"health.thresholds.shard_size.large_warning", thresholds.ShardSize.LargeWarning, func(value int64) { health.Thresholds.ShardSize.LargeWarning = value }},
			{"health.thresholds.shard_size.large_high", thresholds.ShardSize.LargeHigh, func(value int64) { health.Thresholds.ShardSize.LargeHigh = value }},
		}
		for _, parser := range parsers {
			if parser.value == nil {
				continue
			}
			value, err := parseByteSize(parser.name, *parser.value)
			if err != nil {
				return err
			}
			parser.set(value)
		}
	}
	durations := []struct {
		name  string
		value *string
		set   func(time.Duration)
	}{
		{"health.thresholds.pending_task_warning", thresholds.PendingTaskWarning, func(value time.Duration) { health.Thresholds.PendingTaskWarning = value }},
		{"health.thresholds.pending_task_high", thresholds.PendingTaskHigh, func(value time.Duration) { health.Thresholds.PendingTaskHigh = value }},
		{"health.thresholds.long_task_warning", thresholds.LongTaskWarning, func(value time.Duration) { health.Thresholds.LongTaskWarning = value }},
		{"health.thresholds.backup_warning", thresholds.BackupWarning, func(value time.Duration) { health.Thresholds.BackupWarning = value }},
		{"health.thresholds.backup_high", thresholds.BackupHigh, func(value time.Duration) { health.Thresholds.BackupHigh = value }},
	}
	for _, parser := range durations {
		if parser.value == nil {
			continue
		}
		value, err := parseDuration(parser.name, *parser.value)
		if err != nil {
			return err
		}
		parser.set(value)
	}
	if thresholds.ThreadPoolQueueHigh != nil {
		health.Thresholds.ThreadPoolQueueHigh = *thresholds.ThreadPoolQueueHigh
	}
	return nil
}

func applyPercentThreshold(destination *PercentThreshold, patch *percentThresholdPatch) {
	if patch == nil {
		return
	}
	if patch.Warning != nil {
		destination.Warning = *patch.Warning
	}
	if patch.High != nil {
		destination.High = *patch.High
	}
	if patch.Critical != nil {
		destination.Critical = *patch.Critical
	}
}

func applyVariationThreshold(destination *VariationThreshold, patch *variationThresholdPatch) {
	if patch.Warning != nil {
		destination.Warning = *patch.Warning
	}
	if patch.High != nil {
		destination.High = *patch.High
	}
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
		{"GARGA_HEALTH_PROFILE", func(value string) error {
			cfg.Health.Profile = parseHealthProfile(value)
			return nil
		}},
		{"GARGA_HEALTH_CONCURRENCY", func(value string) error {
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return invalidEnvironment("GARGA_HEALTH_CONCURRENCY", "must be an integer")
			}
			cfg.Health.Concurrency = parsed
			return nil
		}},
		{"GARGA_HEALTH_RATE", func(value string) error {
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				return invalidEnvironment("GARGA_HEALTH_RATE", "must be a number")
			}
			cfg.Health.RequestsPerSecond = parsed
			return nil
		}},
		{"GARGA_HEALTH_TOP_N", func(value string) error {
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return invalidEnvironment("GARGA_HEALTH_TOP_N", "must be an integer")
			}
			cfg.Health.TopN = parsed
			return nil
		}},
		{"GARGA_HEALTH_MAX_RESPONSE_BYTES", func(value string) error {
			parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return invalidEnvironment("GARGA_HEALTH_MAX_RESPONSE_BYTES", "must be an integer byte count")
			}
			cfg.Health.MaxResponseBytes = parsed
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

func parseByteSize(field, value string) (int64, error) {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	units := []struct {
		suffix     string
		multiplier float64
	}{
		{"TIB", 1 << 40}, {"TB", 1e12},
		{"GIB", 1 << 30}, {"GB", 1e9},
		{"MIB", 1 << 20}, {"MB", 1e6},
		{"KIB", 1 << 10}, {"KB", 1e3},
		{"B", 1},
	}
	for _, unit := range units {
		if !strings.HasSuffix(normalized, unit.suffix) {
			continue
		}
		number := strings.TrimSpace(strings.TrimSuffix(normalized, unit.suffix))
		parsed, err := strconv.ParseFloat(number, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed <= 0 || parsed > float64(math.MaxInt64)/unit.multiplier {
			return 0, fmt.Errorf("invalid configuration: %s must be a positive byte size such as 1GB", field)
		}
		return int64(parsed * unit.multiplier), nil
	}
	return 0, fmt.Errorf("invalid configuration: %s must be a byte size such as 1GB", field)
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
	if overrides.HealthProfile != nil {
		cfg.Health.Profile = parseHealthProfile(string(*overrides.HealthProfile))
	}
	if overrides.HealthConcurrency != nil {
		cfg.Health.Concurrency = *overrides.HealthConcurrency
	}
	if overrides.HealthRate != nil {
		cfg.Health.RequestsPerSecond = *overrides.HealthRate
	}
	if overrides.HealthTopN != nil {
		cfg.Health.TopN = *overrides.HealthTopN
	}
	if overrides.HealthMaxResponseBytes != nil {
		cfg.Health.MaxResponseBytes = *overrides.HealthMaxResponseBytes
	}
	if overrides.OutputFormat != nil {
		cfg.Output.Format = parseOutputFormat(string(*overrides.OutputFormat))
	}
	if overrides.LogLevel != nil {
		cfg.Logging.Level = parseLogLevel(string(*overrides.LogLevel))
	}
}
