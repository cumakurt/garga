package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/secrets"
	"github.com/cumakurt/garga/internal/target"
	"github.com/spf13/cobra"
)

func newSecretsCommand(buildInfo BuildInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Discover sensitive data in authorized Elasticsearch indices",
		Long: strings.TrimSpace(`
Scan authorized Elasticsearch clusters for sensitive values in mappings and
sampled documents. The command is read-only: it never creates, updates, or
deletes indices, documents, or cluster settings.

Use only against clusters you own or are explicitly authorized to assess.
Table, JSON, JSONL, SARIF, and the timestamped PDF artifact all render
the same canonical masked findings. Raw discovered values are discarded before
the report model is created.

Authentication secrets are read from environment variables named by
--password-env, --api-key-env, or --bearer-token-env. There is no --password
flag.
`),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsScan(cmd, buildInfo, args)
		},
	}
	bindSecretsFlags(cmd)
	cmd.AddCommand(newSecretsGenerateCommand(buildInfo))
	return cmd
}

func newSecretsGenerateCommand(buildInfo BuildInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Write synthetic sensitive-data fixtures to a local test index",
		Long: strings.TrimSpace(`
Index clearly fake credentials into garga-sensitive-test on one authorized
local Elasticsearch target. Documents are labeled as synthetic test data.
Never point this command at a production cluster.
`),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsGenerate(cmd, buildInfo, args)
		},
	}
	bindSecretsFlags(cmd)
	return cmd
}

type secretsFlags struct {
	targets              []string
	targetsFile          string
	user                 string
	username             string
	passwordEnv          string
	apiKeyEnv            string
	bearerTokenEnv       string
	caCert               string
	clientCert           string
	clientKey            string
	insecure             bool
	allowPlaintextAuth   bool
	timeout              time.Duration
	concurrency          int
	rateLimit            float64
	sampleSize           int
	maxDocuments         int
	indices              []string
	excludeIndices       []string
	includeSystemIndices bool
	output               string
	format               string
	minConfidence        string
	verbose              bool
	maxDepth             int
	maxArrayItems        int
	maxFieldBytes        int
	deepScan             bool
	deepSampleSize       int
	deepMaxDocuments     int
	deepMaxFieldBytes    int
	deepMaxDepth         int
	deepMaxArrayItems    int
}

func bindSecretsFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringArray("target", nil, "Elasticsearch URL (repeatable)")
	flags.String("targets", "", "file containing Elasticsearch URLs, one per line")
	flags.String("user", "", "Basic Auth username")
	flags.String("username", "", "alias for --user")
	flags.String("password-env", "", "environment variable name that holds the Basic Auth password")
	flags.String("api-key-env", "", "environment variable name that holds the API key")
	flags.String("bearer-token-env", "", "environment variable name that holds the Bearer token")
	flags.String("ca-cert", "", "PEM CA certificate file")
	flags.String("client-cert", "", "PEM client certificate file")
	flags.String("client-key", "", "PEM client private key file")
	flags.Bool("insecure", false, "skip TLS certificate verification")
	flags.Bool("allow-plaintext-auth", false, "allow credentials over HTTP (unsafe)")
	flags.Duration("timeout", secrets.DefaultTimeout, "overall scan timeout")
	flags.Int("concurrency", secrets.DefaultConcurrency, "maximum concurrent Elasticsearch targets")
	flags.Float64("rate-limit", secrets.DefaultRateLimit, "maximum requests per second per target")
	flags.Int("sample-size", secrets.DefaultSampleSize, "maximum documents sampled per index")
	flags.Int("max-documents", secrets.DefaultMaxDocuments, "maximum documents sampled across the run")
	flags.StringSlice("indices", nil, "index names or globs to include")
	flags.StringSlice("exclude-indices", nil, "index names or globs to exclude")
	flags.Bool("include-system-indices", false, "include indices whose names start with '.'")
	flags.String("output", "", "write the masked report to a file instead of stdout")
	flags.String("format", "table", "output format: json, jsonl, table, or sarif")
	flags.String("min-confidence", "medium", "lowest confidence to report: low, medium, high, or confirmed-pattern")
	flags.Bool("verbose", false, "emit redacted debug logs on stderr")
	flags.Int("max-depth", secrets.DefaultMaxDepth, "maximum nested object depth")
	flags.Int("max-array-items", secrets.DefaultMaxArrayItems, "maximum array items inspected per field")
	flags.Int("max-field-bytes", secrets.DefaultMaxFieldBytes, "maximum bytes inspected per text field")
	flags.Bool("deep-scan", false, "enable bounded deep scan (higher sample limits, generic field analysis, broader correlation)")
	flags.Int("deep-sample-size", secrets.DefaultDeepSampleSize, "deep-scan documents sampled per index")
	flags.Int("deep-max-documents", secrets.DefaultDeepMaxDocuments, "deep-scan maximum documents across the run")
	flags.Int("deep-max-field-bytes", secrets.DefaultDeepMaxFieldBytes, "deep-scan maximum bytes inspected per text field")
	flags.Int("deep-max-depth", secrets.DefaultDeepMaxDepth, "deep-scan maximum nested object depth")
	flags.Int("deep-max-array-items", secrets.DefaultDeepMaxArrayItems, "deep-scan maximum array items inspected per field")
}

func readSecretsFlags(cmd *cobra.Command) (secretsFlags, error) {
	var options secretsFlags
	flags := cmd.Flags()
	var err error
	if options.targets, err = flags.GetStringArray("target"); err != nil {
		return options, err
	}
	if options.targetsFile, err = flags.GetString("targets"); err != nil {
		return options, err
	}
	if options.user, err = flags.GetString("user"); err != nil {
		return options, err
	}
	if options.username, err = flags.GetString("username"); err != nil {
		return options, err
	}
	if options.passwordEnv, err = flags.GetString("password-env"); err != nil {
		return options, err
	}
	if options.apiKeyEnv, err = flags.GetString("api-key-env"); err != nil {
		return options, err
	}
	if options.bearerTokenEnv, err = flags.GetString("bearer-token-env"); err != nil {
		return options, err
	}
	if options.caCert, err = flags.GetString("ca-cert"); err != nil {
		return options, err
	}
	if options.clientCert, err = flags.GetString("client-cert"); err != nil {
		return options, err
	}
	if options.clientKey, err = flags.GetString("client-key"); err != nil {
		return options, err
	}
	if options.insecure, err = flags.GetBool("insecure"); err != nil {
		return options, err
	}
	if options.allowPlaintextAuth, err = flags.GetBool("allow-plaintext-auth"); err != nil {
		return options, err
	}
	if options.timeout, err = flags.GetDuration("timeout"); err != nil {
		return options, err
	}
	if options.concurrency, err = flags.GetInt("concurrency"); err != nil {
		return options, err
	}
	if options.rateLimit, err = flags.GetFloat64("rate-limit"); err != nil {
		return options, err
	}
	if options.sampleSize, err = flags.GetInt("sample-size"); err != nil {
		return options, err
	}
	if options.maxDocuments, err = flags.GetInt("max-documents"); err != nil {
		return options, err
	}
	if options.indices, err = flags.GetStringSlice("indices"); err != nil {
		return options, err
	}
	if options.excludeIndices, err = flags.GetStringSlice("exclude-indices"); err != nil {
		return options, err
	}
	if options.includeSystemIndices, err = flags.GetBool("include-system-indices"); err != nil {
		return options, err
	}
	if options.output, err = flags.GetString("output"); err != nil {
		return options, err
	}
	if options.format, err = flags.GetString("format"); err != nil {
		return options, err
	}
	if options.minConfidence, err = flags.GetString("min-confidence"); err != nil {
		return options, err
	}
	if options.verbose, err = flags.GetBool("verbose"); err != nil {
		return options, err
	}
	if options.maxDepth, err = flags.GetInt("max-depth"); err != nil {
		return options, err
	}
	if options.maxArrayItems, err = flags.GetInt("max-array-items"); err != nil {
		return options, err
	}
	if options.maxFieldBytes, err = flags.GetInt("max-field-bytes"); err != nil {
		return options, err
	}
	if options.deepScan, err = flags.GetBool("deep-scan"); err != nil {
		return options, err
	}
	if options.deepSampleSize, err = flags.GetInt("deep-sample-size"); err != nil {
		return options, err
	}
	if options.deepMaxDocuments, err = flags.GetInt("deep-max-documents"); err != nil {
		return options, err
	}
	if options.deepMaxFieldBytes, err = flags.GetInt("deep-max-field-bytes"); err != nil {
		return options, err
	}
	if options.deepMaxDepth, err = flags.GetInt("deep-max-depth"); err != nil {
		return options, err
	}
	if options.deepMaxArrayItems, err = flags.GetInt("deep-max-array-items"); err != nil {
		return options, err
	}
	return options, nil
}

func runSecretsScan(cmd *cobra.Command, buildInfo BuildInfo, args []string) error {
	flags, err := readSecretsFlags(cmd)
	if err != nil {
		return secretsInputError("invalid secrets flags", err)
	}
	targets, err := collectSecretsTargets(flags, args)
	if err != nil {
		return err
	}
	secret, err := secretsSecret(flags)
	if err != nil {
		return err
	}
	if secret != nil {
		defer secret.Destroy()
	}
	options, err := secretsEngineOptions(cmd, flags)
	if err != nil {
		return err
	}
	format, err := secrets.ParseFormat(flags.format)
	if err != nil {
		return secretsInputError(err.Error(), nil)
	}
	level := config.DefaultLogLevel
	if flags.verbose {
		level = config.LogDebug
	}
	logger := newLogger(level, cmd.ErrOrStderr(), secret)
	engine, err := secrets.NewEngine(options, secret, "garga/"+buildInfo.normalized().Version, logger)
	if err != nil {
		return secretsInputError(err.Error(), nil)
	}
	result, err := engine.Scan(cmd.Context(), targets)
	if err != nil {
		return classifySecretsError(err)
	}
	artifactPath, err := secrets.WriteTimestampedPDF(result)
	if err != nil {
		return &executionError{exitCode: ExitInternalError, message: "write timestamped secrets PDF report", cause: err}
	}
	if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "garga: PDF secrets report written to %s\n", artifactPath); err != nil {
		return &executionError{exitCode: ExitInternalError, message: "write secrets report notice", cause: err}
	}
	if format != secrets.FormatTable {
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), secrets.FormatSummary(result.Summary)); err != nil {
			return &executionError{exitCode: ExitInternalError, message: "write secrets summary", cause: err}
		}
	}
	if path := strings.TrimSpace(flags.output); path != "" {
		if err := secrets.WriteReportFile(path, format, result); err != nil {
			return &executionError{exitCode: ExitInternalError, message: "write secrets report file", cause: err}
		}
	} else if err := secrets.WriteReport(cmd.OutOrStdout(), format, result); err != nil {
		return &executionError{exitCode: ExitInternalError, message: "write secrets report", cause: err}
	}
	if result.Summary.PartialFailures > 0 && result.Summary.ReachableTargets == 0 {
		return &executionError{exitCode: ExitInternalError, message: "secrets scan failed for all targets"}
	}
	if result.Summary.PartialFailures > 0 {
		return &executionError{exitCode: ExitPartialFailure, message: "secrets scan completed with partial failures"}
	}
	return nil
}

func runSecretsGenerate(cmd *cobra.Command, buildInfo BuildInfo, args []string) error {
	flags, err := readSecretsFlags(cmd)
	if err != nil {
		return secretsInputError("invalid secrets flags", err)
	}
	targets, err := collectSecretsTargets(flags, args)
	if err != nil {
		return err
	}
	if len(targets) != 1 {
		return secretsInputError("secrets generate requires exactly one target", nil)
	}
	secret, err := secretsSecret(flags)
	if err != nil {
		return err
	}
	if secret != nil {
		defer secret.Destroy()
	}
	options, err := secretsEngineOptions(cmd, flags)
	if err != nil {
		return err
	}
	parsed, err := target.Parse(targets[0], "cli")
	if err != nil {
		return secretsInputError("invalid secrets target", err)
	}
	endpoint, err := target.Endpoint(parsed)
	if err != nil {
		return secretsInputError("invalid secrets target", err)
	}
	count, err := secrets.Generate(cmd.Context(), endpoint, secret, options, "garga/"+buildInfo.normalized().Version)
	if err != nil {
		return classifySecretsError(err)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "indexed %d synthetic documents into %s\n", count, secrets.TestIndex)
	return err
}

func collectSecretsTargets(flags secretsFlags, args []string) ([]string, error) {
	var targets []string
	targets = append(targets, flags.targets...)
	targets = append(targets, args...)
	if path := strings.TrimSpace(flags.targetsFile); path != "" {
		file, err := os.Open(path)
		if err != nil {
			return nil, secretsInputError("read --targets file", err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			targets = append(targets, line)
		}
		if err := scanner.Err(); err != nil {
			return nil, secretsInputError("read --targets file", err)
		}
	}
	if len(targets) == 0 {
		return nil, secretsInputError("at least one --target, --targets file, or positional URL is required", nil)
	}
	return targets, nil
}

func secretsEngineOptions(cmd *cobra.Command, flags secretsFlags) (secrets.Options, error) {
	confidence, err := secrets.ParseConfidence(flags.minConfidence)
	if err != nil {
		return secrets.Options{}, secretsInputError(err.Error(), nil)
	}
	changed := cmd.Flags().Changed
	if !flags.deepScan {
		for _, name := range []string{"deep-sample-size", "deep-max-documents", "deep-max-field-bytes", "deep-max-depth", "deep-max-array-items"} {
			if changed(name) {
				return secrets.Options{}, secretsInputError("--"+name+" requires --deep-scan", nil)
			}
		}
	}
	user := strings.TrimSpace(flags.user)
	if user == "" {
		user = strings.TrimSpace(flags.username)
	}
	options := secrets.Options{
		User:                 user,
		PasswordEnv:          strings.TrimSpace(flags.passwordEnv),
		APIKeyEnv:            strings.TrimSpace(flags.apiKeyEnv),
		BearerTokenEnv:       strings.TrimSpace(flags.bearerTokenEnv),
		CACert:               flags.caCert,
		ClientCert:           flags.clientCert,
		ClientKey:            flags.clientKey,
		Insecure:             flags.insecure,
		AllowPlaintextAuth:   flags.allowPlaintextAuth,
		Timeout:              flags.timeout,
		Concurrency:          flags.concurrency,
		RateLimit:            flags.rateLimit,
		SampleSize:           flags.sampleSize,
		MaxDocuments:         flags.maxDocuments,
		Indices:              flags.indices,
		ExcludeIndices:       flags.excludeIndices,
		IncludeSystemIndices: flags.includeSystemIndices,
		MinConfidence:        confidence,
		Verbose:              flags.verbose,
		MaxDepth:             flags.maxDepth,
		MaxArrayItems:        flags.maxArrayItems,
		MaxFieldBytes:        flags.maxFieldBytes,
	}
	profile := secrets.NormalProfile()
	if flags.deepScan {
		profile = secrets.DeepScanProfile()
		if changed("deep-sample-size") && !changed("sample-size") {
			options.SampleSize = flags.deepSampleSize
		}
		if changed("deep-max-documents") && !changed("max-documents") {
			options.MaxDocuments = flags.deepMaxDocuments
		}
		if changed("deep-max-field-bytes") && !changed("max-field-bytes") {
			options.MaxFieldBytes = flags.deepMaxFieldBytes
		}
		if changed("deep-max-depth") && !changed("max-depth") {
			options.MaxDepth = flags.deepMaxDepth
		}
		if changed("deep-max-array-items") && !changed("max-array-items") {
			options.MaxArrayItems = flags.deepMaxArrayItems
		}
	}
	secrets.ApplyProfile(&options, profile, secrets.ProfileOverrides{
		SampleSize:    changed("sample-size") || (flags.deepScan && changed("deep-sample-size")),
		MaxDocuments:  changed("max-documents") || (flags.deepScan && changed("deep-max-documents")),
		MaxFieldBytes: changed("max-field-bytes") || (flags.deepScan && changed("deep-max-field-bytes")),
		MaxDepth:      changed("max-depth") || (flags.deepScan && changed("deep-max-depth")),
		MaxArrayItems: changed("max-array-items") || (flags.deepScan && changed("deep-max-array-items")),
	})
	return options, nil
}

func secretsSecret(flags secretsFlags) (*credential.Secret, error) {
	user := strings.TrimSpace(flags.user)
	if user == "" {
		user = strings.TrimSpace(flags.username)
	}
	mechanisms := 0
	for _, name := range []string{flags.passwordEnv, flags.apiKeyEnv, flags.bearerTokenEnv} {
		if strings.TrimSpace(name) != "" {
			mechanisms++
		}
	}
	if mechanisms > 1 {
		return nil, secretsInputError("select only one secrets authentication mechanism", nil)
	}
	if mechanisms == 0 {
		if user != "" {
			return nil, secretsInputError("--user requires --password-env", nil)
		}
		return nil, nil
	}
	readEnv := func(name string) ([]byte, error) {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, secretsInputError("environment variable name is required", nil)
		}
		value, ok := os.LookupEnv(name)
		if !ok || value == "" {
			return nil, secretsInputError("environment variable "+name+" is not set", nil)
		}
		return []byte(value), nil
	}
	switch {
	case strings.TrimSpace(flags.passwordEnv) != "":
		if user == "" {
			return nil, secretsInputError("--password-env requires --user", nil)
		}
		value, err := readEnv(flags.passwordEnv)
		if err != nil {
			return nil, err
		}
		secret, createErr := credential.NewBasic(user, value)
		if createErr != nil {
			return nil, secretsInputError("invalid Basic Auth credential", createErr)
		}
		return secret, nil
	case strings.TrimSpace(flags.apiKeyEnv) != "":
		value, err := readEnv(flags.apiKeyEnv)
		if err != nil {
			return nil, err
		}
		secret, createErr := credential.NewAPIKey(value)
		if createErr != nil {
			return nil, secretsInputError("invalid API key", createErr)
		}
		return secret, nil
	default:
		value, err := readEnv(flags.bearerTokenEnv)
		if err != nil {
			return nil, err
		}
		secret, createErr := credential.NewBearer(value)
		if createErr != nil {
			return nil, secretsInputError("invalid Bearer token", createErr)
		}
		return secret, nil
	}
}

func secretsInputError(message string, cause error) error {
	return &executionError{exitCode: ExitInvalidInput, message: message, cause: cause}
}

func classifySecretsError(err error) error {
	if err == nil {
		return nil
	}
	return &executionError{exitCode: ExitInternalError, message: "secrets scan failed", cause: err}
}
