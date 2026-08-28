package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/credential/detect"
	"github.com/cumakurt/garga/internal/logging"
	"github.com/cumakurt/garga/internal/target"
	"github.com/cumakurt/garga/internal/transport"
	"github.com/spf13/cobra"
	"log/slog"
)

func newAuthDetectCommand(buildInfo BuildInfo) *cobra.Command {
	var (
		mode             string
		username         string
		credentialsStdin bool
		credentialsFile  string
		passwordsStdin   bool
		passwordsFile    string
		wordlist         string
		sprayInputStdin  bool
		usersFile        string
		charset          string
		minLength        int
		maxLength        int
		sprayDelay       time.Duration
		insecure         bool
		configPath       string
		maxAttempts      int
		stopOnSuccess    bool
	)

	cmd := &cobra.Command{
		Use:   "auth-detect TARGET",
		Short: "Run an explicit, bounded credential detection assessment",
		Long: strings.TrimSpace(`
Run an isolated, opt-in credential detection assessment against one Elasticsearch target.

This command is not part of the normal scan path. Every attempt is a GET to
/_security/_authenticate. Secrets are supplied through stdin or a local list file;
garga does not accept a --password flag because command-line secrets can appear in
process listings, shell history, and audit logs. List file paths may appear in
process listings; file contents are not logged.

Modes:

  stuffing      Try explicit username+password pairs (credential stuffing).
  spraying      Try each password across every username before the next password.
  brute-force   Try many passwords, or a bounded charset, against one username.
  dictionary    Try a wordlist against one username.

Input:

  stuffing:
    garga auth-detect TARGET --mode stuffing --credentials-stdin
    garga auth-detect TARGET --mode stuffing --credentials-file pairs.txt

    Lines:
      basic USERNAME PASSWORD
      USERNAME:PASSWORD
      USERNAME,PASSWORD
      USERNAME PASSWORD

  spraying:
    garga auth-detect TARGET --mode spraying --spray-input-stdin
    garga auth-detect TARGET --mode spraying --users-file users.txt --passwords-file passwords.txt

    Structured stdin:
      @users
      elastic
      admin
      @passwords
      password
      changeme

  brute-force:
    garga auth-detect TARGET --mode brute-force --username USER --passwords-stdin
    garga auth-detect TARGET --mode brute-force --username USER --passwords-file passwords.txt
    garga auth-detect TARGET --mode brute-force --username USER --charset digits --min-length 1 --max-length 2

  dictionary:
    garga auth-detect TARGET --mode dictionary --username USER --wordlist wordlist.txt
    garga auth-detect TARGET --mode dictionary --username USER --passwords-stdin

A per-host attempt ceiling and a 1 request/second default rate apply to every
request, including retries. Spraying can add --spray-delay after each password
round. The run stops on the first valid credential unless --no-stop-on-success
is set. Exhausted HTTP 429 responses stop the run as rate_limited.
`),
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuthDetect(cmd, buildInfo, authDetectOptions{
				target:           args[0],
				mode:             mode,
				username:         username,
				credentialsStdin: credentialsStdin,
				credentialsFile:  credentialsFile,
				passwordsStdin:   passwordsStdin,
				passwordsFile:    passwordsFile,
				wordlist:         wordlist,
				sprayInputStdin:  sprayInputStdin,
				usersFile:        usersFile,
				charset:          charset,
				minLength:        minLength,
				maxLength:        maxLength,
				sprayDelay:       sprayDelay,
				insecure:         insecure,
				configPath:       configPath,
				maxAttempts:      maxAttempts,
				stopOnSuccess:    stopOnSuccess,
			})
		},
	}
	cmd.Flags().StringVar(&mode, "mode", "", "detection mode: stuffing, spraying, brute-force, or dictionary")
	cmd.Flags().StringVar(&username, "username", "", "target username for brute-force or dictionary mode")
	cmd.Flags().BoolVar(&credentialsStdin, "credentials-stdin", false, "read credential pairs from stdin for stuffing mode")
	cmd.Flags().StringVar(&credentialsFile, "credentials-file", "", "read credential pairs from a local file for stuffing mode")
	cmd.Flags().BoolVar(&passwordsStdin, "passwords-stdin", false, "read a password list from stdin")
	cmd.Flags().StringVar(&passwordsFile, "passwords-file", "", "read a password list from a local file")
	cmd.Flags().StringVar(&wordlist, "wordlist", "", "read a dictionary wordlist from a local file")
	cmd.Flags().BoolVar(&sprayInputStdin, "spray-input-stdin", false, "read structured @users/@passwords stdin for spraying mode")
	cmd.Flags().StringVar(&usersFile, "users-file", "", "read usernames from a local file for spraying mode")
	cmd.Flags().StringVar(&charset, "charset", "", "brute-force alphabet: digits, lower, upper, alnum, or a custom set")
	cmd.Flags().IntVar(&minLength, "min-length", 1, "minimum generated password length for brute-force charset mode")
	cmd.Flags().IntVar(&maxLength, "max-length", 1, "maximum generated password length for brute-force charset mode")
	cmd.Flags().DurationVar(&sprayDelay, "spray-delay", 0, "extra delay after each spraying password round")
	cmd.Flags().IntVar(&maxAttempts, "max-attempts", detect.DefaultMaxAttemptsPerHost, "maximum authenticate requests per host")
	cmd.Flags().BoolVar(&stopOnSuccess, "stop-on-success", true, "stop after the first valid credential")
	cmd.Flags().Bool("no-stop-on-success", false, "continue after the first valid credential")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS certificate verification")
	cmd.Flags().StringVar(&configPath, "config", "", "optional configuration file")
	return cmd
}

type authDetectOptions struct {
	target           string
	mode             string
	username         string
	credentialsStdin bool
	credentialsFile  string
	passwordsStdin   bool
	passwordsFile    string
	wordlist         string
	sprayInputStdin  bool
	usersFile        string
	charset          string
	minLength        int
	maxLength        int
	sprayDelay       time.Duration
	insecure         bool
	configPath       string
	maxAttempts      int
	stopOnSuccess    bool
}

func runAuthDetect(cmd *cobra.Command, buildInfo BuildInfo, options authDetectOptions) error {
	parsedMode, err := detect.ParseMode(options.mode)
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid credential detection mode", cause: err}
	}
	if noStop, _ := cmd.Flags().GetBool("no-stop-on-success"); noStop {
		options.stopOnSuccess = false
	}

	parsed, err := target.Parse(options.target, "cli")
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid target", cause: err}
	}
	endpoint, err := target.Endpoint(parsed)
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid target", cause: err}
	}

	input, err := loadDetectionInput(cmd, parsedMode, options)
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid credential detection input", cause: err}
	}

	detectOptions := detect.Defaults()
	detectOptions.Mode = parsedMode
	detectOptions.MaxAttemptsPerHost = options.maxAttempts
	detectOptions.StopOnSuccess = options.stopOnSuccess
	if parsedMode == detect.ModeSpraying {
		detectOptions.SprayRoundSize = len(input.Users)
		detectOptions.SprayRoundDelay = options.sprayDelay
	} else if options.sprayDelay > 0 {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid credential detection options", cause: fmt.Errorf("--spray-delay applies only to spraying mode")}
	}
	if err := detectOptions.Validate(); err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid credential detection options", cause: err}
	}

	planned, err := detect.BuildSecrets(detectOptions, input)
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid credential detection plan", cause: err}
	}
	defer destroySecrets(planned)

	cfg, err := config.Load(config.Options{ConfigPath: options.configPath})
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid configuration", cause: err}
	}
	transportOptions, err := transport.OptionsFromConfig(cfg, "garga/"+buildInfo.Version)
	if err != nil {
		return &executionError{exitCode: ExitInternalError, message: "invalid transport options", cause: err}
	}
	transportOptions.InsecureSkipVerify = options.insecure
	factory, err := transport.NewFactory(transportOptions)
	if err != nil {
		return &executionError{exitCode: ExitInternalError, message: "create HTTP transport", cause: err}
	}
	defer factory.CloseIdleConnections()

	verifier, err := credential.NewVerifier(factory.Client())
	if err != nil {
		return &executionError{exitCode: ExitInternalError, message: "create credential verifier", cause: err}
	}
	engine, err := detect.New(detectOptions, verifier)
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid credential detection options", cause: err}
	}

	report, err := engine.Run(cmd.Context(), endpoint, planned)
	if writeErr := writeDetectReport(cmd.OutOrStdout(), report, planned); writeErr != nil {
		return &executionError{exitCode: ExitInternalError, message: "write auth-detect result", cause: writeErr}
	}
	if err != nil {
		if cmd.Context().Err() != nil {
			return cmd.Context().Err()
		}
		return &executionError{exitCode: ExitInternalError, message: "credential detection failed", cause: err}
	}
	newLogger(cfg.Logging.Level, cmd.ErrOrStderr(), planned...).Debug(
		"auth-detect completed",
		logging.Bounded("mode", string(report.Mode),
			string(detect.ModeStuffing),
			string(detect.ModeSpraying),
			string(detect.ModeBruteForce),
			string(detect.ModeDictionary),
		),
		logging.Bounded("stop_reason", string(report.StopReason),
			string(detect.StopCompleted),
			string(detect.StopSuccess),
			string(detect.StopCeiling),
			string(detect.StopUnavailable),
			string(detect.StopCanceled),
			string(detect.StopRateLimited),
		),
		slog.Int("attempts", report.Attempts),
		slog.Int("planned", report.Planned),
		slog.Int("valid", len(report.ValidUsernames)),
	)
	return nil
}

func loadDetectionInput(cmd *cobra.Command, mode detect.Mode, options authDetectOptions) (detect.Input, error) {
	stdin := cmd.InOrStdin()
	switch mode {
	case detect.ModeStuffing:
		return loadStuffingInput(stdin, options)
	case detect.ModeSpraying:
		return loadSprayingInput(stdin, options)
	case detect.ModeBruteForce:
		return loadBruteForceInput(stdin, options)
	case detect.ModeDictionary:
		return loadDictionaryInput(stdin, options)
	default:
		return detect.Input{}, fmt.Errorf("unsupported mode %q", mode)
	}
}

func loadStuffingInput(stdin io.Reader, options authDetectOptions) (detect.Input, error) {
	if options.passwordsStdin || options.passwordsFile != "" || options.sprayInputStdin ||
		options.usersFile != "" || options.username != "" || options.wordlist != "" || options.charset != "" {
		return detect.Input{}, fmt.Errorf("stuffing mode accepts only --credentials-stdin or --credentials-file")
	}
	reader, closer, err := exclusiveReader(stdin, options.credentialsStdin, options.credentialsFile, "stuffing")
	if err != nil {
		return detect.Input{}, err
	}
	defer closer()
	pairs, err := detect.ParsePairs(reader)
	if err != nil {
		return detect.Input{}, err
	}
	return detect.Input{Pairs: pairs}, nil
}

func loadSprayingInput(stdin io.Reader, options authDetectOptions) (detect.Input, error) {
	if options.credentialsStdin || options.credentialsFile != "" || options.username != "" ||
		options.wordlist != "" || options.charset != "" {
		return detect.Input{}, fmt.Errorf("spraying mode accepts --spray-input-stdin or --users-file with a password source")
	}
	if options.sprayInputStdin {
		if options.usersFile != "" || options.passwordsFile != "" || options.passwordsStdin {
			return detect.Input{}, fmt.Errorf("spraying mode accepts either --spray-input-stdin or list files")
		}
		users, passwords, err := detect.ParseStructuredSprayInput(stdin)
		if err != nil {
			return detect.Input{}, err
		}
		return detect.Input{Users: users, Passwords: passwords}, nil
	}
	if options.usersFile == "" {
		return detect.Input{}, fmt.Errorf("spraying mode requires --spray-input-stdin or --users-file")
	}
	users, err := parseUsersFile(options.usersFile)
	if err != nil {
		return detect.Input{}, err
	}
	passwords, err := parsePasswordSource(stdin, options.passwordsStdin, options.passwordsFile, "spraying")
	if err != nil {
		return detect.Input{}, err
	}
	return detect.Input{Users: users, Passwords: passwords}, nil
}

func loadBruteForceInput(stdin io.Reader, options authDetectOptions) (detect.Input, error) {
	if options.username == "" {
		return detect.Input{}, fmt.Errorf("brute-force mode requires --username")
	}
	if options.credentialsStdin || options.credentialsFile != "" || options.sprayInputStdin ||
		options.usersFile != "" || options.wordlist != "" {
		return detect.Input{}, fmt.Errorf("brute-force mode accepts --passwords-stdin, --passwords-file, or --charset")
	}
	if options.charset != "" {
		if options.passwordsStdin || options.passwordsFile != "" {
			return detect.Input{}, fmt.Errorf("brute-force charset cannot be combined with a password list")
		}
		return detect.Input{
			Username:  options.username,
			Charset:   options.charset,
			MinLength: options.minLength,
			MaxLength: options.maxLength,
		}, nil
	}
	passwords, err := parsePasswordSource(stdin, options.passwordsStdin, options.passwordsFile, "brute-force")
	if err != nil {
		return detect.Input{}, err
	}
	return detect.Input{Username: options.username, Passwords: passwords}, nil
}

func loadDictionaryInput(stdin io.Reader, options authDetectOptions) (detect.Input, error) {
	if options.username == "" {
		return detect.Input{}, fmt.Errorf("dictionary mode requires --username")
	}
	if options.credentialsStdin || options.credentialsFile != "" || options.sprayInputStdin ||
		options.usersFile != "" || options.charset != "" || options.passwordsFile != "" {
		return detect.Input{}, fmt.Errorf("dictionary mode accepts --wordlist or --passwords-stdin")
	}
	if options.wordlist != "" {
		if options.passwordsStdin {
			return detect.Input{}, fmt.Errorf("dictionary mode accepts either --wordlist or --passwords-stdin")
		}
		passwords, err := parsePasswordsFile(options.wordlist)
		if err != nil {
			return detect.Input{}, err
		}
		return detect.Input{Username: options.username, Passwords: passwords}, nil
	}
	if !options.passwordsStdin {
		return detect.Input{}, fmt.Errorf("dictionary mode requires --wordlist or --passwords-stdin")
	}
	passwords, err := detect.ParsePasswords(stdin)
	if err != nil {
		return detect.Input{}, err
	}
	return detect.Input{Username: options.username, Passwords: passwords}, nil
}

func parsePasswordSource(stdin io.Reader, fromStdin bool, path, mode string) ([][]byte, error) {
	if fromStdin && path != "" {
		return nil, fmt.Errorf("%s mode accepts either --passwords-stdin or --passwords-file", mode)
	}
	if fromStdin {
		return detect.ParsePasswords(stdin)
	}
	if path == "" {
		return nil, fmt.Errorf("%s mode requires a password list", mode)
	}
	return parsePasswordsFile(path)
}

func parseUsersFile(path string) ([]string, error) {
	file, err := openDetectListFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return detect.ParseUsers(file)
}

func parsePasswordsFile(path string) ([][]byte, error) {
	file, err := openDetectListFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return detect.ParsePasswords(file)
}

func exclusiveReader(stdin io.Reader, fromStdin bool, path, mode string) (io.Reader, func(), error) {
	if fromStdin && path != "" {
		return nil, func() {}, fmt.Errorf("%s mode accepts either stdin or a list file", mode)
	}
	if fromStdin {
		return stdin, func() {}, nil
	}
	if path == "" {
		return nil, func() {}, fmt.Errorf("%s mode requires stdin or a list file", mode)
	}
	file, err := openDetectListFile(path)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { _ = file.Close() }, nil
}

func openDetectListFile(path string) (*os.File, error) {
	if path == "" || path == "-" {
		return nil, fmt.Errorf("list file path is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open list file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat list file: %w", err)
	}
	if info.IsDir() {
		_ = file.Close()
		return nil, fmt.Errorf("list file path is a directory")
	}
	return file, nil
}

func writeDetectReport(stdout io.Writer, report detect.Report, secrets []*credential.Secret) error {
	for _, event := range report.Events {
		line := redactAuditText(detect.FormatEvent(event), secrets)
		if _, err := fmt.Fprintln(stdout, line); err != nil {
			return err
		}
	}
	if report.StopReason == "" {
		return nil
	}
	_, err := fmt.Fprintln(stdout, redactAuditText(detect.FormatSummary(report), secrets))
	return err
}
