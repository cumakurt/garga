package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/health/checker"
	"github.com/cumakurt/garga/internal/health/collector"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/health/normalize"
	healthreport "github.com/cumakurt/garga/internal/health/report"
	basemodel "github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/transport"
	"github.com/cumakurt/garga/internal/vulnerability"
)

type Options struct {
	Config             config.Config
	Endpoint           basemodel.Endpoint
	Secret             *credential.Secret
	Deep               bool
	Insecure           bool
	AllowPlaintextAuth bool
	UserAgent          string
	ScannerVersion     string
	Baseline           *healthmodel.Baseline
	Logger             *slog.Logger
	Now                func() time.Time
	SignatureDir       string
	AssessmentMode     bool
}

type Result struct {
	Report   healthmodel.Report
	Baseline healthmodel.Baseline
}

func Run(ctx context.Context, options Options) (Result, error) {
	if ctx == nil {
		return Result{}, &Error{Kind: ErrorConfiguration, Cause: errors.New("context is required")}
	}
	if err := options.Config.Validate(); err != nil {
		return Result{}, &Error{Kind: ErrorConfiguration, Cause: err}
	}
	if _, err := options.Endpoint.URL(); err != nil {
		return Result{}, &Error{Kind: ErrorConfiguration, Cause: err}
	}
	if options.Secret != nil && options.Endpoint.Scheme == basemodel.SchemeHTTP && !options.AllowPlaintextAuth {
		return Result{}, &Error{Kind: ErrorConfiguration, Cause: errors.New("refusing to send credentials over plaintext HTTP without explicit override")}
	}
	var signatures []vulnerability.Signature
	if options.AssessmentMode {
		var err error
		if options.SignatureDir == "" {
			signatures, err = vulnerability.LoadBundled()
		} else {
			signatures, err = vulnerability.LoadDir(options.SignatureDir)
		}
		if err != nil {
			return Result{}, &Error{Kind: ErrorConfiguration, Cause: fmt.Errorf("invalid vulnerability signature corpus: %w", err)}
		}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	started := options.Now()
	transportOptions, err := transport.OptionsFromConfig(options.Config, options.UserAgent)
	if err != nil {
		return Result{}, &Error{Kind: ErrorConfiguration, Cause: err}
	}
	transportOptions.InsecureSkipVerify = options.Insecure
	transportOptions.MaxResponseBytes = options.Config.Health.MaxResponseBytes
	transportOptions.MaxIdleConnectionsPerHost = options.Config.Health.Concurrency
	if transportOptions.MaxIdleConnections < transportOptions.MaxIdleConnectionsPerHost {
		transportOptions.MaxIdleConnections = transportOptions.MaxIdleConnectionsPerHost
	}
	factory, err := transport.NewFactory(transportOptions)
	if err != nil {
		return Result{}, &Error{Kind: ErrorConfiguration, Cause: err}
	}
	defer factory.CloseIdleConnections()

	dataCollector, err := collector.New(collector.Options{
		Endpoint: options.Endpoint, Client: factory.Client(), Secret: options.Secret, Deep: options.Deep,
		Concurrency: options.Config.Health.Concurrency, Rate: options.Config.Health.RequestsPerSecond, Retries: options.Config.Scanner.Retries,
	})
	if err != nil {
		return Result{}, classifyCollectorError(err)
	}
	responses, err := dataCollector.Collect(ctx)
	if err != nil {
		return Result{}, classifyCollectorError(err)
	}
	timestamp := options.Now()
	snapshot, err := normalize.Build(responses, options.Endpoint, options.Secret != nil, timestamp)
	if err != nil {
		return Result{}, &Error{Kind: ErrorProduct, Cause: err}
	}
	snapshot.Security.AllowPlaintextAuth = options.AllowPlaintextAuth
	if options.Baseline != nil {
		if err := validateBaseline(snapshot, options.Baseline); err != nil {
			return Result{}, &Error{Kind: ErrorConfiguration, Cause: err}
		}
		snapshot.Baseline = options.Baseline
	}
	registry, err := checker.DefaultRegistry(options.Config.Health, signatures...)
	if err != nil {
		return Result{}, &Error{Kind: ErrorInternal, Cause: err}
	}
	findings, checks := registry.Evaluate(ctx, snapshot)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	duration := options.Now().Sub(started)
	report := healthreport.Build(snapshot, findings, checks, healthreport.BuildOptions{
		ScannerVersion: options.ScannerVersion, Profile: options.Config.Health.Profile, Deep: options.Deep, Duration: duration, TopN: options.Config.Health.TopN, AssessmentMode: options.AssessmentMode,
	})
	if options.Logger != nil {
		options.Logger.Debug("health assessment completed",
			slog.Int("findings", len(report.Findings)), slog.Int("score", report.Summary.HealthScore),
			slog.Int("requests", report.Metadata.APIRequests), slog.Int("failed_requests", report.Metadata.FailedRequests),
		)
	}
	return Result{Report: report, Baseline: healthmodel.NewBaseline(snapshot)}, nil
}

type ErrorKind string

const (
	ErrorConfiguration  ErrorKind = "configuration"
	ErrorConnection     ErrorKind = "connection"
	ErrorAuthentication ErrorKind = "authentication"
	ErrorProduct        ErrorKind = "product"
	ErrorInternal       ErrorKind = "internal"
)

type Error struct {
	Kind  ErrorKind
	Cause error
}

func (err *Error) Error() string {
	switch err.Kind {
	case ErrorConfiguration:
		return "health assessment configuration is invalid"
	case ErrorAuthentication:
		return "Elasticsearch authentication failed"
	case ErrorProduct:
		return "target is not a supported Elasticsearch endpoint"
	case ErrorConnection:
		return "Elasticsearch connection failed"
	default:
		return "health assessment failed"
	}
}

func (err *Error) Unwrap() error { return err.Cause }

func classifyCollectorError(err error) error {
	var collectorError *collector.Error
	if !errors.As(err, &collectorError) {
		return &Error{Kind: ErrorConnection, Cause: err}
	}
	switch collectorError.Kind {
	case collector.ErrorAuthentication:
		return &Error{Kind: ErrorAuthentication, Cause: err}
	case collector.ErrorProduct:
		return &Error{Kind: ErrorProduct, Cause: err}
	case collector.ErrorConfiguration:
		return &Error{Kind: ErrorConfiguration, Cause: err}
	default:
		return &Error{Kind: ErrorConnection, Cause: err}
	}
}

func validateBaseline(snapshot *healthmodel.ClusterSnapshot, baseline *healthmodel.Baseline) error {
	if baseline.SchemaVersion != healthmodel.BaselineSchemaVersion {
		return fmt.Errorf("baseline schema version is unsupported")
	}
	if baseline.Timestamp.IsZero() || !snapshot.Timestamp.After(baseline.Timestamp) {
		return fmt.Errorf("baseline timestamp must precede the current scan")
	}
	if baseline.ClusterUUID == "" || snapshot.Cluster.UUID == "" || baseline.ClusterUUID != snapshot.Cluster.UUID {
		return fmt.Errorf("baseline belongs to a different Elasticsearch cluster")
	}
	return nil
}
