package app

import (
	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/probe"
	"github.com/cumakurt/garga/internal/progress"
	"github.com/cumakurt/garga/internal/scanner"
	"github.com/cumakurt/garga/internal/target"
	"github.com/cumakurt/garga/internal/transport"
)

type probeSession struct {
	factory     *transport.Factory
	prober      probe.Prober
	engine      *scanner.Engine
	fingerprint *fingerprint.Engine
	source      scanner.Source
	progress    *progress.Bar
}

func openProbeSession(options Options) (*probeSession, error) {
	if options.Source == nil {
		return nil, invalidError("a target source is required", nil)
	}

	maxUnique := options.MaxUniqueTargets
	if maxUnique <= 0 {
		maxUnique = DefaultMaxUniqueTargets
	}
	deduped, err := target.NewDeduplicatingSource(options.Source, maxUnique)
	if err != nil {
		_ = options.Source.Close()
		return nil, invalidError("invalid target source", err)
	}

	fpOptions, err := fingerprint.OptionsFromConfig(options.Config)
	if err != nil {
		_ = deduped.Close()
		return nil, invalidError("invalid configuration", err)
	}
	identityEngine, err := fingerprint.New(fpOptions)
	if err != nil {
		_ = deduped.Close()
		return nil, invalidError("invalid fingerprint options", err)
	}

	scannerOptions, err := scanner.OptionsFromConfig(options.Config)
	if err != nil {
		_ = deduped.Close()
		return nil, invalidError("invalid configuration", err)
	}
	scannerOptions.Logger = options.Logger
	bar := progressBar(options)
	if bar != nil {
		scannerOptions.Progress = func(stats scanner.Stats) {
			bar.Record(progress.Snapshot{
				Submitted: stats.Submitted,
				Completed: stats.Completed,
				Succeeded: stats.Succeeded,
				Failed:    stats.Failed,
			})
		}
	}

	transportOptions, err := transport.OptionsFromConfig(options.Config, options.UserAgent)
	if err != nil {
		_ = deduped.Close()
		return nil, invalidError("invalid configuration", err)
	}
	transportOptions.InsecureSkipVerify = options.Insecure
	factory, err := transport.NewFactory(transportOptions)
	if err != nil {
		_ = deduped.Close()
		return nil, internalError("create HTTP transport", err)
	}

	prober, err := probe.NewHTTP(factory.Client())
	if err != nil {
		factory.CloseIdleConnections()
		_ = deduped.Close()
		return nil, internalError("create HTTP prober", err)
	}

	engine, err := scanner.New(scannerOptions, prober)
	if err != nil {
		factory.CloseIdleConnections()
		_ = deduped.Close()
		return nil, internalError("create scanner engine", err)
	}

	return &probeSession{
		factory:     factory,
		prober:      prober,
		engine:      engine,
		fingerprint: identityEngine,
		source:      &endpointSource{inner: deduped},
		progress:    bar,
	}, nil
}

func progressBar(options Options) *progress.Bar {
	if options.NoProgress {
		return nil
	}
	bar := progress.Open(options.Progress, progress.Options{})
	if !bar.Enabled() {
		return nil
	}
	return bar
}

func (session *probeSession) closeProgress() {
	if session == nil || session.progress == nil {
		return
	}
	_ = session.progress.Close()
}

func (session *probeSession) closeIdle() {
	if session == nil || session.factory == nil {
		return
	}
	session.factory.CloseIdleConnections()
}
