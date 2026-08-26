package fingerprint

import (
	"fmt"

	"github.com/cumakurt/garga/internal/config"
)

// Options controls the score required to identify a response as Elasticsearch.
type Options struct {
	Threshold int
}

// OptionsFromConfig derives fingerprint options from validated application configuration.
func OptionsFromConfig(cfg config.Config) (Options, error) {
	if err := cfg.Validate(); err != nil {
		return Options{}, err
	}
	return Options{Threshold: cfg.Fingerprint.Threshold}, nil
}

func (options Options) validate() error {
	if options.Threshold < 1 || options.Threshold > 100 {
		return fmt.Errorf("invalid fingerprint options: threshold must be between 1 and 100")
	}
	return nil
}
