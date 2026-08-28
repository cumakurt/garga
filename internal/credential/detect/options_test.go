package detect

import (
	"testing"
	"time"
)

func TestDefaultsAreConservative(t *testing.T) {
	t.Parallel()

	options := Defaults()
	if options.MaxAttemptsPerHost != DefaultMaxAttemptsPerHost || options.GlobalRate != DefaultGlobalRate || options.PerHostRate != DefaultPerHostRate {
		t.Fatalf("Defaults() = %#v", options)
	}
	if options.GlobalRate > 1 || options.PerHostRate > 1 {
		t.Fatalf("default detection rate %g/%g exceeds 1 req/s", options.GlobalRate, options.PerHostRate)
	}
	if err := options.Validate(); err != nil {
		t.Fatalf("Defaults().Validate() error = %v", err)
	}
}

func TestOptionsRejectUnsafeLimits(t *testing.T) {
	t.Parallel()

	options := Defaults()
	options.MaxAttemptsPerHost = maxAttemptsPerHost + 1
	if err := options.Validate(); err == nil {
		t.Fatal("accepted attempts above the ceiling")
	}

	options = Defaults()
	options.PerHostRate = options.GlobalRate + 1
	if err := options.Validate(); err == nil {
		t.Fatal("accepted per-host rate above the global rate")
	}

	options = Defaults()
	options.Mode = ModeStuffing
	options.SprayRoundDelay = time.Second
	if err := options.Validate(); err == nil {
		t.Fatal("accepted spray delay outside spraying mode")
	}

	options = Defaults()
	options.Mode = ModeSpraying
	options.SprayRoundDelay = maxSprayDelay + time.Second
	if err := options.Validate(); err == nil {
		t.Fatal("accepted spray delay above the ceiling")
	}
}
