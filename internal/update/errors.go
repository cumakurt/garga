package update

import "errors"

var (
	// ErrVerification is returned when the trust root, manifest signature, or checksum fails.
	ErrVerification = errors.New("signature bundle verification failed")
	// ErrArchive is returned when the archive is unsafe, truncated, or inconsistent.
	ErrArchive = errors.New("signature archive is unsafe or invalid")
	// ErrValidation is returned when staged YAML signatures fail LoadDir.
	ErrValidation = errors.New("staged signatures failed validation")
	// ErrFetch is returned when a required bundle artifact cannot be read.
	ErrFetch = errors.New("signature bundle fetch failed")
)

const (
	ManifestName  = "manifest.json"
	SignatureName = "manifest.sig"
	ArchiveName   = "signatures.zip"
	CurrentDir    = "current"
	PreviousDir   = "previous"

	// MaxArchiveBytes is the maximum compressed signature zip size.
	MaxArchiveBytes = 8 << 20

	maxManifestBytes          = 64 * 1024
	maxDetachedSignatureBytes = 256
	nextDirName               = ".next"
	rollbackTempName          = ".rollback-tmp"
	stagingPrefix             = ".staging-"
)
