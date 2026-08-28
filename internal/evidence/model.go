package evidence

const (
	SchemaVersion      = "0.1"
	DigestAlgorithm    = "sha256"
	SignatureAlgorithm = "ed25519"
	MaxArtifacts       = 32
	MaxArtifactBytes   = 64 << 20
	MaxTotalBytes      = 256 << 20
	MaxBundleBytes     = MaxTotalBytes + 4<<20
	maxManifestBytes   = 1 << 20
)

type Entry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type SignatureMetadata struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
}

type Manifest struct {
	SchemaVersion string             `json:"schema_version"`
	Algorithm     string             `json:"algorithm"`
	Entries       []Entry            `json:"entries"`
	Signature     *SignatureMetadata `json:"signature,omitempty"`
}

type Verification struct {
	SchemaVersion string `json:"schema_version"`
	Bundle        string `json:"bundle"`
	Artifacts     int    `json:"artifacts"`
	Bytes         int64  `json:"bytes"`
	Signed        bool   `json:"signed"`
	KeyID         string `json:"key_id,omitempty"`
	Verified      bool   `json:"verified"`
}
