package update

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cumakurt/garga/internal/transport"
)

// Fetcher loads one named bundle artifact.
type Fetcher interface {
	Fetch(ctx context.Context, name string) ([]byte, error)
}

type dirFetcher struct {
	dir string
}

type httpFetcher struct {
	client  *transport.Client
	baseURL *url.URL
}

func newFetcher(source string, client *transport.Client) (Fetcher, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, fmt.Errorf("update signatures: source is required")
	}
	parsed, err := url.Parse(source)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return newHTTPFetcher(parsed, client)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return nil, fmt.Errorf("%w: source directory is not readable", ErrFetch)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: source directory must not be a symlink", ErrFetch)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: source must be a directory or HTTP(S) URL", ErrFetch)
	}
	return dirFetcher{dir: filepath.Clean(source)}, nil
}

func newHTTPFetcher(base *url.URL, client *transport.Client) (Fetcher, error) {
	if client == nil {
		return nil, fmt.Errorf("update signatures: HTTP transport is required")
	}
	switch strings.ToLower(base.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("%w: source URL scheme must be http or https", ErrFetch)
	}
	if base.User != nil {
		return nil, fmt.Errorf("%w: source URL must not contain credentials", ErrFetch)
	}
	cloned := *base
	cloned.RawQuery = ""
	cloned.Fragment = ""
	if cloned.Path == "" {
		cloned.Path = "/"
	}
	if !strings.HasSuffix(cloned.Path, "/") {
		cloned.Path += "/"
	}
	return httpFetcher{client: client, baseURL: &cloned}, nil
}

func (fetcher dirFetcher) Fetch(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := allowedArtifact(name); err != nil {
		return nil, err
	}
	artifactPath := filepath.Join(fetcher.dir, name)
	if filepath.Dir(artifactPath) != fetcher.dir {
		return nil, fmt.Errorf("%w: artifact path escaped the source directory", ErrFetch)
	}
	info, err := os.Lstat(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("%w: artifact %s is missing", ErrFetch, name)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: artifact %s must be a regular file", ErrFetch, name)
	}
	if info.Size() > artifactLimit(name) {
		return nil, fmt.Errorf("%w: artifact %s exceeds the size limit", ErrFetch, name)
	}
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read artifact %s", ErrFetch, name)
	}
	if int64(len(data)) > artifactLimit(name) {
		return nil, fmt.Errorf("%w: artifact %s exceeds the size limit", ErrFetch, name)
	}
	return data, nil
}

func (fetcher httpFetcher) Fetch(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := allowedArtifact(name); err != nil {
		return nil, err
	}
	resolved := fetcher.baseURL.ResolveReference(&url.URL{Path: path.Clean(name)})
	if resolved.Host != fetcher.baseURL.Host || resolved.User != nil {
		return nil, fmt.Errorf("%w: artifact URL is invalid", ErrFetch)
	}
	if !strings.HasPrefix(resolved.EscapedPath(), fetcher.baseURL.EscapedPath()) {
		return nil, fmt.Errorf("%w: artifact URL escaped the source", ErrFetch)
	}
	request, err := transport.NewRequest(ctx, http.MethodGet, resolved.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFetch, err.Error())
	}
	response, err := fetcher.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: artifact %s returned HTTP %d", ErrFetch, name, response.StatusCode)
	}
	if int64(len(response.Body)) > artifactLimit(name) {
		return nil, fmt.Errorf("%w: artifact %s exceeds the size limit", ErrFetch, name)
	}
	return response.Body, nil
}

func allowedArtifact(name string) error {
	switch name {
	case ManifestName, SignatureName, ArchiveName:
		return nil
	default:
		return fmt.Errorf("%w: artifact name is not allowed", ErrFetch)
	}
}

func artifactLimit(name string) int64 {
	switch name {
	case ManifestName:
		return maxManifestBytes
	case SignatureName:
		return maxDetachedSignatureBytes
	default:
		return MaxArchiveBytes
	}
}
