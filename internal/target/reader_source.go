package target

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"unicode"

	"github.com/cumakurt/garga/internal/model"
)

const (
	defaultSourceName        = "input"
	maxSourceNameBytes       = 4 * 1024
	maxTargetSourceLineBytes = maxTargetInputBytes + 1024
)

// ReaderSource parses line-oriented targets and lazily expands CIDR lines.
type ReaderSource struct {
	scanner     *bufio.Scanner
	name        string
	lineNumber  int
	activeCIDR  *CIDRSource
	closer      io.Closer
	terminalErr error
	closed      bool
}

// NewReaderSource creates a source without taking ownership of the supplied reader.
func NewReaderSource(reader io.Reader, sourceName string) (*ReaderSource, error) {
	if reader == nil {
		return nil, newSourceError("create target source: reader is nil", nil)
	}
	name, err := normalizeSourceName(sourceName)
	if err != nil {
		return nil, err
	}
	return newReaderSource(reader, nil, name), nil
}

// OpenFileSource opens a target file and returns a source that owns the file descriptor.
func OpenFileSource(path string) (*ReaderSource, error) {
	if strings.TrimSpace(path) == "" {
		return nil, newSourceError("open target source: file path is empty", nil)
	}
	name, err := normalizeSourceName(path)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, newSourceError(
			fmt.Sprintf("open target source %s: unable to open file", name),
			err,
		)
	}

	return newReaderSource(file, file, name), nil
}

func newReaderSource(reader io.Reader, closer io.Closer, sourceName string) *ReaderSource {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), maxTargetSourceLineBytes)

	return &ReaderSource{
		scanner: scanner,
		name:    sourceName,
		closer:  closer,
	}
}

// Next returns the next canonical target. Empty lines and lines whose first non-space character
// is '#' are ignored. Inline comments are intentionally not supported.
func (source *ReaderSource) Next(ctx context.Context) (model.Target, error) {
	if err := ctx.Err(); err != nil {
		return model.Target{}, err
	}
	if source.closed {
		return model.Target{}, io.EOF
	}
	if source.terminalErr != nil {
		return model.Target{}, source.terminalErr
	}

	for {
		if source.activeCIDR != nil {
			target, err := source.activeCIDR.Next(ctx)
			if err == nil {
				return target, nil
			}
			if !errors.Is(err, io.EOF) {
				return model.Target{}, err
			}
			_ = source.activeCIDR.Close()
			source.activeCIDR = nil
		}

		if err := ctx.Err(); err != nil {
			return model.Target{}, err
		}
		if !source.scanner.Scan() {
			if err := source.scanner.Err(); err != nil {
				source.terminalErr = newSourceError(
					fmt.Sprintf("read target source %s: input line is too long or unreadable", source.name),
					err,
				)
			} else {
				source.terminalErr = io.EOF
			}
			return model.Target{}, source.terminalErr
		}

		source.lineNumber++
		line := strings.TrimSpace(source.scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		attribution := fmt.Sprintf("%s:%d", source.name, source.lineNumber)
		if _, err := netip.ParsePrefix(line); err == nil {
			cidr, err := NewCIDRSource(line, attribution)
			if err != nil {
				source.terminalErr = newSourceError(
					fmt.Sprintf("parse CIDR target at %s: %s", attribution, err),
					err,
				)
				return model.Target{}, source.terminalErr
			}
			source.activeCIDR = cidr
			continue
		}

		parsed, err := Parse(line, attribution)
		if err != nil {
			source.terminalErr = newSourceError(
				fmt.Sprintf("parse target at %s: %s", attribution, err),
				err,
			)
			return model.Target{}, source.terminalErr
		}
		return parsed, nil
	}
}

// Close releases an owned file and stops target production. It is safe to call more than once.
func (source *ReaderSource) Close() error {
	if source.closed {
		return nil
	}
	source.closed = true
	source.terminalErr = io.EOF
	source.scanner = nil
	if source.activeCIDR != nil {
		_ = source.activeCIDR.Close()
		source.activeCIDR = nil
	}
	closer := source.closer
	source.closer = nil
	if closer == nil {
		return nil
	}
	if err := closer.Close(); err != nil {
		return newSourceError(
			fmt.Sprintf("close target source %s", source.name),
			err,
		)
	}
	return nil
}

func normalizeSourceName(sourceName string) (string, error) {
	if strings.TrimSpace(sourceName) == "" {
		return defaultSourceName, nil
	}
	if len(sourceName) > maxSourceNameBytes {
		return "", newSourceError("create target source: source name exceeds 4096 bytes", nil)
	}
	for _, character := range sourceName {
		if unicode.IsControl(character) {
			return "", newSourceError(
				"create target source: source name contains control characters",
				nil,
			)
		}
	}
	return sourceName, nil
}
