package cli

import (
	"io"
	"strings"

	"github.com/cumakurt/garga/internal/target"
)

func openTargetSource(args []string, filePath string, stdin io.Reader) (target.Source, error) {
	var sources []target.Source
	if len(args) > 0 {
		reader, err := target.NewReaderSource(strings.NewReader(strings.Join(args, "\n")+"\n"), "cli")
		if err != nil {
			return nil, &executionError{exitCode: ExitInvalidInput, message: "invalid target input", cause: err}
		}
		sources = append(sources, reader)
	}

	path := strings.TrimSpace(filePath)
	if path != "" {
		if path == "-" {
			if stdin == nil {
				return nil, &executionError{exitCode: ExitInvalidInput, message: "target stdin is required"}
			}
			reader, err := target.NewReaderSource(stdin, "stdin")
			if err != nil {
				return nil, &executionError{exitCode: ExitInvalidInput, message: "invalid target input", cause: err}
			}
			sources = append(sources, reader)
		} else {
			file, err := target.OpenFileSource(path)
			if err != nil {
				return nil, &executionError{exitCode: ExitInvalidInput, message: "open target file", cause: err}
			}
			sources = append(sources, file)
		}
	}

	source, err := target.Chain(sources...)
	if err != nil {
		for _, item := range sources {
			_ = item.Close()
		}
		return nil, &executionError{exitCode: ExitInvalidInput, message: "invalid target input", cause: err}
	}
	return source, nil
}
