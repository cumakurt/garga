package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cumakurt/garga/internal/evidence"
	"github.com/spf13/cobra"
)

func newEvidenceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "evidence",
		Short:         "Create and verify tamper-evident assessment bundles",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newEvidencePackCommand())
	cmd.AddCommand(newEvidenceVerifyCommand())
	return cmd
}

func newEvidencePackCommand() *cobra.Command {
	var (
		paths          []string
		outputPath     string
		signingKeyPath string
		format         string
	)
	cmd := &cobra.Command{
		Use:   "pack",
		Short: "Package reports with SHA-256 integrity and optional Ed25519 signing",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			parsedFormat, err := parseEvidenceFormat(format)
			if err != nil {
				return &executionError{exitCode: ExitInvalidInput, message: err.Error(), cause: err}
			}
			manifest, err := evidence.Pack(cmd.Context(), evidence.PackOptions{
				Paths: paths, OutputPath: outputPath, SigningKeyPath: signingKeyPath,
			})
			if err != nil {
				return &executionError{exitCode: ExitInvalidInput, message: err.Error(), cause: err}
			}
			result := struct {
				SchemaVersion string `json:"schema_version"`
				Bundle        string `json:"bundle"`
				Artifacts     int    `json:"artifacts"`
				Signed        bool   `json:"signed"`
				KeyID         string `json:"key_id,omitempty"`
			}{
				SchemaVersion: evidence.SchemaVersion,
				Bundle:        filepath.Base(outputPath),
				Artifacts:     len(manifest.Entries),
				Signed:        manifest.Signature != nil,
			}
			if manifest.Signature != nil {
				result.KeyID = manifest.Signature.KeyID
			}
			if parsedFormat == "json" {
				if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
					return &executionError{exitCode: ExitInternalError, message: "write evidence result", cause: err}
				}
				return nil
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Evidence bundle written: %s (%d artifacts, signed: %t)\n", result.Bundle, result.Artifacts, result.Signed)
			if err != nil {
				return &executionError{exitCode: ExitInternalError, message: "write evidence result", cause: err}
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&paths, "file", nil, "artifact file to include (repeatable, maximum 32)")
	cmd.Flags().StringVar(&outputPath, "output", "", "output evidence ZIP path (must not already exist)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "optional Ed25519 private key (PKCS#8 PEM, hex, or base64)")
	cmd.Flags().StringVar(&format, "format", "console", "output format: console or json")
	return cmd
}

func newEvidenceVerifyCommand() *cobra.Command {
	var (
		publicKeyPath string
		format        string
	)
	cmd := &cobra.Command{
		Use:   "verify BUNDLE",
		Short: "Verify evidence hashes and an optional Ed25519 signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedFormat, err := parseEvidenceFormat(format)
			if err != nil {
				return &executionError{exitCode: ExitInvalidInput, message: err.Error(), cause: err}
			}
			result, err := evidence.Verify(cmd.Context(), evidence.VerifyOptions{
				BundlePath: args[0], PublicKeyPath: publicKeyPath,
			})
			if err != nil {
				return &executionError{exitCode: ExitInvalidInput, message: err.Error(), cause: err}
			}
			if parsedFormat == "json" {
				if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
					return &executionError{exitCode: ExitInternalError, message: "write evidence verification", cause: err}
				}
				return nil
			}
			_, err = fmt.Fprintf(
				cmd.OutOrStdout(),
				"Evidence verified: %s (%d artifacts, %d bytes, signed: %t)\n",
				result.Bundle,
				result.Artifacts,
				result.Bytes,
				result.Signed,
			)
			if err != nil {
				return &executionError{exitCode: ExitInternalError, message: "write evidence verification", cause: err}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&publicKeyPath, "public-key", "", "Ed25519 public key for a signed bundle (PKIX PEM, hex, or base64)")
	cmd.Flags().StringVar(&format, "format", "console", "output format: console or json")
	return cmd
}

func parseEvidenceFormat(value string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(value))
	if format != "console" && format != "json" {
		return "", fmt.Errorf("evidence format must be console or json")
	}
	return format, nil
}
