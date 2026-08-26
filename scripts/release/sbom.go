package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type goModule struct {
	Path     string    `json:"Path"`
	Version  string    `json:"Version"`
	Main     bool      `json:"Main"`
	Indirect bool      `json:"Indirect"`
	Replace  *goModule `json:"Replace"`
}

type spdxDocument struct {
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	SPDXID            string           `json:"SPDXID"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo `json:"creationInfo"`
	Packages          []spdxPackage    `json:"packages"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo,omitempty"`
	DownloadLocation string `json:"downloadLocation"`
	LicenseConcluded string `json:"licenseConcluded"`
	PrimaryPurpose   string `json:"primaryPackagePurpose,omitempty"`
}

func writeSBOM(cfg config) (string, error) {
	modules, err := listModules(cfg)
	if err != nil {
		return "", err
	}
	document := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "garga-" + cfg.Version,
		DocumentNamespace: "https://github.com/cumakurt/garga/spdx/" + cfg.Version,
		CreationInfo: spdxCreationInfo{
			Created:  cfg.BuiltAt.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: garga-release"},
		},
	}
	for index, module := range modules {
		path := module.Path
		version := module.Version
		if module.Replace != nil {
			path = module.Replace.Path
			version = module.Replace.Version
		}
		if module.Main {
			version = cfg.Version
		}
		license := "NOASSERTION"
		purpose := "LIBRARY"
		if module.Main {
			license = "AGPL-3.0-only"
			purpose = "APPLICATION"
		}
		document.Packages = append(document.Packages, spdxPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", index),
			Name:             path,
			VersionInfo:      version,
			DownloadLocation: "NOASSERTION",
			LicenseConcluded: license,
			PrimaryPurpose:   purpose,
		})
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(cfg.OutDir, fmt.Sprintf("%s_%s.spdx.json", binaryName, cfg.Version))
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func listModules(cfg config) ([]goModule, error) {
	command := exec.Command(cfg.GoBin, "list", "-m", "-json", "all")
	command.Dir = cfg.Root
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	var modules []goModule
	for decoder.More() {
		var module goModule
		if err := decoder.Decode(&module); err != nil {
			return nil, fmt.Errorf("decode go list: %w", err)
		}
		modules = append(modules, module)
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("go list returned no modules")
	}
	return modules, nil
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func maybeSign(cfg config, sumsPath string) error {
	keyID := strings.TrimSpace(os.Getenv("GARGA_RELEASE_GPG_KEY"))
	if keyID == "" {
		fmt.Fprintln(os.Stderr, "release: signing skipped (set GARGA_RELEASE_GPG_KEY to sign SHA256SUMS)")
		return nil
	}
	command := exec.Command("gpg", "--detach-sign", "--armor", "--local-user", keyID, "--output", sumsPath+".asc", sumsPath)
	command.Dir = cfg.Root
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gpg sign: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	fmt.Fprintf(os.Stderr, "release: wrote %s.asc\n", sumsPath)
	return nil
}
