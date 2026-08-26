package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func writeTarGz(dest, prefix string, files []archiveFile, builtAt time.Time) error {
	file, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	dirHeader := &tar.Header{
		Typeflag: tar.TypeDir,
		Name:     prefix + "/",
		Mode:     0o755,
		ModTime:  builtAt,
		Format:   tar.FormatPAX,
	}
	if err := tarWriter.WriteHeader(dirHeader); err != nil {
		return err
	}
	for _, member := range files {
		if err := addTarFile(tarWriter, prefix, member, builtAt); err != nil {
			return err
		}
	}
	return tarWriter.Close()
}

func addTarFile(writer *tar.Writer, prefix string, member archiveFile, builtAt time.Time) error {
	info, err := os.Stat(member.Path)
	if err != nil {
		return err
	}
	header := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     prefix + "/" + member.Name,
		Mode:     int64(member.Mode.Perm()),
		Size:     info.Size(),
		ModTime:  builtAt,
		Format:   tar.FormatPAX,
	}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	source, err := os.Open(member.Path)
	if err != nil {
		return err
	}
	defer source.Close()
	_, err = io.Copy(writer, source)
	return err
}

func writeZip(dest, prefix string, files []archiveFile, builtAt time.Time) error {
	file, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()

	for _, member := range files {
		header := &zip.FileHeader{
			Name:     prefix + "/" + member.Name,
			Method:   zip.Deflate,
			Modified: builtAt,
		}
		header.SetMode(member.Mode)
		entry, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		source, err := os.Open(member.Path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(entry, source)
		_ = source.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return zipWriter.Close()
}

func writeChecksums(outDir string, artifacts []string) (string, error) {
	sumsPath := filepath.Join(outDir, "SHA256SUMS")
	file, err := os.OpenFile(sumsPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	defer file.Close()
	for _, artifact := range artifacts {
		sum, err := sha256File(artifact)
		if err != nil {
			return "", err
		}
		if _, err := fmt.Fprintf(file, "%s  %s\n", sum, filepath.Base(artifact)); err != nil {
			return "", err
		}
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return sumsPath, nil
}
