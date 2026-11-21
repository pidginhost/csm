package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/klauspost/compress/zstd"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
)

var errSensitiveExport = errors.New("store export omitted because it contains credential material")

func openSupportExport(path string) (*os.File, error) {
	// #nosec G304 G703 -- the local daemon returned this staging path. Refuse links and special files.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("staged export is not a regular file")
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// Check the decompressed archive, including database pages and tar metadata.
// Both this pass and the final copy must match the daemon's digest.
func inspectSupportExport(res *control.StoreExportResult, cfg *config.Config, secrets []string) error {
	f, err := openSupportExport(res.Path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	zr, err := zstd.NewReader(io.TeeReader(f, h), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return err
	}
	defer zr.Close()

	privateKeyHeaders := []string{
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN DSA PRIVATE KEY-----",
	}
	screen := newExportScreen(append(privateKeyHeaders, secrets...))
	checked := io.TeeReader(zr, screen)
	tr := tar.NewReader(checked)
	keyFiles := map[string]bool{"state/webui.key": true}
	for _, file := range cfg.SupportBundleKeyFiles() {
		if file == "" {
			continue
		}
		for prefix, base := range map[string]string{"state/": cfg.StatePath, "rules/": cfg.Signatures.RulesDir} {
			if base == "" {
				continue
			}
			if rel, relErr := filepath.Rel(base, file); relErr == nil && filepath.IsLocal(rel) {
				keyFiles[prefix+filepath.ToSlash(rel)] = true
			}
		}
	}
	for {
		hdr, readErr := tr.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return fmt.Errorf("checking store export: %w", readErr)
		}
		if keyFiles[hdr.Name] {
			return errSensitiveExport
		}
	}
	// tar stops at its end markers. Finish the frame to check its trailer and
	// cover all compressed bytes with the digest.
	if _, err = io.Copy(io.Discard, checked); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), res.ArchiveSHA256) {
		return errors.New("staged archive digest does not match daemon response")
	}
	return nil
}

type exportScreen struct {
	needles [][]byte
	window  []byte
	overlap int
}

func newExportScreen(values []string) *exportScreen {
	s := &exportScreen{}
	for _, v := range values {
		s.needles = append(s.needles, []byte(v))
		s.overlap = max(s.overlap, len(v)-1)
	}
	return s
}

func (s *exportScreen) Write(p []byte) (int, error) {
	s.window = append(s.window, p...)
	for _, needle := range s.needles {
		if bytes.Contains(s.window, needle) {
			return 0, errSensitiveExport
		}
	}
	// A credential can straddle two reads, including inside a binary database page.
	keep := min(len(s.window), s.overlap)
	copy(s.window, s.window[len(s.window)-keep:])
	s.window = s.window[:keep]
	return len(p), nil
}
