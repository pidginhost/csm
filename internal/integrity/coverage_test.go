package integrity

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func expectedHash(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h[:])
}

// --- HashFile ---------------------------------------------------------

func TestHashFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary")
	payload := []byte("fake binary content")
	if err := os.WriteFile(path, payload, 0755); err != nil {
		t.Fatal(err)
	}
	got, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if got != expectedHash(payload) {
		t.Errorf("hash = %q, want %q", got, expectedHash(payload))
	}
}

func TestHashFileMissing(t *testing.T) {
	_, err := HashFile(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("missing file should error")
	}
}

func TestHashFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	got, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != expectedHash(nil) {
		t.Errorf("empty file hash mismatch: %q", got)
	}
}

// --- Verify -----------------------------------------------------------

func TestVerifyUnbaselinedNoOp(t *testing.T) {
	// Empty BinaryHash → Verify should return nil without hashing anything.
	cfg := &config.Config{}
	if err := Verify("/nonexistent/binary", cfg); err != nil {
		t.Errorf("Verify unbaselined should return nil, got %v", err)
	}
}

func TestVerifyBinaryHashMatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "csm")
	if err := os.WriteFile(bin, []byte("binary bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	hash, err := HashFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Integrity.BinaryHash = hash
	if err := Verify(bin, cfg); err != nil {
		t.Errorf("Verify matching binary = %v, want nil", err)
	}
}

func TestVerifyBinaryHashMismatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "csm")
	if err := os.WriteFile(bin, []byte("binary bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Integrity.BinaryHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	err := Verify(bin, cfg)
	if err == nil || !strings.Contains(err.Error(), "binary hash mismatch") {
		t.Errorf("err = %v, want binary hash mismatch", err)
	}
}

func TestVerifyBinaryMissing(t *testing.T) {
	cfg := &config.Config{}
	cfg.Integrity.BinaryHash = "sha256:x"
	err := Verify("/nonexistent/binary", cfg)
	if err == nil || !strings.Contains(err.Error(), "hashing binary") {
		t.Errorf("err = %v, want hashing binary error", err)
	}
}

func TestVerifyConfigHashMatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "csm")
	if err := os.WriteFile(bin, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	binHash, _ := HashFile(bin)

	cfgPath := filepath.Join(dir, "csm.yaml")
	content := "hostname: web01\nalerts:\n  email:\n    enabled: true\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfgHash, err := HashConfigStable(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{ConfigFile: cfgPath}
	cfg.Integrity.BinaryHash = binHash
	cfg.Integrity.ConfigHash = cfgHash
	if err := Verify(bin, cfg); err != nil {
		t.Errorf("Verify matching config = %v, want nil", err)
	}
}

func TestVerifyConfigHashMismatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "csm")
	if err := os.WriteFile(bin, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	binHash, _ := HashFile(bin)

	cfgPath := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(cfgPath, []byte("hostname: web01\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ConfigFile: cfgPath}
	cfg.Integrity.BinaryHash = binHash
	cfg.Integrity.ConfigHash = "sha256:wrong"
	err := Verify(bin, cfg)
	if err == nil || !strings.Contains(err.Error(), "config hash mismatch") {
		t.Errorf("err = %v, want config hash mismatch", err)
	}
}

func TestVerifyConfigHashFileMissing(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "csm")
	if err := os.WriteFile(bin, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	binHash, _ := HashFile(bin)

	cfg := &config.Config{ConfigFile: filepath.Join(dir, "missing.yaml")}
	cfg.Integrity.BinaryHash = binHash
	cfg.Integrity.ConfigHash = "sha256:x"
	err := Verify(bin, cfg)
	if err == nil || !strings.Contains(err.Error(), "hashing config") {
		t.Errorf("err = %v, want hashing config error", err)
	}
}

// --- HashConfigStable --------------------------------------------------

func TestHashConfigStableIgnoresIntegritySection(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.yaml")
	pathB := filepath.Join(dir, "b.yaml")

	// Same config, differing only in the integrity: block.
	base := "hostname: web01\nalerts:\n  email:\n    enabled: true\n"
	a := base + "integrity:\n  binary_hash: sha256:aaa\n  config_hash: sha256:bbb\n"
	b := base + "integrity:\n  binary_hash: sha256:ccc\n  config_hash: sha256:ddd\n"

	if err := os.WriteFile(pathA, []byte(a), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte(b), 0644); err != nil {
		t.Fatal(err)
	}

	hashA, err := HashConfigStable(pathA)
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := HashConfigStable(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Errorf("integrity section changes should not affect hash: %q vs %q", hashA, hashB)
	}
}

func TestHashConfigStableNoIntegritySection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.yaml")
	if err := os.WriteFile(path, []byte("hostname: x\nalerts: {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Just ensure it does not error.
	if _, err := HashConfigStable(path); err != nil {
		t.Fatal(err)
	}
}

func TestHashConfigStableMissingFile(t *testing.T) {
	_, err := HashConfigStable(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("missing file should error")
	}
}

func TestHashConfigStableTrailingSectionAfterIntegrity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	// An unindented top-level section after `integrity:` should break out
	// of the integrity-skip block.
	content := "hostname: web01\n" +
		"integrity:\n" +
		"  binary_hash: sha256:a\n" +
		"  config_hash: sha256:b\n" +
		"alerts:\n" +
		"  email:\n" +
		"    enabled: true\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	// The `alerts:` line must appear in the hash so the returned value
	// changes if alerts is modified.
	hash1, err := HashConfigStable(path)
	if err != nil {
		t.Fatal(err)
	}

	// Now change the alerts block.
	modified := "hostname: web01\n" +
		"integrity:\n" +
		"  binary_hash: sha256:a\n" +
		"  config_hash: sha256:b\n" +
		"alerts:\n" +
		"  email:\n" +
		"    enabled: false\n"
	if writeErr := os.WriteFile(path, []byte(modified), 0644); writeErr != nil {
		t.Fatal(writeErr)
	}
	hash2, err := HashConfigStable(path)
	if err != nil {
		t.Fatal(err)
	}
	if hash1 == hash2 {
		t.Error("changing alerts section should change stable hash")
	}
}
