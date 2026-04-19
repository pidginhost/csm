package integrity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestHashConfigStable_ReturnsScannerError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	oversizedLine := strings.Repeat("a", 70*1024)
	data := "hostname: test.example\n" + oversizedLine + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := HashConfigStable(path); err == nil {
		t.Fatal("HashConfigStable() = nil error, want scanner failure")
	}
}

func TestHashConfigStableBytes_MatchesHashConfigStable(t *testing.T) {
	// Both functions must produce the same hash for the same input
	// (same file content). The in-memory path skips a disk read but
	// must not drift from the file path semantically.
	path := filepath.Join(t.TempDir(), "csm.yaml")
	data := []byte(`hostname: host.example.com
integrity:
  binary_hash: "sha256:aaaa"
  config_hash: "sha256:bbbb"
  immutable: false
thresholds:
  mail_queue_warn: 100
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	fromFile, err := HashConfigStable(path)
	if err != nil {
		t.Fatalf("HashConfigStable: %v", err)
	}
	fromBytes := HashConfigStableBytes(data)

	if fromFile != fromBytes {
		t.Errorf("hash drift: file=%s bytes=%s", fromFile, fromBytes)
	}
}

func TestHashConfigStableBytes_IgnoresIntegritySection(t *testing.T) {
	// Two configs that differ ONLY inside the integrity block must
	// produce the same hash -- that is the whole point of the
	// "stable" variant.
	a := []byte(`hostname: x
integrity:
  binary_hash: "sha256:111"
  config_hash: "sha256:222"
thresholds:
  mail_queue_warn: 100
`)
	b := []byte(`hostname: x
integrity:
  binary_hash: "sha256:aaa"
  config_hash: "sha256:bbb"
thresholds:
  mail_queue_warn: 100
`)
	if HashConfigStableBytes(a) != HashConfigStableBytes(b) {
		t.Error("integrity-only edits should not change the stable hash")
	}
}

func TestSignAndSaveAtomic_RoundTrips(t *testing.T) {
	// Happy path: marshal, sign, atomic-write, Verify passes.
	path := filepath.Join(t.TempDir(), "csm.yaml")

	cfg := &config.Config{ConfigFile: path}
	cfg.Hostname = "host.example.com"
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"ops@example.com"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "localhost:25"

	fakeBin := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(fakeBin, []byte("stand-in"), 0o600); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	bh, err := HashFile(fakeBin)
	if err != nil {
		t.Fatalf("hash bin: %v", err)
	}

	if serr := SignAndSaveAtomic(cfg, bh); serr != nil {
		t.Fatalf("SignAndSaveAtomic: %v", serr)
	}

	if _, serr := os.Stat(path); serr != nil {
		t.Fatalf("expected csm.yaml on disk: %v", serr)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.Integrity.BinaryHash != bh {
		t.Errorf("binary hash drift: got %q want %q", loaded.Integrity.BinaryHash, bh)
	}
	if loaded.Integrity.ConfigHash == "" {
		t.Error("config hash is empty after sign-and-save")
	}
	if err := Verify(fakeBin, loaded); err != nil {
		t.Errorf("Verify should pass on freshly-signed file: %v", err)
	}
}

func TestSignAndSaveAtomic_NoTempFileLeaks(t *testing.T) {
	// On success, the target dir must contain exactly one file
	// (csm.yaml) and zero temp stragglers.
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")

	cfg := &config.Config{ConfigFile: path, Hostname: "x"}
	if err := SignAndSaveAtomic(cfg, "sha256:0000"); err != nil {
		t.Fatalf("SignAndSaveAtomic: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "csm.yaml" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("expected only csm.yaml in dir, got %v", names)
	}
}
