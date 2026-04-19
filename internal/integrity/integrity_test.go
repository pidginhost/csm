package integrity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestHashConfigStable_ToleratesLongLines(t *testing.T) {
	// The scanner is sized at 1 MiB. A 70 KiB line must produce a
	// real digest rather than an error; callers can compare the
	// digest against the stored ConfigHash and fail Verify there if
	// the content drifted. Erroring inside HashConfigStable would
	// mean the daemon can't even START against a corrupted file to
	// tell the operator what is wrong.
	path := filepath.Join(t.TempDir(), "csm.yaml")
	longLine := strings.Repeat("a", 70*1024)
	data := "hostname: test.example\n" + longLine + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	h, err := HashConfigStable(path)
	if err != nil {
		t.Fatalf("HashConfigStable: got error %v, want success", err)
	}
	if !strings.HasPrefix(h, "sha256:") {
		t.Errorf("digest shape: got %q want sha256:...", h)
	}
}

func TestHashConfigStable_TruncatesOversizedLinesDeterministically(t *testing.T) {
	// Beyond the 1 MiB cap the scanner silently truncates the line.
	// Two files differing only past the truncation point must still
	// produce the same digest (the trailing content is invisible).
	// Verify can still catch drift vs a stored hash because any
	// operator edit that adds or removes non-oversized content
	// changes the digest.
	dir := t.TempDir()
	huge := strings.Repeat("b", 2*1024*1024) // 2 MiB, past the 1 MiB cap
	base := "hostname: test.example\n"

	pathA := filepath.Join(dir, "a.yaml")
	pathB := filepath.Join(dir, "b.yaml")
	if err := os.WriteFile(pathA, []byte(base+huge+"DIFFERENT_TAIL_A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte(base+huge+"DIFFERENT_TAIL_B\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ha, err := HashConfigStable(pathA)
	if err != nil {
		t.Fatalf("HashConfigStable a: %v", err)
	}
	hb, err := HashConfigStable(pathB)
	if err != nil {
		t.Fatalf("HashConfigStable b: %v", err)
	}
	if ha != hb {
		t.Errorf("truncation should hide tail differences: a=%s b=%s", ha, hb)
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
