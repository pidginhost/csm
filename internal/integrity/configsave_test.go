package integrity

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestSignAndSavePreservingRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")

	original := []byte(`hostname: example.com

# Keep this comment
thresholds:
  mail_queue_warn: 500

integrity:
  binary_hash: "sha256:stale"
  config_hash: "sha256:stale"
`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	edited, err := config.YAMLEdit(original, []config.YAMLChange{
		{Path: []string{"thresholds", "mail_queue_warn"}, Value: 750},
	})
	if err != nil {
		t.Fatal(err)
	}
	clone, err := config.LoadBytes(edited)
	if err != nil {
		t.Fatal(err)
	}
	clone.ConfigFile = path

	if serr := SignAndSavePreserving(path, "", edited, clone, "sha256:newbinary"); serr != nil {
		t.Fatalf("save: %v", serr)
	}

	final, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(final), "# Keep this comment") {
		t.Errorf("operator comment was lost")
	}
	if !strings.Contains(string(final), "mail_queue_warn: 750") {
		t.Errorf("edit not reflected: %s", final)
	}
	if stripIntegrityBlock(string(final)) != stripIntegrityBlock(string(edited)) {
		t.Errorf("non-integrity bytes drifted:\nfinal = %q\nedited = %q", final, edited)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Integrity.BinaryHash != "sha256:newbinary" {
		t.Errorf("binary_hash = %q", loaded.Integrity.BinaryHash)
	}
	stable, _ := HashConfigStable(path)
	if loaded.Integrity.ConfigHash != stable {
		t.Errorf("config_hash mismatch:\n  got  = %q\n  want = %q", loaded.Integrity.ConfigHash, stable)
	}

	expected := *clone
	expected.Integrity.BinaryHash = "sha256:newbinary"
	expected.Integrity.ConfigHash = loaded.Integrity.ConfigHash
	if !reflect.DeepEqual(loaded, &expected) {
		t.Errorf("loaded != intended clone")
	}
}

func TestSignConfigFilePreservingFollowsConfigSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "etc", "csm.yaml")
	link := filepath.Join(dir, "opt", "csm.yaml")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("hostname: prod\nintegrity:\n  binary_hash: \"sha256:old\"\n  config_hash: \"sha256:old\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	configHash, _, err := SignConfigFilePreserving(link, "", "sha256:newbin")
	if err != nil {
		t.Fatalf("SignConfigFilePreserving: %v", err)
	}
	if configHash == "" {
		t.Fatal("config hash is empty")
	}
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatal("config symlink was replaced, want symlink preserved")
	}
	final, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(final), "binary_hash: sha256:newbin") {
		t.Fatalf("target config was not signed through symlink:\n%s", final)
	}
}

func TestSignAndSavePreservingRejectsDrift(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Bytes claim hostname: b but intendedClone says hostname: a.
	bogus := []byte("hostname: b\nintegrity:\n  binary_hash: \"\"\n  config_hash: \"\"\n")
	applied, _ := config.LoadBytes([]byte("hostname: a\n"))
	applied.ConfigFile = path

	err := SignAndSavePreserving(path, "", bogus, applied, "sha256:bin")
	if err == nil {
		t.Fatal("expected drift error, got nil")
	}
	if !strings.Contains(err.Error(), "drift") && !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error does not mention drift/mismatch: %v", err)
	}

	unchanged, _ := os.ReadFile(path)
	if string(unchanged) != "hostname: a\n" {
		t.Errorf("file touched despite drift: %q", unchanged)
	}
}
