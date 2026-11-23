package integrity

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// A process that cannot write the config directory hands the signed result
// to a writer that can. The writer gets exactly what a direct save would
// have written, and nothing is written in the caller's process.
func TestSignAndSaveHandsWritesToTheConfigWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	original := []byte("hostname: example.com\nthresholds:\n  mail_queue_warn: 500\nintegrity:\n  binary_hash: \"sha256:stale\"\n  config_hash: \"sha256:stale\"\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	edited, err := config.YAMLEdit(original, []config.YAMLChange{{Path: []string{"thresholds", "mail_queue_warn"}, Value: 750}})
	if err != nil {
		t.Fatal(err)
	}
	clone, err := config.LoadBytes(edited)
	if err != nil {
		t.Fatal(err)
	}
	clone.ConfigFile = path

	var handed []SignedConfig
	SetConfigWriter(func(c SignedConfig) error {
		handed = append(handed, c)
		return nil
	})
	t.Cleanup(func() { SetConfigWriter(nil) })
	if err := SignAndSavePreserving(path, "", edited, clone, "sha256:bin"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, original) {
		t.Fatal("the caller wrote the config itself")
	}
	if _, err := os.Stat(path + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the caller wrote the backup itself")
	}
	if len(handed) != 1 || handed[0].Path != path || !bytes.Contains(handed[0].Bytes, []byte("mail_queue_warn: 750")) ||
		!bytes.Contains(handed[0].Bytes, []byte(clone.Integrity.ConfigHash)) || handed[0].ConfdHash != clone.Integrity.ConfdHash {
		t.Fatalf("handed = %+v", handed)
	}

	// Writing what was handed over produces the signed file and its backup.
	if err := WriteSignedConfig(handed[0]); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, handed[0].Bytes) {
		t.Fatal("WriteSignedConfig did not write the signed bytes")
	}
	if got, _ := os.ReadFile(path + ".bak"); !bytes.Equal(got, original) {
		t.Fatal("WriteSignedConfig did not keep the previous file")
	}
	if got, _ := os.ReadFile(path); HashConfigStableBytes(got) != clone.Integrity.ConfigHash {
		t.Fatal("the written config does not carry the hash it was signed with")
	}
}

// A writer failure is the save's failure.
func TestSignAndSaveReportsConfigWriterFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	data := []byte("hostname: example.com\nintegrity:\n  binary_hash: \"sha256:stale\"\n  config_hash: \"sha256:stale\"\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	clone, err := config.LoadBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	clone.ConfigFile = path
	SetConfigWriter(func(SignedConfig) error { return errors.New("helper refused") })
	t.Cleanup(func() { SetConfigWriter(nil) })
	if err := SignAndSavePreserving(path, "", data, clone, "sha256:bin"); err == nil || err.Error() != "helper refused" {
		t.Fatalf("err = %v, want the writer's failure", err)
	}
}
