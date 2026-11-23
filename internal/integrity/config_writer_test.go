package integrity

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// The helper takes a signed config from the daemon. It writes only an
// absolute .yaml or .yml path and refuses anything it does not recognise.
func TestReadSignedConfigValidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	data := []byte("hostname: a\n")
	data = append(data, []byte("integrity:\n  config_hash: "+HashConfigStableBytes(data)+"\n")...)
	good, err := json.Marshal(SignedConfig{Path: path, Bytes: data, Fragments: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ReadSignedConfig(bytes.NewReader(good))
	if err != nil || c.Path != path || !bytes.Equal(c.Bytes, data) {
		t.Fatalf("ReadSignedConfig = %+v, %v", c, err)
	}
	for name, in := range map[string]string{
		"relative path":         strings.Replace(string(good), path, "csm.yaml", 1),
		"unclean path":          strings.Replace(string(good), path, filepath.Dir(path)+"/../csm.yaml", 1),
		"not yaml":              strings.Replace(string(good), path, filepath.Join(filepath.Dir(path), "other.conf"), 1),
		"unknown member":        strings.TrimSuffix(string(good), "}") + `,"mode":"0777"}`,
		"not json":              `path=/etc/csm/csm.yaml`,
		"too large":             `{"path":"/etc/csm/csm.yaml","bytes":"` + strings.Repeat("A", maxSignedConfigBytes) + `"}`,
		"padded past the limit": string(good) + strings.Repeat(" ", maxSignedConfigBytes),
	} {
		if _, err := ReadSignedConfig(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Writes land beside the config's resolved target, so that directory is
// the one the helper needs.
func TestResolveConfigWritePathFollowsSymlink(t *testing.T) {
	real := t.TempDir()
	link := t.TempDir()
	target := filepath.Join(real, "csm.yaml")
	if err := os.WriteFile(target, []byte("hostname: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(link, "csm.yaml")); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{target: target, filepath.Join(link, "csm.yaml"): target, filepath.Join(link, "new.yaml"): filepath.Join(link, "new.yaml")} {
		if got, err := ResolveConfigWritePath(path); err != nil || got != want {
			t.Errorf("ResolveConfigWritePath(%s) = %q, %v; want %q", path, got, err, want)
		}
	}
}

// Rollback must use the same writer without replacing backups or fragment records.
func TestRestoreConfigUsesWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	original := []byte("hostname: current\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	restored := []byte("hostname: previous\n")
	wantErr := errors.New("helper refused")
	var calls int
	SetConfigWriter(func(c SignedConfig) error {
		calls++
		if c.Path != path || !bytes.Equal(c.Bytes, restored) || c.Fragments != nil {
			t.Fatal("restore changed the snapshot or supplied a replacement fragment record")
		}
		return wantErr
	})
	t.Cleanup(func() { SetConfigWriter(nil) })
	if err := WriteConfigBytesAtomic(path, restored); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("writer calls = %d", calls)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, original) {
		t.Fatal("restore bypassed the writer")
	}
}

func TestRecordVerifiedConfDUsesWriter(t *testing.T) {
	cfg, _, _ := signFragmentBaseline(t, "hostname: example.com\n")
	record, err := FragmentRecordPath(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if removeErr := os.Remove(record); removeErr != nil {
		t.Fatal(removeErr)
	}
	before, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("helper refused")
	var handed *SignedConfig
	SetConfigWriter(func(c SignedConfig) error {
		if ConfigWriteMutex().TryLock() {
			ConfigWriteMutex().Unlock()
			t.Error("fragment recording is not serialized with rollback")
		}
		handed = &c
		return wantErr
	})
	t.Cleanup(func() { SetConfigWriter(nil) })
	if recordErr := RecordVerifiedConfD(cfg); !errors.Is(recordErr, wantErr) {
		t.Fatalf("error = %v", recordErr)
	}
	if handed == nil || handed.Path != cfg.ConfigFile || !bytes.Equal(handed.Bytes, before) {
		t.Fatal("verified config was not handed to writer unchanged")
	}
	if validateErr := (fragmentRecord{ConfdHash: handed.ConfdHash, Fragments: handed.Fragments}).validate(); validateErr != nil {
		t.Fatal(validateErr)
	}
	if _, statErr := os.Stat(record); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("daemon wrote fragment record directly")
	}
	body, err := json.Marshal(handed)
	if err != nil {
		t.Fatal(err)
	}
	received, err := ReadSignedConfig(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("helper refused a verified fragment snapshot: %v", err)
	}
	if writeErr := WriteSignedConfig(received); writeErr != nil {
		t.Fatal(writeErr)
	}
	rec, err := readFragmentRecord(cfg.ConfigFile)
	if err != nil || rec.ConfdHash != cfg.Integrity.ConfdHash {
		t.Fatalf("written fragment record: %v", err)
	}
}

func TestReadSignedConfigRejectsUnsignedOrMismatchedData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	valid := []byte("hostname: example.com\n")
	valid = append(valid, []byte("integrity:\n  config_hash: "+HashConfigStableBytes(valid)+"\n")...)
	for name, c := range map[string]SignedConfig{
		"unsigned":          {Path: path, Bytes: []byte("hostname: example.com\n")},
		"invalid YAML":      {Path: path, Bytes: []byte("hostname: [\n")},
		"stale hash":        {Path: path, Bytes: bytes.ReplaceAll(valid, []byte("example.com"), []byte("changed.example.com"))},
		"fragment digest":   {Path: path, Bytes: valid, ConfdHash: "sha256:wrong", Fragments: map[string][]byte{}},
		"fragment contents": {Path: path, Bytes: valid, Fragments: map[string][]byte{"test.yaml": []byte("hostname: other\n")}},
	} {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadSignedConfig(bytes.NewReader(body)); err == nil {
				t.Fatal("accepted invalid signed config")
			}
		})
	}
}

func TestReadSignedConfigRejectsNonYAMLTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "other.conf")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "csm.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	data := []byte("hostname: example.com\n")
	data = append(data, []byte("integrity:\n  config_hash: "+HashConfigStableBytes(data)+"\n")...)
	body, err := json.Marshal(SignedConfig{Path: link, Bytes: data})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSignedConfig(bytes.NewReader(body)); err == nil {
		t.Fatal("accepted a non-YAML resolved target")
	}
}
