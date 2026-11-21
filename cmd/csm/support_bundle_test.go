package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"gopkg.in/yaml.v3"
)

// fillConfigStrings gives every reachable string field its own value, so
// any field Redact hides holds a value the bundle must not carry.
func fillConfigStrings(v reflect.Value, n *int) {
	switch v.Kind() {
	case reflect.String:
		*n++
		v.SetString(fmt.Sprintf("bundle-secret-%03d-value", *n))
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				fillConfigStrings(v.Field(i), n)
			}
		}
	case reflect.Pointer:
		if v.IsNil() && v.Type().Elem().Kind() == reflect.Struct {
			v.Set(reflect.New(v.Type().Elem()))
		}
		if !v.IsNil() {
			fillConfigStrings(v.Elem(), n)
		}
	case reflect.Slice:
		if k := v.Type().Elem().Kind(); k == reflect.String || k == reflect.Struct {
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
			fillConfigStrings(v.Index(0), n)
		}
	}
}

// redactedYAMLValues lists the original value of every YAML leaf that
// Redact changes. It reads the YAML rendering, not the struct, so it does
// not share the walker the bundle uses.
func redactedYAMLValues(t *testing.T, cfg *config.Config) []string {
	t.Helper()
	tree := func(c *config.Config) any {
		data, err := yaml.Marshal(c)
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		var out any
		if err := yaml.Unmarshal(data, &out); err != nil {
			t.Fatalf("unmarshal config: %v", err)
		}
		return out
	}
	var out []string
	var walk func(orig, red any)
	walk = func(orig, red any) {
		switch o := orig.(type) {
		case map[string]any:
			r, _ := red.(map[string]any)
			for k, v := range o {
				walk(v, r[k])
			}
		case []any:
			r, _ := red.([]any)
			for i, v := range o {
				if i < len(r) {
					walk(v, r[i])
				}
			}
		case string:
			if red != o {
				out = append(out, o)
			}
		}
	}
	walk(tree(cfg), tree(config.Redact(cfg)))
	return out
}

func readSupportBundle(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer func() { _ = f.Close() }()
	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	entries := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return entries
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", hdr.Name, err)
		}
		entries[hdr.Name] = data
	}
}

func entryNames(entries map[string][]byte) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// fakeStoreExport answers store.export the way a staging daemon does: it
// writes the archive under its own directory and returns that path.
func fakeStoreExport(t *testing.T, payload []byte, digest string) (stagedPath string, cleanup func()) {
	t.Helper()
	stageDir := filepath.Join(t.TempDir(), "exports", "export-1")
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cleanup = fakeDaemon(t, func(req control.Request) control.Response {
		if req.Cmd != control.CmdStoreExport {
			return control.Response{Error: "unexpected command " + req.Cmd}
		}
		var args control.StoreExportArgs
		if err := json.Unmarshal(req.Args, &args); err != nil || !args.Stage {
			return control.Response{Error: "export must ask the daemon to stage"}
		}
		staged := filepath.Join(stageDir, filepath.Base(args.DstPath))
		if err := os.WriteFile(staged, payload, 0o600); err != nil {
			return control.Response{Error: err.Error()}
		}
		if err := os.WriteFile(staged+".sha256", []byte(digest+"\n"), 0o600); err != nil {
			return control.Response{Error: err.Error()}
		}
		res, _ := json.Marshal(control.StoreExportResult{Path: staged, Bytes: int64(len(payload)), ArchiveSHA256: digest, BboltSHA256: "bolt-digest"})
		return control.Response{OK: true, Result: res}
	})
	return filepath.Join(stageDir, supportBundleExportName), cleanup
}

func stubSupportBundleJournal(t *testing.T, fn func(int) ([]byte, error)) {
	t.Helper()
	prev := supportBundleJournal
	supportBundleJournal = fn
	t.Cleanup(func() { supportBundleJournal = prev })
}

func TestSupportBundleHoldsPartsWithoutConfiguredSecrets(t *testing.T) {
	cfg := &config.Config{}
	n := 0
	fillConfigStrings(reflect.ValueOf(cfg).Elem(), &n)
	secrets := redactedYAMLValues(t, cfg)
	// The oracle must see scalar, list and URL secrets, or it proves nothing.
	for _, want := range []string{cfg.WebUI.AuthToken, cfg.WebUI.Tokens[0].Token, cfg.Alerts.Webhook.URL} {
		if !slices.Contains(secrets, want) {
			t.Fatalf("oracle missed secret %q; found %d secrets", want, len(secrets))
		}
	}

	// A journal that echoes every secret, as a logged URL error would.
	stubSupportBundleJournal(t, func(int) ([]byte, error) {
		return []byte("daemon started\nPost " + strings.Join(secrets, " failed\nPost ") + " failed\n"), nil
	})
	payload := []byte("store export archive bytes")
	sum := sha256.Sum256(payload)
	stagedPath, cleanup := fakeStoreExport(t, payload, hex.EncodeToString(sum[:]))
	defer cleanup()

	out := filepath.Join(t.TempDir(), "bundle.tar.zst")
	failed, err := writeSupportBundle(out, cfg, 1000)
	if err != nil {
		t.Fatalf("writeSupportBundle: %v", err)
	}
	if len(failed) != 0 {
		t.Fatalf("failed parts = %v, want none", failed)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode = %v, want 0600", info.Mode().Perm())
	}

	entries := readSupportBundle(t, out)
	if got, want := strings.Join(entryNames(entries), ","), "config.yaml,journal.txt,store-export.tar.zst,system.txt"; got != want {
		t.Fatalf("entries = %s, want %s", got, want)
	}
	if !bytes.Equal(entries["store-export.tar.zst"], payload) {
		t.Fatalf("store export entry = %q, want the staged archive", entries["store-export.tar.zst"])
	}
	for _, name := range []string{"config.yaml", "journal.txt"} {
		if !bytes.Contains(entries[name], []byte(config.RedactedValue)) {
			t.Fatalf("%s carries no redaction marker:\n%s", name, entries[name])
		}
	}
	if !bytes.Contains(entries["system.txt"], []byte(hex.EncodeToString(sum[:]))) {
		t.Fatalf("system.txt lacks the store export digest:\n%s", entries["system.txt"])
	}
	for name, data := range entries {
		for _, secret := range secrets {
			if bytes.Contains(data, []byte(secret)) {
				t.Errorf("%s contains configured secret %q", name, secret)
			}
		}
	}
	if _, err := os.Stat(stagedPath); !os.IsNotExist(err) {
		t.Fatalf("staged export left behind: %v", err)
	}
}

func TestSupportBundleJournalTailHonoursLineCount(t *testing.T) {
	var asked int
	stubSupportBundleJournal(t, func(n int) ([]byte, error) {
		asked = n
		var b strings.Builder
		for i := 1; i <= 10; i++ {
			fmt.Fprintf(&b, "line %d\n", i)
		}
		return []byte(b.String()), nil
	})
	got, err := supportBundleJournalTail(3)
	if err != nil {
		t.Fatal(err)
	}
	if asked != 3 {
		t.Fatalf("journal asked for %d lines, want 3", asked)
	}
	if want := "line 8\nline 9\nline 10\n"; string(got) != want {
		t.Fatalf("tail = %q, want %q", got, want)
	}
}

func TestParseSupportBundleArgs(t *testing.T) {
	tests := []struct {
		args    []string
		path    string
		lines   int
		wantErr bool
	}{
		{args: []string{"/root/b.tar.zst"}, path: "/root/b.tar.zst", lines: defaultSupportBundleJournalLines},
		{args: []string{"b.tar.zst", "--journal-lines", "25"}, path: "b.tar.zst", lines: 25},
		{args: []string{"--journal-lines=40", "--config", "/etc/csm/csm.yaml", "b.tar.zst"}, path: "b.tar.zst", lines: 40},
		{args: []string{"b.tar.zst", "--journal-lines", "0"}, wantErr: true},
		{args: []string{"b.tar.zst", "--journal-lines"}, wantErr: true},
		{args: []string{"b.tar.zst", "--bogus"}, wantErr: true},
		{args: []string{"a.tar.zst", "b.tar.zst"}, wantErr: true},
		{args: nil, wantErr: true},
	}
	for _, tt := range tests {
		path, lines, err := parseSupportBundleArgs(tt.args)
		if tt.wantErr {
			if err == nil {
				t.Errorf("%q: want error, got path %q lines %d", tt.args, path, lines)
			}
			continue
		}
		if err != nil || path != tt.path || lines != tt.lines {
			t.Errorf("%q = (%q, %d, %v), want (%q, %d)", tt.args, path, lines, err, tt.path, tt.lines)
		}
	}
}

func TestSupportBundleRefusesExistingPath(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle.tar.zst")
	if err := os.WriteFile(out, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeSupportBundle(out, &config.Config{}, 10); err == nil {
		t.Fatal("writeSupportBundle overwrote an existing path")
	}
	if data, _ := os.ReadFile(out); string(data) != "keep me" {
		t.Fatalf("existing file changed to %q", data)
	}
}

func TestSupportBundleRemovesPartialFileOnError(t *testing.T) {
	stubSupportBundleJournal(t, func(int) ([]byte, error) { return []byte("x\n"), nil })
	_, cleanup := fakeStoreExport(t, []byte("tampered"), strings.Repeat("0", 64))
	defer cleanup()

	out := filepath.Join(t.TempDir(), "bundle.tar.zst")
	if _, err := writeSupportBundle(out, &config.Config{}, 10); err == nil {
		t.Fatal("writeSupportBundle accepted a staged export that does not match its digest")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("partial bundle left at %s: %v", out, err)
	}
}

func TestSupportBundleRecordsUnavailableParts(t *testing.T) {
	saved := controlSocketPath
	controlSocketPath = shortSockPath(t)
	t.Cleanup(func() { controlSocketPath = saved })
	stubSupportBundleJournal(t, func(int) ([]byte, error) { return nil, errors.New("journalctl not found") })

	out := filepath.Join(t.TempDir(), "bundle.tar.zst")
	failed, err := writeSupportBundle(out, &config.Config{}, 10)
	if err != nil {
		t.Fatalf("writeSupportBundle: %v", err)
	}
	if got := strings.Join(failed, ","); got != "journal.txt,store-export.tar.zst" {
		t.Fatalf("failed parts = %s", got)
	}
	entries := readSupportBundle(t, out)
	if got, want := strings.Join(entryNames(entries), ","), "config.yaml,journal.txt.err,store-export.tar.zst.err,system.txt"; got != want {
		t.Fatalf("entries = %s, want %s", got, want)
	}
	if !strings.Contains(string(entries["store-export.tar.zst.err"]), "daemon not running") {
		t.Fatalf("store export error = %q", entries["store-export.tar.zst.err"])
	}
}
