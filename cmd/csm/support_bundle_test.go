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
	"net/url"
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
		if err := json.Unmarshal(req.Args, &args); err != nil || !args.Stage || len(args.SupportRedactionSHA256) != sha256.Size*2 || args.DstPath != "" {
			return control.Response{Error: "export must ask the daemon to stage"}
		}
		staged := filepath.Join(stageDir, supportBundleExportName)
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
	target := cfg.Reputation.Report.Targets[0]
	for _, name := range []string{cfg.Alerts.Webhook.HMACSecretEnv, cfg.AutoResponse.VerdictCallback.HMACSecretEnv, cfg.Reputation.Upstream.TokenEnv, cfg.Reputation.Rspamd.TokenEnv, target.KeyEnv, target.TokenEnv} {
		t.Setenv(name, "env-"+name)
	}
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
	payload := nestedExport(t, "bbolt.snapshot", []byte("store export archive bytes"))
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
	got, err := supportBundleJournalTail(3, func(s string) string { return s })
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
		{args: []string{"b", "--config="}, wantErr: true},
		{args: []string{"b", "--config-dir", "--journal-lines=2"}, wantErr: true},
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
	_, cleanup := fakeStoreExport(t, nestedExport(t, "state/data", []byte("test entry")), strings.Repeat("0", 64))
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

func nestedExport(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	if err := addBytes(tw, name, data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSupportBundleOmitsSensitiveStoreExport(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = t.Name()
	cfg.StatePath = t.TempDir()
	cfg.Stalwart.APIKeyFile = filepath.Join(cfg.StatePath, "local", "api")
	stubSupportBundleJournal(t, func(int) ([]byte, error) { return []byte("service ready"), nil })
	for _, tc := range []struct{ name, content string }{
		{"bbolt.snapshot", strings.Repeat(".", 65536-520) + cfg.WebUI.AuthToken},
		{"state/webui.key", "test entry"},
		{"state/renamed", "-----BEGIN PRIVATE KEY-----"},
		{"state/local/api", "test entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := nestedExport(t, tc.name, []byte(tc.content))
			sum := sha256.Sum256(payload)
			staged, cleanup := fakeStoreExport(t, payload, hex.EncodeToString(sum[:]))
			defer cleanup()
			out := filepath.Join(t.TempDir(), "bundle")
			failed, err := writeSupportBundle(out, cfg, 100)
			if err != nil {
				t.Fatal(err)
			}
			entries := readSupportBundle(t, out)
			if !slices.Equal(failed, []string{supportBundleExportName}) || len(entries[supportBundleExportName+".err"]) == 0 || entries[supportBundleExportName] != nil || string(entries["journal.txt"]) != "service ready" {
				t.Fatalf("unsafe export disposition: failed %v, entries %v", failed, entryNames(entries))
			}
			if _, err := os.Stat(staged); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staged export remains: %v", err)
			}
		})
	}
}

func TestSupportBundleRedactsBeforeEncodingAndTailing(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = t.Name() + "\nsecond-line"
	cfg.Hostname = cfg.WebUI.AuthToken
	cfg.Reputation.Upstream.TokenEnv = "CSM_BUNDLE_TEST_VALUE"
	t.Setenv(cfg.Reputation.Upstream.TokenEnv, t.Name()+"-from-env")
	stubSupportBundleJournal(t, func(int) ([]byte, error) {
		return []byte(cfg.WebUI.AuthToken + " " + os.Getenv(cfg.Reputation.Upstream.TokenEnv) + "\n"), nil
	})
	out := filepath.Join(t.TempDir(), "bundle")
	save := controlSocketPath
	controlSocketPath = shortSockPath(t)
	t.Cleanup(func() { controlSocketPath = save })
	if _, err := writeSupportBundle(out, cfg, 1); err != nil {
		t.Fatal(err)
	}
	entries := readSupportBundle(t, out)
	var got config.Config
	if err := yaml.Unmarshal(entries["config.yaml"], &got); err != nil {
		t.Fatal(err)
	}
	if got.Hostname != config.RedactedValue {
		t.Error("duplicate multiline credential in configuration")
	}
	if string(entries["journal.txt"]) != config.RedactedValue+" "+config.RedactedValue+"\n" {
		t.Error("unscrubbed journal tail")
	}
}

func TestSupportBundleRejectsSharedDestination(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "bundle")
	if _, err := writeSupportBundle(out, &config.Config{}, 1); err == nil {
		t.Fatal("accepted a directory writable by other accounts")
	}
}

func TestSupportBundleLegacyDaemonCannotClobberExport(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	dir := filepath.Join(cfg.StatePath, "exports")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dir, supportBundleExportName)
	if err := os.WriteFile(existing, []byte("previous export"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup := fakeDaemon(t, func(req control.Request) control.Response {
		var args control.StoreExportArgs
		if err := json.Unmarshal(req.Args, &args); err != nil {
			return control.Response{Error: err.Error()}
		}
		if args.DstPath == "" {
			return control.Response{Error: "dst_path is required"}
		}
		if args.DstPath != existing {
			t.Error("collector supplied a writable destination")
			return control.Response{Error: "unexpected destination"}
		}
		if err := os.WriteFile(args.DstPath, []byte("legacy output"), 0o600); err != nil {
			return control.Response{Error: err.Error()}
		}
		return control.Response{Error: "legacy daemon wrote the destination"}
	})
	defer cleanup()
	if _, err := requestSupportBundleExport(nil); err == nil {
		t.Fatal("legacy daemon unexpectedly supplied a diagnostic export")
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "previous export" {
		t.Fatal("existing export was overwritten")
	}
}

func TestSupportBundleBoundsJournalOutput(t *testing.T) {
	dir := t.TempDir()
	script := []byte("#!/bin/sh\nexec /usr/bin/head -c 33554432 /dev/zero\n")
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), script, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if out, err := supportBundleJournal(1); err == nil || !strings.Contains(err.Error(), "exceeds") || len(out) != 0 {
		t.Fatalf("oversized journal entry: got %d bytes, error %v", len(out), err)
	}
}

func TestSupportBundleSystemReportsConfiguredWebServer(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.Type = "litespeed"
	if !bytes.Contains(supportBundleSystem(cfg, nil), []byte("\nweb server: litespeed\n")) {
		t.Fatal("system report ignored web_server.type")
	}
}

type mutateExportAtHeader struct {
	io.Writer
	mutate func()
}

func (w *mutateExportAtHeader) Write(data []byte) (int, error) {
	if w.mutate != nil {
		w.mutate()
		w.mutate = nil
	}
	return w.Writer.Write(data)
}

func TestSupportBundleChecksCopiedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "export")
	payload := nestedExport(t, "state/data", []byte("test entry"))
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	res := control.StoreExportResult{Path: path, Bytes: int64(len(payload)), ArchiveSHA256: hex.EncodeToString(sum[:])}
	tw := tar.NewWriter(&mutateExportAtHeader{Writer: io.Discard, mutate: func() {
		if err := os.WriteFile(path, bytes.Repeat([]byte("."), len(payload)), 0o600); err != nil {
			t.Fatal(err)
		}
	}})
	if err := addVerifiedStoreExport(tw, &res); err == nil {
		t.Fatal("accepted unverified bytes during copy")
	}
}

func TestSupportBundleScrubsLoggedURL(t *testing.T) {
	u := url.URL{Scheme: "https", Host: "example.org", Path: "/callback/" + t.Name(), User: url.UserPassword("operator", t.Name())}
	cfg := &config.Config{}
	cfg.Alerts.Webhook.URL = u.String()
	stubSupportBundleJournal(t, func(int) ([]byte, error) { return []byte(u.Redacted()), nil })
	save := controlSocketPath
	controlSocketPath = shortSockPath(t)
	t.Cleanup(func() { controlSocketPath = save })
	out := filepath.Join(t.TempDir(), "bundle")
	if _, err := writeSupportBundle(out, cfg, 1); err != nil {
		t.Fatal(err)
	}
	if string(readSupportBundle(t, out)["journal.txt"]) != config.RedactedValue {
		t.Fatal("logged URL still exposes its credential-bearing path")
	}
}

func TestSupportBundleUnavailableServiceCredential(t *testing.T) {
	cfg := &config.Config{}
	cfg.Reputation.Upstream.TokenEnv = "CSM_BUNDLE_TEST_UNAVAILABLE"
	t.Setenv(cfg.Reputation.Upstream.TokenEnv, "")
	stubSupportBundleJournal(t, func(int) ([]byte, error) { return []byte("service log"), nil })
	payload := nestedExport(t, "bbolt.snapshot", []byte("store"))
	sum := sha256.Sum256(payload)
	_, cleanup := fakeStoreExport(t, payload, hex.EncodeToString(sum[:]))
	defer cleanup()
	out := filepath.Join(t.TempDir(), "bundle")
	failed, err := writeSupportBundle(out, cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	entries := readSupportBundle(t, out)
	if !slices.Equal(failed, []string{"journal.txt", supportBundleExportName}) || len(entries["config.yaml"]) == 0 || len(entries["system.txt"]) == 0 || entries["journal.txt"] != nil || entries[supportBundleExportName] != nil {
		t.Fatalf("unavailable credential: entries %v", entryNames(entries))
	}
}

func TestSupportBundleJournalPreservesFailureReason(t *testing.T) {
	dir := t.TempDir()
	script := []byte("#!/bin/sh\necho 'journal unavailable' >&2\nexit 1\n")
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), script, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if _, err := supportBundleJournal(1); err == nil || !strings.Contains(err.Error(), "journal unavailable") {
		t.Fatalf("journal error lacks its reason: %v", err)
	}
}

func TestSupportBundleScrubsConfiguredMapKeys(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = t.Name()
	cfg.Incidents.AutoClose.ByKind = map[string]string{t.Name(): "1h", "public": "2h"}
	data, err := supportConfigYAML(cfg, strings.NewReplacer(t.Name(), config.RedactedValue).Replace)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(t.Name())) {
		t.Fatal("configured map key exposed credential")
	}
	var got config.Config
	if err := yaml.Unmarshal(data, &got); err != nil || got.Incidents.AutoClose.ByKind["public"] != "2h" {
		t.Fatal("lost public config value")
	}
}

func TestSupportBundleTruncatedJournalErrorHidesPartialValues(t *testing.T) {
	dir := t.TempDir()
	script := []byte("#!/bin/sh\necho " + strings.Repeat("X", 4100) + " >&2\nexit 1\n")
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), script, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	_, err := supportBundleJournal(1)
	if err == nil || strings.Contains(err.Error(), "XXX") {
		t.Fatal("truncated stderr exposed partial text")
	}
}

func TestSupportBundleMismatchedServiceConfiguration(t *testing.T) {
	cleanup := fakeDaemon(t, func(control.Request) control.Response {
		return control.Response{Error: "the running daemon and collector have different redaction settings"}
	})
	defer cleanup()
	stubSupportBundleJournal(t, func(int) ([]byte, error) { return []byte("service data"), nil })
	out := filepath.Join(t.TempDir(), "bundle")
	failed, err := writeSupportBundle(out, &config.Config{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	entries := readSupportBundle(t, out)
	if !slices.Equal(failed, []string{"journal.txt", supportBundleExportName}) || entries["journal.txt"] != nil {
		t.Fatalf("included live data for mismatched configuration: %v", entryNames(entries))
	}
}

func TestSupportBundleScrubsCredentialsInDownloadURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.Signatures.UpdateURL = "https://example.org/rules?access_token=" + t.Name()
	saved := controlSocketPath
	controlSocketPath = shortSockPath(t)
	t.Cleanup(func() { controlSocketPath = saved })
	stubSupportBundleJournal(t, func(int) ([]byte, error) { return []byte(t.Name()), nil })
	out := filepath.Join(t.TempDir(), "bundle")
	if _, err := writeSupportBundle(out, cfg, 1); err != nil {
		t.Fatal(err)
	}
	entries := readSupportBundle(t, out)
	if bytes.Contains(entries["config.yaml"], []byte(t.Name())) || string(entries["journal.txt"]) != config.RedactedValue {
		t.Fatal("authenticated download URL or its access token was disclosed")
	}
}

func TestSupportBundleScrubsBinaryYAMLValues(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = string([]byte{0xff}) + t.Name()
	cfg.Hostname = cfg.WebUI.AuthToken
	data, err := supportConfigYAML(cfg, strings.NewReplacer(cfg.WebUI.AuthToken, config.RedactedValue).Replace)
	if err != nil {
		t.Fatal(err)
	}
	var got config.Config
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Hostname != config.RedactedValue {
		t.Fatal("binary YAML exposed a duplicate credential")
	}
}
