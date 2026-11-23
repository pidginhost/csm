package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
)

type helperCall struct {
	name  string
	args  []string
	input []byte
}

func fakeHelper(calls *[]helperCall, err error) func(context.Context, []byte, string, ...string) ([]byte, error) {
	return func(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
		*calls = append(*calls, helperCall{name, args, input})
		return nil, err
	}
}

func systemdRunFound(string) (string, error) { return "/usr/bin/systemd-run", nil }

// helperRuns are the calls that ran the helper, not systemd-run's probe.
func helperRuns(calls []helperCall) []helperCall {
	var out []helperCall
	for _, c := range calls {
		if len(c.args) > 0 && c.args[len(c.args)-1] == integrity.ConfigWriteCommand {
			out = append(out, c)
		}
	}
	return out
}

// The daemon's sandbox cannot write its config directory, so a save goes to
// csm config-write in a transient unit whose only writable path is that
// directory.
func TestConfigWriterRunsHelperInNarrowUnit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []helperCall
	data := []byte("hostname: b\n")
	data = append(data, []byte("integrity:\n  config_hash: "+integrity.HashConfigStableBytes(data)+"\n")...)
	c := integrity.SignedConfig{Path: path, Bytes: data, Fragments: map[string][]byte{}}
	if err := runConfigWriter(context.Background(), "/opt/csm/csm", systemdRunFound, fakeHelper(&calls, nil), c); err != nil {
		t.Fatal(err)
	}
	calls = helperRuns(calls)
	if len(calls) != 1 || calls[0].name != "/usr/bin/systemd-run" {
		t.Fatalf("helper runs = %+v, want one through systemd-run", calls)
	}
	args := calls[0].args
	for _, want := range []string{"--property=ProtectSystem=strict", "--property=ReadWritePaths=" + dir, "--property=NoNewPrivileges=yes", "--property=PrivateNetwork=yes", "--property=PrivateTmp=no"} {
		if !slices.Contains(args, want) {
			t.Errorf("args %q lack %s", args, want)
		}
	}
	if !slices.Equal(args[len(args)-3:], []string{"--", "/opt/csm/csm", integrity.ConfigWriteCommand}) {
		t.Fatalf("args %q do not end with the helper command", args)
	}
	got, err := integrity.ReadSignedConfig(bytes.NewReader(calls[0].input))
	if err != nil || got.Path != path || !bytes.Equal(got.Bytes, data) {
		t.Fatalf("helper input = %+v, %v", got, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "hostname: a\n" {
		t.Fatal("the daemon wrote the config itself")
	}
}

// A failed helper is a failed save, and a directory that cannot be named in
// a unit property is refused before anything runs.
func TestConfigWriterFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []helperCall
	err := runConfigWriter(context.Background(), "/opt/csm/csm", systemdRunFound, fakeHelper(&calls, errors.New("exit status 1: config-write: denied")), integrity.SignedConfig{Path: path})
	if err == nil || !strings.Contains(err.Error(), "denied") || len(helperRuns(calls)) != 1 {
		t.Fatalf("err = %v, want the helper's failure", err)
	}
	odd := filepath.Join(t.TempDir(), "a dir")
	if err := os.Mkdir(odd, 0o700); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err := runConfigWriter(context.Background(), "/opt/csm/csm", systemdRunFound, fakeHelper(&calls, nil), integrity.SignedConfig{Path: filepath.Join(odd, "csm.yaml")}); err == nil || len(helperRuns(calls)) != 0 {
		t.Fatalf("err = %v, calls %d: want a refusal before running", err, len(calls))
	}
}

// Every save the daemon makes goes through the helper once routed.
func TestRouteConfigWritesSendsSavesToTheHelper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	data := []byte("hostname: example.com\nintegrity:\n  binary_hash: \"sha256:stale\"\n  config_hash: \"sha256:stale\"\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []helperCall
	prevLook, prevRun := configWriterLookPath, configWriterRun
	configWriterLookPath, configWriterRun = systemdRunFound, fakeHelper(&calls, nil)
	t.Cleanup(func() {
		configWriterLookPath, configWriterRun = prevLook, prevRun
		integrity.SetConfigWriter(nil)
	})
	routeConfigWrites()
	clone, err := config.LoadBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	clone.ConfigFile = path
	if err := integrity.SignAndSavePreserving(path, "", data, clone, "sha256:bin"); err != nil {
		t.Fatal(err)
	}
	if len(helperRuns(calls)) != 1 {
		t.Fatalf("calls = %+v, want the save handed to the helper", calls)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, data) {
		t.Fatal("the daemon wrote the config itself")
	}
}

// A relative legacy path must be resolved before PID 1 starts the helper
// with a different working directory.
func TestConfigWriterResolvesRelativeAndSymlinkedPaths(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(realDir, "actual.yaml")
	if err := os.WriteFile(path, []byte("hostname: before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "parent")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("parent/actual.yaml", filepath.Join(root, "legacy.yaml")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	for _, inputPath := range []string{"legacy.yaml", "parent/actual.yaml"} {
		var calls []helperCall
		c := integrity.SignedConfig{Path: inputPath, Bytes: []byte("hostname: after\n")}
		if err := runConfigWriter(context.Background(), "/opt/csm/csm", systemdRunFound, fakeHelper(&calls, nil), c); err != nil {
			t.Fatal(err)
		}
		runs := helperRuns(calls)
		if len(runs) != 1 {
			t.Fatalf("helper runs = %d", len(runs))
		}
		var got integrity.SignedConfig
		if err := json.Unmarshal(runs[0].input, &got); err != nil {
			t.Fatal(err)
		}
		if got.Path != path || !slices.Contains(runs[0].args, "--property=ReadWritePaths="+realDir) {
			t.Fatal("helper did not receive the resolved path and directory")
		}
	}
}

func TestConfigWriterWithoutSystemdRun(t *testing.T) {
	var calls []helperCall
	wantErr := errors.New("direct helper failed")
	err := runConfigWriter(context.Background(), "/opt/csm/csm", func(string) (string, error) { return "", exec.ErrNotFound }, fakeHelper(&calls, wantErr), integrity.SignedConfig{Path: filepath.Join(t.TempDir(), "csm.yaml")})
	if !errors.Is(err, wantErr) || len(calls) != 1 || calls[0].name != "/opt/csm/csm" || !slices.Equal(calls[0].args, []string{integrity.ConfigWriteCommand}) {
		t.Fatalf("direct helper: error = %v, calls = %d", err, len(calls))
	}
}
