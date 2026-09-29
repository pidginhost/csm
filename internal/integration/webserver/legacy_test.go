package webserver

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

const legacyBody = "RewriteMap csm_challenge \"txt:/var/cache/csm/challenge_ips.txt\"\n"

// newLegacyInstaller returns a test installer whose legacy snippet sits
// next to the integration snippet, as on cPanel, with the legacy file
// already deployed by an older installer.
func newLegacyInstaller(t *testing.T, h *fakeHandler) (*Installer, string) {
	t.Helper()
	i := newTestInstaller(t, h)
	legacy := filepath.Join(filepath.Dir(h.path), "csm_challenge.conf")
	if err := os.WriteFile(legacy, []byte(legacyBody), 0o644); err != nil {
		t.Fatal(err)
	}
	i.LegacySnippetPath = legacy
	return i, legacy
}

func assertLegacyRestored(t *testing.T, legacy string) {
	t.Helper()
	got, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatalf("legacy snippet not restored: %v", err)
	}
	if !bytes.Equal(got, []byte(legacyBody)) {
		t.Fatalf("legacy snippet restored as %q, want %q", got, legacyBody)
	}
}

func TestInstallRetiresLegacySnippet(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i, legacy := newLegacyInstaller(t, h)

	res, err := i.Install()
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Status != "ok" || !strings.Contains(res.Message, legacy) {
		t.Fatalf("result = %+v, want ok naming the retired %s", res, legacy)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy snippet still present: %v", err)
	}
	if _, err := os.Stat(h.path); err != nil {
		t.Fatalf("integration snippet missing: %v", err)
	}
	if h.validates.Load() != 1 || h.reloads.Load() != 1 {
		t.Fatalf("validate %d, reload %d; want one configtest and one reload for both changes", h.validates.Load(), h.reloads.Load())
	}
}

func TestInstallRestoresLegacySnippetWhenConfigtestFails(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n", validateErr: []error{errors.New("syntax error")}}
	i, legacy := newLegacyInstaller(t, h)

	if _, err := i.Install(); err == nil {
		t.Fatal("expected configtest failure")
	}
	assertLegacyRestored(t, legacy)
	if _, err := os.Stat(h.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("integration snippet left behind after rollback: %v", err)
	}
	if h.reloads.Load() != 0 {
		t.Fatalf("reload ran %d times after a failed configtest", h.reloads.Load())
	}
}

func TestInstallRestoresLegacySnippetWhenReloadFails(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n", reloadErr: []error{errors.New("reload returned 1")}}
	i, legacy := newLegacyInstaller(t, h)

	if _, err := i.Install(); err == nil {
		t.Fatal("expected reload failure")
	}
	assertLegacyRestored(t, legacy)
	if h.reloads.Load() != 2 {
		t.Fatalf("reload ran %d times; want failed reload plus recovery reload", h.reloads.Load())
	}
}

// A host that ran the integration before the installer stopped shipping
// the legacy snippet carries both. Upgrading a current snippet must still
// retire the legacy one instead of reporting a no-op.
func TestUpgradeRetiresLegacySnippetBesideCurrentSnippet(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	if _, err := i.Install(); err != nil {
		t.Fatalf("first install: %v", err)
	}
	current, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(filepath.Dir(h.path), "csm_challenge.conf")
	if err = os.WriteFile(legacy, []byte(legacyBody), 0o644); err != nil {
		t.Fatal(err)
	}
	i.LegacySnippetPath = legacy

	res, err := i.Upgrade()
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res.Status != "ok" || !strings.Contains(res.Message, legacy) {
		t.Fatalf("result = %+v, want ok naming the retired %s", res, legacy)
	}
	if _, err = os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy snippet still present: %v", err)
	}
	after, err := os.ReadFile(h.path)
	if err != nil || !bytes.Equal(after, current) {
		t.Fatalf("current integration snippet changed: %q, %v", after, err)
	}
	if h.validates.Load() != 2 || h.reloads.Load() != 2 {
		t.Fatalf("validate %d, reload %d; want a second configtest and reload for the retirement", h.validates.Load(), h.reloads.Load())
	}
}

func TestUpgradeRestoresLegacySnippetBesideCurrentSnippetWhenConfigtestFails(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n", validateErr: []error{nil, errors.New("map csm_challenge undefined")}}
	i := newTestInstaller(t, h)
	if _, err := i.Install(); err != nil {
		t.Fatalf("first install: %v", err)
	}
	legacy := filepath.Join(filepath.Dir(h.path), "csm_challenge.conf")
	if err := os.WriteFile(legacy, []byte(legacyBody), 0o644); err != nil {
		t.Fatal(err)
	}
	i.LegacySnippetPath = legacy

	if _, err := i.Upgrade(); err == nil {
		t.Fatal("expected configtest failure")
	}
	assertLegacyRestored(t, legacy)
	if _, err := os.Stat(h.path); err != nil {
		t.Fatalf("current integration snippet removed by rollback: %v", err)
	}
}

func TestInstallLeavesLegacySnippetWhenRefusingOperatorEdits(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i, legacy := newLegacyInstaller(t, h)
	if err := os.WriteFile(h.path, []byte("# operator notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := i.Install(); !errors.Is(err, ErrManualEdits) {
		t.Fatalf("err = %v, want ErrManualEdits", err)
	}
	assertLegacyRestored(t, legacy)
}

func TestStatusReportsLegacySnippetAsStale(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	if _, err := i.Install(); err != nil {
		t.Fatalf("install: %v", err)
	}
	legacy := filepath.Join(filepath.Dir(h.path), "csm_challenge.conf")
	if err := os.WriteFile(legacy, []byte(legacyBody), 0o644); err != nil {
		t.Fatal(err)
	}
	i.LegacySnippetPath = legacy

	res, err := i.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if res.Status != "stale" || !strings.Contains(res.Message, legacy) || !strings.Contains(res.Message, "upgrade") {
		t.Fatalf("status = %+v, want stale naming %s and the upgrade command", res, legacy)
	}

	if err := os.Remove(legacy); err != nil {
		t.Fatal(err)
	}
	if res, err := i.Status(); err != nil || res.Status != "ok" {
		t.Fatalf("status without legacy snippet = %+v, %v; want ok", res, err)
	}
}

// The legacy snippet lives in cPanel's Apache drop-in directory. Only a
// handler whose configtest and reload cover that directory may retire it.
func TestLegacySnippetPathOnlyWhereHandlerValidatesIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		info platform.Info
		want string
	}{
		{"cpanel apache", platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSApache}, LegacySnippetPath},
		{"cpanel litespeed", platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed}, LegacySnippetPath},
		{"cpanel nginx", platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSNginx}, ""},
		{"debian apache", platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache}, ""},
		{"rhel apache", platform.Info{OS: platform.OSAlma, WebServer: platform.WSApache}, ""},
		{"plain litespeed", platform.Info{WebServer: platform.WSLiteSpeed}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := pickHandler(tc.info, realCmdRunner{})
			if err != nil {
				t.Fatal(err)
			}
			if got := legacySnippetFor(h); got != tc.want {
				t.Fatalf("legacySnippetFor(%s at %s) = %q, want %q", h.Kind(), h.SnippetPath(), got, tc.want)
			}
		})
	}
}

// A legacy snippet that could not be deleted is still intact: rollback
// removes the new integration snippet and leaves the legacy file as found.
func TestInstallLegacyDeleteFailureRollsBackOnlyIntegrationSnippet(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i, legacy := newLegacyInstaller(t, h)
	i.RemoveAt = func(path string) error {
		if path == legacy {
			return errors.New("read-only file system")
		}
		return os.Remove(path)
	}
	write := i.WriteAt
	i.WriteAt = func(path string, data []byte, mode os.FileMode) error {
		if path == legacy {
			t.Errorf("legacy snippet rewritten although it was never deleted")
		}
		return write(path, data, mode)
	}

	res, err := i.Install()
	if err == nil || res.Status != "fail" || !strings.Contains(res.Message, "legacy") {
		t.Fatalf("result = %+v, %v; want failure naming the legacy snippet", res, err)
	}
	if _, err := os.Stat(h.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("integration snippet left behind: %v", err)
	}
	assertLegacyRestored(t, legacy)
	if h.validates.Load() != 0 || h.reloads.Load() != 0 {
		t.Fatalf("validate %d, reload %d; want neither after a failed delete", h.validates.Load(), h.reloads.Load())
	}
}
