package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integration/webserver"
)

// The web servers read the challenge maps as part of their own configuration:
// Apache and LSWS validate a txt: RewriteMap at parse time and nginx fails on
// a missing include. The maps must therefore survive every csm stop (package
// upgrades, restores, reboots), which the runtime directory cannot provide:
// systemd deletes it whenever the unit stops. The cache directory is kept
// across stops and boots and, unlike the 0700 state directory, may be
// world-readable.
func TestSystemdServiceUnitKeepsChallengeMapsAcrossStops(t *testing.T) {
	unit := systemdServiceUnit("/opt/csm/csm")
	for _, want := range []string{"CacheDirectory=csm", "CacheDirectoryMode=0755"} {
		if !strings.Contains(unit, want) {
			t.Errorf("systemd unit missing %q", want)
		}
	}
	for _, p := range []string{challenge.DefaultMapPath, challenge.DefaultNginxMapPath} {
		if filepath.Dir(p) != "/var/cache/csm" {
			t.Errorf("%s is not inside the unit's cache directory", p)
		}
	}
}

func TestPrepareChallengeConfEnsuresBothPersistentMaps(t *testing.T) {
	origApache, origNginx := ensureChallengeMapFile, ensureChallengeNginxMapFile
	origDest, origNew := challengeConfDest, newWebserverIntegration
	var apacheCalls, nginxCalls int
	ensureChallengeMapFile = func() error { apacheCalls++; return nil }
	ensureChallengeNginxMapFile = func() error { nginxCalls++; return nil }
	challengeConfDest = filepath.Join(t.TempDir(), "absent.conf")
	newWebserverIntegration = func(*config.Config) (*webserver.Installer, error) {
		return nil, webserver.ErrUnknownWebserver
	}
	t.Cleanup(func() {
		ensureChallengeMapFile, ensureChallengeNginxMapFile = origApache, origNginx
		challengeConfDest, newWebserverIntegration = origDest, origNew
	})

	if _, err := prepareChallengeConf(nil); err != nil {
		t.Fatal(err)
	}
	if apacheCalls != 1 || nginxCalls != 1 {
		t.Fatalf("persistent map ensure calls = Apache %d, Nginx %d; want 1 each", apacheCalls, nginxCalls)
	}
}

// Snippets written before the maps left the runtime directory keep pointing
// at files nothing creates any more. Until such a snippet is refreshed the
// daemon has to keep those files present, or the web server fails its
// configtest host-wide.
func TestRuntimeChallengeMapPathsFindsStaleReferences(t *testing.T) {
	legacy := []byte("RewriteMap csm_challenge \"txt:/run/csm/challenge_ips.txt\"\n")
	nginx := []byte("map $remote_addr $csm_challenged {\n    default 0;\n    include /var/run/csm/challenge_ips.nginx.map;\n}\n")
	current := []byte("RewriteMap csm_chal \"txt:" + challenge.DefaultMapPath + "\"\ninclude " + challenge.DefaultNginxMapPath + ";\n")

	got := runtimeChallengeMapPaths(legacy, nginx, current, legacy)
	want := []string{"/run/csm/challenge_ips.txt", "/var/run/csm/challenge_ips.nginx.map"}
	if !slices.Equal(got, want) {
		t.Fatalf("runtimeChallengeMapPaths = %v, want %v", got, want)
	}
	if got := runtimeChallengeMapPaths(current); len(got) != 0 {
		t.Fatalf("current snippets reported stale paths %v", got)
	}
}

func TestRuntimeChallengeMapPathsRejectsLookalikeNames(t *testing.T) {
	snippets := []byte("include /run/csm/challenge_ips.nginx.map.backup;\n" +
		"RewriteMap csm_challenge txt:/var/run/csm/challenge_ips.txt.old\n" +
		"include /srv/run/csm/challenge_ips.nginx.map;\n")
	if got := runtimeChallengeMapPaths(snippets); len(got) != 0 {
		t.Fatalf("lookalike runtime map references = %v, want none", got)
	}
}

type fakeWebserverHandler struct {
	snippet   string
	validated int
	reloaded  int
}

func (h *fakeWebserverHandler) Kind() string        { return "apache" }
func (h *fakeWebserverHandler) SnippetPath() string { return h.snippet }
func (h *fakeWebserverHandler) Template() string {
	return "RewriteMap csm_chal \"txt:{{ .ChallengeMapPath }}\"\n"
}
func (h *fakeWebserverHandler) Validate() error                 { h.validated++; return nil }
func (h *fakeWebserverHandler) Reload() error                   { h.reloaded++; return nil }
func (h *fakeWebserverHandler) PostInstallInstructions() string { return "" }

// challengeRefreshFixture routes every side effect of prepareChallengeConf
// into a temp tree: the legacy snippet path, the integration installer, the
// daemon map and the runtime-map fallback.
func challengeRefreshFixture(t *testing.T, snippetBody string) (*fakeWebserverHandler, string, *[]string, *webserver.Installer) {
	t.Helper()
	dir := t.TempDir()
	snippet := filepath.Join(dir, "csm-challenge.conf")
	if err := os.WriteFile(snippet, []byte(snippetBody), 0o644); err != nil {
		t.Fatal(err)
	}
	h := &fakeWebserverHandler{snippet: snippet}
	inst := &webserver.Installer{
		Handler: h,
		Config: webserver.RenderConfig{
			ChallengeMapPath:      filepath.Join(dir, "maps", "challenge_ips.txt"),
			ChallengeNginxMapPath: filepath.Join(dir, "maps", "challenge_ips.nginx.map"),
			ChallengeListenAddr:   "203.0.113.10",
			ChallengePublicURL:    "https://challenge.example.test/challenge",
		},
		MkdirAll: os.MkdirAll,
		WriteAt:  os.WriteFile,
		ReadAt:   os.ReadFile,
		StatAt:   os.Stat,
		RemoveAt: os.Remove,
		Stderr:   io.Discard,
	}

	var ensured []string
	origEnsure, origEnsureNginx := ensureChallengeMapFile, ensureChallengeNginxMapFile
	origDest, origNew, origRuntime := challengeConfDest, newWebserverIntegration, ensureRuntimeChallengeMap
	ensureChallengeMapFile = func() error { return nil }
	ensureChallengeNginxMapFile = func() error { return nil }
	challengeConfDest = filepath.Join(dir, "absent-legacy.conf")
	newWebserverIntegration = func(*config.Config) (*webserver.Installer, error) { return inst, nil }
	ensureRuntimeChallengeMap = func(path string) error { ensured = append(ensured, path); return nil }
	t.Cleanup(func() {
		ensureChallengeMapFile, ensureChallengeNginxMapFile = origEnsure, origEnsureNginx
		challengeConfDest, newWebserverIntegration, ensureRuntimeChallengeMap = origDest, origNew, origRuntime
	})
	return h, snippet, &ensured, inst
}

// Binary-swap upgrades never re-run the integration installer. A CSM-managed
// snippet from an older template must be rewritten at daemon start, through
// the installer's own configtest-then-reload flow, so the web server stops
// depending on files the daemon no longer maintains.
func TestPrepareChallengeConfRefreshesStaleIntegrationSnippet(t *testing.T) {
	old := "# csm-managed-version: " + strconv.Itoa(webserver.TemplateVersion-1) + "\nRewriteMap csm_chal \"txt:/run/csm/challenge_ips.txt\"\n"
	h, snippet, ensured, _ := challengeRefreshFixture(t, old)

	changed, err := prepareChallengeConf(nil)
	if err != nil {
		t.Fatalf("prepareChallengeConf: %v", err)
	}
	if !changed {
		t.Fatal("stale integration snippet was not reported as refreshed")
	}
	body, err := os.ReadFile(snippet)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "# csm-managed-version: "+strconv.Itoa(webserver.TemplateVersion)+"\n") {
		t.Fatalf("snippet not rewritten to the shipped template:\n%s", body)
	}
	if strings.Contains(string(body), "/run/csm/") {
		t.Fatalf("refreshed snippet still references the runtime directory:\n%s", body)
	}
	if h.validated != 1 || h.reloaded != 1 {
		t.Fatalf("configtest/reload counts = %d/%d, want 1/1", h.validated, h.reloaded)
	}
	if len(*ensured) != 0 {
		t.Fatalf("runtime maps created although no snippet needs them: %v", *ensured)
	}
}

// An operator-edited snippet is never rewritten. While it still references a
// runtime-directory map the daemon keeps that file present so the web server
// keeps validating, exactly as it did before the maps moved.
func TestPrepareChallengeConfKeepsRuntimeMapsForOperatorEditedSnippet(t *testing.T) {
	edited := "RewriteMap csm_chal \"txt:/run/csm/challenge_ips.txt\"\n# tuned by hand\n"
	h, snippet, ensured, _ := challengeRefreshFixture(t, edited)

	if _, err := prepareChallengeConf(nil); err != nil {
		t.Fatalf("prepareChallengeConf: %v", err)
	}
	body, err := os.ReadFile(snippet)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != edited {
		t.Fatalf("operator-edited snippet was rewritten:\n%s", body)
	}
	if h.reloaded != 0 {
		t.Fatalf("web server reloaded %d times for an untouched snippet", h.reloaded)
	}
	if want := []string{"/run/csm/challenge_ips.txt"}; !slices.Equal(*ensured, want) {
		t.Fatalf("runtime maps kept = %v, want %v", *ensured, want)
	}
}

func TestPrepareChallengeConfKeepsRuntimeMapWhenRefreshIsReadOnly(t *testing.T) {
	old := "# csm-managed-version: " + strconv.Itoa(webserver.TemplateVersion-1) + "\nRewriteMap csm_chal \"txt:/run/csm/challenge_ips.txt\"\n"
	h, snippet, ensured, inst := challengeRefreshFixture(t, old)
	inst.WriteAt = func(path string, data []byte, mode os.FileMode) error {
		if path == snippet {
			return os.ErrPermission
		}
		return os.WriteFile(path, data, mode)
	}

	changed, err := prepareChallengeConf(nil)
	if err == nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("read-only integration refresh error = %v, want permission error", err)
	}
	if changed {
		t.Fatal("read-only integration refresh reported a rewrite")
	}
	body, readErr := os.ReadFile(snippet)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != old {
		t.Fatalf("read-only integration snippet changed:\n%s", body)
	}
	if h.validated != 0 || h.reloaded != 0 {
		t.Fatalf("read-only refresh reached configtest/reload: %d/%d", h.validated, h.reloaded)
	}
	if want := []string{"/run/csm/challenge_ips.txt"}; !slices.Equal(*ensured, want) {
		t.Fatalf("runtime maps kept after failed refresh = %v, want %v", *ensured, want)
	}
}
