package webserver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

func newPeerLogInstaller(t *testing.T, h *fakeHandler) *Installer {
	t.Helper()
	i := newTestInstaller(t, h)
	dir := t.TempDir()
	i.PeerLogPath = filepath.Join(dir, "conf.d", "csm-peer-log.conf")
	i.PeerLogDir = filepath.Join(dir, "log", "csm")
	return i
}

// Install writes the versioned snippet, makes sure the log directory exists
// before the web server reloads, then validates and reloads; a failing
// configtest restores the previous state and reloads it.
func TestPeerLogInstallWritesValidatesReloads(t *testing.T) {
	h := &fakeHandler{kind: "apache"}
	i := newPeerLogInstaller(t, h)
	res, err := i.InstallPeerLog()
	if err != nil || res.Status != "ok" {
		t.Fatalf("InstallPeerLog = %+v, %v", res, err)
	}
	data, err := os.ReadFile(i.PeerLogPath)
	if err != nil || parseHeaderVersion(data) != PeerLogTemplateVersion ||
		!strings.Contains(string(data), `LogFormat "%{%s}t %v %{c}a %a" csmpeer`) ||
		!strings.Contains(string(data), "CustomLog "+filepath.Join(i.PeerLogDir, "web-peer.log")+" csmpeer") {
		t.Fatalf("snippet = %q, %v", data, err)
	}
	if info, err := os.Stat(i.PeerLogDir); err != nil || !info.IsDir() {
		t.Fatalf("log directory not created: %v", err)
	}
	if h.validates.Load() != 1 || h.reloads.Load() != 1 {
		t.Fatalf("validate/reload = %d/%d, want 1/1", h.validates.Load(), h.reloads.Load())
	}

	bad := &fakeHandler{kind: "apache", validateErr: []error{errors.New("syntax error")}}
	j := newPeerLogInstaller(t, bad)
	if _, err := j.InstallPeerLog(); err == nil {
		t.Fatal("a failing configtest was accepted")
	}
	if _, err := os.Stat(j.PeerLogPath); !os.IsNotExist(err) {
		t.Fatalf("a refused snippet was left on disk: %v", err)
	}
	if bad.reloads.Load() != 0 {
		t.Fatalf("reloaded %d times after a failing configtest of a fresh snippet", bad.reloads.Load())
	}
}

func TestPeerLogInstallNeedsNoPublicURL(t *testing.T) {
	h := &fakeHandler{kind: "lsws"}
	i := newPeerLogInstaller(t, h)
	i.Config.ChallengePublicURL = ""
	if res, err := i.InstallPeerLog(); err != nil || res.Status != "ok" {
		t.Fatalf("InstallPeerLog without a challenge URL = %+v, %v", res, err)
	}
}

func TestPeerLogRefusesManualEdits(t *testing.T) {
	h := &fakeHandler{kind: "apache"}
	i := newPeerLogInstaller(t, h)
	if err := os.MkdirAll(filepath.Dir(i.PeerLogPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(i.PeerLogPath, []byte("CustomLog /tmp/x combined\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := i.InstallPeerLog(); !errors.Is(err, ErrManualEdits) {
		t.Fatalf("InstallPeerLog over an operator file = %v, want ErrManualEdits", err)
	}
	if _, err := i.RemovePeerLog(); !errors.Is(err, ErrManualEdits) {
		t.Fatalf("RemovePeerLog of an operator file = %v, want ErrManualEdits", err)
	}
	if data, _ := os.ReadFile(i.PeerLogPath); string(data) != "CustomLog /tmp/x combined\n" {
		t.Fatalf("operator file changed: %q", data)
	}
}

// Remove takes the snippet away and reloads; Status reports each state.
func TestPeerLogRemoveAndStatus(t *testing.T) {
	h := &fakeHandler{kind: "apache"}
	i := newPeerLogInstaller(t, h)
	if res, _ := i.PeerLogStatus(); res.Status != "missing" {
		t.Fatalf("status before install = %+v, want missing", res)
	}
	if _, err := i.InstallPeerLog(); err != nil {
		t.Fatal(err)
	}
	if res, _ := i.PeerLogStatus(); res.Status != "ok" || res.OnDiskVer != PeerLogTemplateVersion {
		t.Fatalf("status after install = %+v, want ok", res)
	}
	if res, err := i.RemovePeerLog(); err != nil || res.Status != "ok" {
		t.Fatalf("RemovePeerLog = %+v, %v", res, err)
	}
	if _, err := os.Stat(i.PeerLogPath); !os.IsNotExist(err) {
		t.Fatalf("snippet still present: %v", err)
	}
	if h.reloads.Load() != 2 {
		t.Fatalf("reloads = %d, want one per install and remove", h.reloads.Load())
	}
}

// Only Apache and cPanel LiteSpeed load the snippet; nginx and standalone
// LiteSpeed, and hosts where nginx fronts the web server, get none.
func TestPeerLogPathFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		info platform.Info
		want string
	}{
		{"cpanel apache", platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSApache}, "/etc/apache2/conf.d/csm-peer-log.conf"},
		{"cpanel litespeed", platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed}, "/etc/apache2/conf.d/csm-peer-log.conf"},
		{"rhel apache", platform.Info{OS: platform.OSRHEL, WebServer: platform.WSApache}, "/etc/httpd/conf.d/csm-peer-log.conf"},
		{"debian apache", platform.Info{OS: platform.OSDebian, WebServer: platform.WSApache}, "/etc/apache2/conf-enabled/csm-peer-log.conf"},
		{"standalone litespeed", platform.Info{WebServer: platform.WSLiteSpeed}, ""},
		{"nginx", platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSNginx}, ""},
		{"fronted", platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSApache, FrontProxied: true}, ""},
	} {
		if got := PeerLogPathFor(tc.info); got != tc.want {
			t.Errorf("%s: PeerLogPathFor = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestPeerLogUnsupportedIsSkipped(t *testing.T) {
	h := &fakeHandler{kind: "nginx"}
	i := newPeerLogInstaller(t, h)
	i.PeerLogPath = ""
	if res, err := i.InstallPeerLog(); err != nil || res.Status != "skipped" || h.reloads.Load() != 0 {
		t.Fatalf("InstallPeerLog on an unsupported server = %+v, %v", res, err)
	}
}

// The integration command carries the peer log beside the challenge
// snippet: install and upgrade write it, status reports it, remove takes it
// away, validate leaves it out. A challenge that cannot install still lets
// the peer log install, and the command still reports the failure.
func TestRunAttachesThePeerLog(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newPeerLogInstaller(t, h)
	for _, tc := range []struct{ verb, want string }{
		{"install", "ok"}, {"status", "ok"}, {"upgrade", "no-op"}, {"remove", "ok"}, {"status", "missing"},
	} {
		res, err := i.Run(tc.verb)
		if err != nil || res.PeerLog == nil || res.PeerLog.Status != tc.want {
			t.Fatalf("Run(%s) = %+v (peer log %+v), %v; want peer log %s", tc.verb, res, res.PeerLog, err, tc.want)
		}
	}
	if res, _ := i.Run("validate"); res.PeerLog != nil {
		t.Fatalf("validate reported a peer log: %+v", res.PeerLog)
	}
	j := newPeerLogInstaller(t, &fakeHandler{kind: "apache", body: "RewriteEngine On\n"})
	j.Config.ChallengePublicURL = ""
	res, err := j.Run("install")
	if err == nil || res.PeerLog == nil || res.PeerLog.Status != "ok" {
		t.Fatalf("install without a challenge URL = %+v (peer log %+v), %v; want the peer log installed and the challenge failure reported", res, res.PeerLog, err)
	}
}

// The snippet the web server loads, byte for byte.
func TestPeerLogTemplateBody(t *testing.T) {
	got, err := (&Installer{PeerLogDir: peerLogDir}).peerLogBody()
	want := "# csm-managed-version: 1\nLogFormat \"%{%s}t %v %{c}a %a\" csmpeer\nCustomLog /var/log/csm/web-peer.log csmpeer\n"
	if err != nil || string(got) != want || PeerLogFile != "/var/log/csm/web-peer.log" {
		t.Fatalf("peer log snippet = %q, %v (log %s); want %q", got, err, PeerLogFile, want)
	}
}

// A snippet from a newer CSM is not downgraded by an older binary.
func TestPeerLogInstallKeepsANewerSnippet(t *testing.T) {
	h := &fakeHandler{kind: "apache"}
	i := newPeerLogInstaller(t, h)
	newer := templateHeaderPrefix + "99\nCustomLog /var/log/csm/web-peer.log csmpeer\n"
	if err := os.MkdirAll(filepath.Dir(i.PeerLogPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(i.PeerLogPath, []byte(newer), 0o644); err != nil {
		t.Fatal(err)
	}
	if res, err := i.InstallPeerLog(); err != nil || res.Status != "no-op" {
		t.Fatalf("InstallPeerLog over a newer snippet = %+v, %v; want no-op", res, err)
	}
	if res, _ := i.PeerLogStatus(); res.Status != "ok" {
		t.Fatalf("status of a newer snippet = %+v, want ok", res)
	}
	if data, _ := os.ReadFile(i.PeerLogPath); string(data) != newer || h.reloads.Load() != 0 {
		t.Fatalf("newer snippet rewritten to %q (reloads %d)", data, h.reloads.Load())
	}
}
