package webserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
)

// fakeHandler is a self-contained Handler for unit tests. It records
// the calls the installer makes and lets a test arrange Validate /
// Reload to fail at chosen call counts so the rollback path can be
// exercised end to end.
type fakeHandler struct {
	kind        string
	path        string
	body        string
	validateErr []error
	reloadErr   []error
	validates   atomic.Int32
	reloads     atomic.Int32
}

func (h *fakeHandler) Kind() string                    { return h.kind }
func (h *fakeHandler) SnippetPath() string             { return h.path }
func (h *fakeHandler) Template() string                { return h.body }
func (h *fakeHandler) PostInstallInstructions() string { return "" }
func (h *fakeHandler) Validate() error {
	idx := h.validates.Add(1) - 1
	if int(idx) < len(h.validateErr) {
		return h.validateErr[int(idx)]
	}
	return nil
}
func (h *fakeHandler) Reload() error {
	idx := h.reloads.Add(1) - 1
	if int(idx) < len(h.reloadErr) {
		return h.reloadErr[int(idx)]
	}
	return nil
}

func newTestInstaller(t *testing.T, h *fakeHandler) *Installer {
	t.Helper()
	dir := t.TempDir()
	if h.path == "" {
		h.path = dir + "/csm-challenge.conf"
	}
	return &Installer{
		Handler: h,
		Config: RenderConfig{
			ChallengeMapPath:      dir + "/run/challenge_ips.txt",
			ChallengeNginxMapPath: dir + "/run/challenge_ips.nginx.map",
			ChallengeListenAddr:   "0.0.0.0",
			ChallengePublicURL:    "https://challenge.example.com:8439/challenge",
		},
		MkdirAll: os.MkdirAll,
		WriteAt:  os.WriteFile,
		ReadAt:   os.ReadFile,
		StatAt:   os.Stat,
		RemoveAt: os.Remove,
		Stderr:   io.Discard,
	}
}

func TestInstallFreshWritesSnippetAndReloads(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)

	res, err := i.Install()
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("status = %q, want ok", res.Status)
	}
	if h.validates.Load() != 1 || h.reloads.Load() != 1 {
		t.Fatalf("validate/reload counts = %d/%d, want 1/1", h.validates.Load(), h.reloads.Load())
	}
	data, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatalf("snippet not written: %v", err)
	}
	if !strings.HasPrefix(string(data), templateHeaderPrefix) {
		t.Errorf("snippet missing version header: %q", string(data))
	}
	if !strings.Contains(string(data), "RewriteEngine On") {
		t.Errorf("snippet missing body content")
	}
	if _, err := os.Stat(i.Config.ChallengeMapPath); err != nil {
		t.Fatalf("challenge map not created: %v", err)
	}
	if _, err := os.Stat(i.Config.ChallengeNginxMapPath); err != nil {
		t.Fatalf("nginx challenge map not created: %v", err)
	}
}

func TestInstallRendersConfiguredPathsAndPublicURL(t *testing.T) {
	h := &fakeHandler{
		kind: "apache",
		body: "map={{ .ChallengeMapPath }} nginx={{ .ChallengeNginxMapPath }} url={{ .ChallengePublicURL }}\n",
	}
	i := newTestInstaller(t, h)
	i.Config.ChallengeMapPath = t.TempDir() + "/challenge_ips.txt"
	i.Config.ChallengeNginxMapPath = t.TempDir() + "/challenge_ips.nginx.map"
	i.Config.ChallengePublicURL = "https://chal.example.net:8439/challenge"

	if _, err := i.Install(); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, "map="+i.Config.ChallengeMapPath) {
		t.Fatalf("rendered map path not based on config: %s", body)
	}
	if !strings.Contains(body, "nginx="+i.Config.ChallengeNginxMapPath) {
		t.Fatalf("rendered nginx map path not based on config: %s", body)
	}
	if !strings.Contains(body, "url=https://chal.example.net:8439/challenge") {
		t.Fatalf("rendered public URL not based on config: %s", body)
	}
}

func TestInstallRequiresPublicURL(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "body\n"}
	i := newTestInstaller(t, h)
	i.Config.ChallengePublicURL = ""

	res, err := i.Install()
	if !errors.Is(err, ErrMissingPublicURL) {
		t.Fatalf("err = %v, want ErrMissingPublicURL", err)
	}
	if res.Status != "fail" {
		t.Fatalf("status = %q, want fail", res.Status)
	}
	if _, statErr := os.Stat(h.path); statErr == nil {
		t.Fatal("snippet must not be written when public_url is missing")
	}
	if h.validates.Load() != 0 || h.reloads.Load() != 0 {
		t.Fatalf("no webserver action expected; got %d/%d", h.validates.Load(), h.reloads.Load())
	}
}

func TestInstallRejectsInvalidPublicURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{name: "relative", url: "chal.example.net:8439/challenge"},
		{name: "ftp", url: "ftp://chal.example.net/challenge"},
		{name: "wrong-path", url: "https://chal.example.net/not-challenge"},
		{name: "query", url: "https://chal.example.net/challenge?x=1"},
		{name: "fragment", url: "https://chal.example.net/challenge#x"},
		{name: "localhost", url: "https://127.0.0.1:8439/challenge"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHandler{kind: "apache", body: "body\n"}
			i := newTestInstaller(t, h)
			i.Config.ChallengePublicURL = tc.url

			res, err := i.Install()
			if !errors.Is(err, ErrInvalidPublicURL) {
				t.Fatalf("err = %v, want ErrInvalidPublicURL", err)
			}
			if res.Status != "fail" {
				t.Fatalf("status = %q, want fail", res.Status)
			}
			if _, statErr := os.Stat(h.path); statErr == nil {
				t.Fatal("snippet must not be written for invalid public_url")
			}
		})
	}
}

func TestInstallRejectsLoopbackListenerForPublicRedirect(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "body\n"}
	i := newTestInstaller(t, h)
	i.Config.ChallengeListenAddr = "127.0.0.1"

	res, err := i.Install()
	if !errors.Is(err, ErrLoopbackPublicURL) {
		t.Fatalf("err = %v, want ErrLoopbackPublicURL", err)
	}
	if res.Status != "fail" {
		t.Fatalf("status = %q, want fail", res.Status)
	}
	if _, statErr := os.Stat(h.path); statErr == nil {
		t.Fatal("snippet must not be written when listener is loopback")
	}
}

func TestInstallRejectsLoopbackListenerBehindTrustedProxy(t *testing.T) {
	// Any local account can connect from loopback, so trusting it lets one
	// pose as any visitor. A proxy on this host uses the socket instead.
	for _, tc := range []struct{ listen, trusted string }{
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1", "127.0.0.0/8"},
		{"::1", "::1"},
		{"[::1]", "::1/128"},
		{"::ffff:127.0.0.1", "127.0.0.1"},
		{"127.0.0.1", "::ffff:127.0.0.0/104"},
		{"localhost", "127.0.0.1"},
		{" LOCALHOST ", "127.0.0.1"},
		{"", "127.0.0.1"},
	} {
		t.Run(tc.listen+" "+tc.trusted, func(t *testing.T) {
			h := &fakeHandler{kind: "apache", body: "body\n"}
			i := newTestInstaller(t, h)
			i.Config.ChallengeListenAddr = tc.listen
			i.Config.ChallengeTrustedProxies = []string{tc.trusted}

			_, err := i.Install()
			if !errors.Is(err, ErrLoopbackPublicURL) {
				t.Fatalf("err = %v, want ErrLoopbackPublicURL", err)
			}
			if !strings.Contains(err.Error(), config.ChallengeSocketExample) {
				t.Fatalf("err = %v, want it to point at %s", err, config.ChallengeSocketExample)
			}
			if _, statErr := os.Stat(h.path); statErr == nil {
				t.Fatal("snippet must not be written")
			}
		})
	}
}

func TestInstallAcceptsSocketListener(t *testing.T) {
	pinInstallerHost(t)
	for _, addr := range []string{config.ChallengeSocketExample, " UNIX:/run/csm/challenge.sock "} {
		t.Run(addr, func(t *testing.T) {
			h := &fakeHandler{kind: "apache", body: "body\n"}
			i := newTestInstaller(t, h)
			i.Config.ChallengeListenAddr = addr
			i.Config.ChallengeListenGroup = "proxy"
			i.Config.ChallengePublicURL = "https://challenge.example.com/challenge"
			if _, err := i.Install(); err != nil {
				t.Fatalf("Install: %v", err)
			}
		})
	}
}

func TestInstallRejectsHostLocalTrustedProxy(t *testing.T) {
	pinInstallerHost(t)
	for _, trusted := range []string{"127.0.0.1", "203.0.113.0/24"} {
		for _, listen := range []string{"0.0.0.0", config.ChallengeSocketExample} {
			t.Run(listen+" "+trusted, func(t *testing.T) {
				h := &fakeHandler{kind: "apache", body: "body\n"}
				i := newTestInstaller(t, h)
				i.Config.ChallengeListenAddr = listen
				i.Config.ChallengeListenGroup = "proxy"
				i.Config.ChallengeTrustedProxies = []string{"198.51.100.2", trusted}
				res, err := i.Install()
				if err == nil || !strings.Contains(err.Error(), config.ChallengeSocketExample) || !strings.Contains(err.Error(), trusted) {
					t.Fatalf("err = %v, want refusal naming %q and the socket", err, trusted)
				}
				if res.Status != "fail" {
					t.Fatalf("status = %q, want fail", res.Status)
				}
				if _, statErr := os.Stat(h.path); statErr == nil {
					t.Fatal("snippet must not be written")
				}
				if h.validates.Load() != 0 || h.reloads.Load() != 0 {
					t.Fatal("refused install touched the webserver")
				}
			})
		}
	}
}

// pinInstallerHost gives the host-local trust check a fixed host address.
func pinInstallerHost(t *testing.T) {
	t.Helper()
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	}))
}

func TestInstallRejectsPortInListenAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8439", "[::1]:8439", "[2001:db8::1]:8439"} {
		t.Run(addr, func(t *testing.T) {
			h := &fakeHandler{kind: "apache", body: "body\n"}
			i := newTestInstaller(t, h)
			i.Config.ChallengeListenAddr = addr
			i.Config.ChallengeTrustedProxies = []string{"127.0.0.1", "::1"}
			if _, err := i.Install(); err == nil || !strings.Contains(err.Error(), "listen_port") {
				t.Fatalf("err = %v, want an error directing the port to listen_port", err)
			}
			if h.validates.Load() != 0 || h.reloads.Load() != 0 {
				t.Fatal("invalid listener changed the webserver")
			}
		})
	}
}

func TestInstallRejectsLoopbackListenerWhenProxyCannotReachIt(t *testing.T) {
	// The proxy on this host connects from the listener's own address; trusting
	// another address leaves every visitor looking like the proxy.
	for _, trusted := range []string{"", "  ", "localhost", "::1", "192.0.2.10", "198.51.100.0/24"} {
		t.Run(trusted, func(t *testing.T) {
			h := &fakeHandler{kind: "apache", body: "body\n"}
			i := newTestInstaller(t, h)
			i.Config.ChallengeListenAddr = "127.0.0.1"
			i.Config.ChallengeTrustedProxies = []string{trusted}

			if _, err := i.Install(); !errors.Is(err, ErrLoopbackPublicURL) {
				t.Fatalf("err = %v, want ErrLoopbackPublicURL", err)
			}
		})
	}
}

func TestShippedTemplatesRenderRuntimeConfig(t *testing.T) {
	for _, tc := range []struct {
		name          string
		body          string
		wantMapPath   string
		rejectMapPath string
	}{
		{name: "apache", body: apacheTemplate, wantMapPath: "/run/custom-csm/challenge_ips.txt", rejectMapPath: "/run/custom-csm/challenge_ips.nginx.map"},
		{name: "lsws", body: lswsTemplate, wantMapPath: "/run/custom-csm/challenge_ips.txt", rejectMapPath: "/run/custom-csm/challenge_ips.nginx.map"},
		{name: "nginx", body: nginxTemplate, wantMapPath: "/run/custom-csm/challenge_ips.nginx.map", rejectMapPath: "/run/custom-csm/challenge_ips.txt"},
		{name: "cpanel-site", body: cpanelSiteTemplate, wantMapPath: "/run/custom-csm/challenge_ips.txt", rejectMapPath: "/run/custom-csm/challenge_ips.nginx.map"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHandler{kind: tc.name, body: tc.body}
			i := newTestInstaller(t, h)
			i.Config.ChallengeMapPath = "/run/custom-csm/challenge_ips.txt"
			i.Config.ChallengeNginxMapPath = "/run/custom-csm/challenge_ips.nginx.map"
			i.Config.ChallengePublicURL = "https://chal.example.net:8439/challenge"
			rendered, err := i.renderTemplate()
			if err != nil {
				t.Fatalf("renderTemplate: %v", err)
			}
			body := string(rendered)
			if strings.Contains(body, "/opt/csm/state") {
				t.Fatalf("template still hardcodes legacy state path: %s", body)
			}
			if !strings.Contains(body, tc.wantMapPath) {
				t.Fatalf("template did not render configured map path: %s", body)
			}
			if strings.Contains(body, tc.rejectMapPath) {
				t.Fatalf("template rendered wrong map path: %s", body)
			}
			if !strings.Contains(body, "https://chal.example.net:8439/challenge") {
				t.Fatalf("template did not render configured public URL: %s", body)
			}
		})
	}
}

func TestRenderTemplateIsStableForNoOpCompare(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	first, err := i.renderTemplate()
	if err != nil {
		t.Fatalf("first render: %v", err)
	}
	second, err := i.renderTemplate()
	if err != nil {
		t.Fatalf("second render: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("rendered template changed between identical inputs:\nfirst=%s\nsecond=%s", first, second)
	}
}

func TestInstallSameVersionIsNoOp(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	if _, err := i.Install(); err != nil {
		t.Fatalf("first install: %v", err)
	}

	res, err := i.Install()
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if res.Status != "no-op" {
		t.Fatalf("status = %q, want no-op", res.Status)
	}
	// Validate + reload run once (first install) only.
	if h.reloads.Load() != 1 {
		t.Fatalf("reload ran %d times; want 1", h.reloads.Load())
	}
}

func TestInstallValidateFailureRollsBack(t *testing.T) {
	h := &fakeHandler{
		kind:        "apache",
		body:        "RewriteEngine On\n",
		validateErr: []error{errors.New("syntax error at line 7")},
	}
	i := newTestInstaller(t, h)

	res, err := i.Install()
	if err == nil {
		t.Fatal("expected configtest failure")
	}
	if res.Status != "fail" || !strings.Contains(res.Message, "configtest") {
		t.Fatalf("result = %+v, want fail/configtest", res)
	}
	// File must not exist after rollback (fresh install).
	if _, statErr := os.Stat(h.path); statErr == nil {
		t.Fatal("rollback failed: snippet still present after configtest failure")
	}
	// Reload must not have run.
	if h.reloads.Load() != 0 {
		t.Fatalf("reload ran %d times; want 0 on configtest fail", h.reloads.Load())
	}
}

func TestInstallReloadFailureRollsBackAndRecovers(t *testing.T) {
	h := &fakeHandler{
		kind:      "apache",
		body:      "RewriteEngine On\n",
		reloadErr: []error{errors.New("systemctl reload returned 1")},
	}
	i := newTestInstaller(t, h)

	res, err := i.Install()
	if err == nil {
		t.Fatal("expected reload failure")
	}
	if res.Status != "fail" || !strings.Contains(res.Message, "rolled back") {
		t.Fatalf("result = %+v, want fail with rolled-back marker", res)
	}
	// Recovery reload runs once after the first failure, total 2.
	if h.reloads.Load() != 2 {
		t.Fatalf("reload ran %d times; want 2 (initial fail + recovery)", h.reloads.Load())
	}
}

func TestInstallRefusesOperatorEdits(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	// Plant an operator-edited file lacking the version marker.
	if err := os.WriteFile(h.path, []byte("# operator notes\nfoo bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := i.Install()
	if !errors.Is(err, ErrManualEdits) {
		t.Fatalf("err = %v, want ErrManualEdits", err)
	}
	if res.Status != "fail" {
		t.Fatalf("status = %q, want fail", res.Status)
	}
}

func TestStatusReportsStateCorrectly(t *testing.T) {
	cases := []struct {
		name       string
		prepare    func(path string)
		wantStatus string
	}{
		{
			name:       "missing",
			prepare:    func(string) {},
			wantStatus: "missing",
		},
		{
			name: "modified",
			prepare: func(path string) {
				_ = os.WriteFile(path, []byte("hand-edited\n"), 0o644)
			},
			wantStatus: "modified",
		},
		{
			name: "stale",
			prepare: func(path string) {
				if TemplateVersion <= 1 {
					// Nothing to stage as stale: any lower marker
					// value (zero) is treated as missing header. The
					// case kicks in when TemplateVersion is bumped.
					return
				}
				_ = os.WriteFile(path, []byte(fmt.Sprintf("%s%d\nold body\n", templateHeaderPrefix, TemplateVersion-1)), 0o644)
			},
			wantStatus: "stale",
		},
		{
			name: "ok",
			prepare: func(path string) {
				_ = os.WriteFile(path, []byte(fmt.Sprintf("%s%d\nbody\n", templateHeaderPrefix, TemplateVersion)), 0o644)
			},
			wantStatus: "ok",
		},
	}
	for _, tc := range cases {
		if tc.name == "stale" && TemplateVersion <= 1 {
			// The "stale" branch can never be exercised via Status()
			// while shipped TemplateVersion is 1, because there is no
			// valid lower version (zero is reserved for "header
			// missing"). The classifier itself is covered by
			// TestClassifyStatus below.
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHandler{kind: "apache", body: "body\n"}
			i := newTestInstaller(t, h)
			tc.prepare(h.path)
			res, _ := i.Status()
			if res.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", res.Status, tc.wantStatus)
			}
		})
	}
}

// classifyStatus is unit-tested with arbitrary version pairs so the
// stale branch is exercised regardless of the package-level
// TemplateVersion constant.
func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		name   string
		exists bool
		on, sh int
		want   string
	}{
		{"missing", false, 0, 1, "missing"},
		{"modified", true, 0, 1, "modified"},
		{"stale", true, 1, 2, "stale"},
		{"current", true, 2, 2, "ok"},
		{"ahead-of-shipped", true, 3, 2, "ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, _ := classifyStatus(c.exists, c.on, c.sh)
			if status != c.want {
				t.Fatalf("status = %q, want %q", status, c.want)
			}
		})
	}
}

func TestRemoveDeletesSnippetAndReloads(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	if _, err := i.Install(); err != nil {
		t.Fatal(err)
	}
	// install ran once; reset counters for clarity.
	h.validates.Store(0)
	h.reloads.Store(0)

	res, err := i.Remove()
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("status = %q, want ok", res.Status)
	}
	if _, statErr := os.Stat(h.path); statErr == nil {
		t.Fatal("snippet still present after Remove")
	}
}

func TestRemoveRefusesOperatorEdits(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	if err := os.WriteFile(h.path, []byte("manual edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := i.Remove()
	if !errors.Is(err, ErrManualEdits) {
		t.Fatalf("err = %v, want ErrManualEdits", err)
	}
	if _, statErr := os.Stat(h.path); statErr != nil {
		t.Fatal("Remove deleted an operator-edited file; must keep it")
	}
}

func TestParseHeaderVersionHandlesGarbage(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"random data without marker", 0},
		{templateHeaderPrefix + "not-an-int\nrest", 0},
		{templateHeaderPrefix + "3\n", 3},
		{templateHeaderPrefix + "12\nbody...", 12},
	}
	for _, c := range cases {
		got := parseHeaderVersion([]byte(c.in))
		if got != c.want {
			t.Errorf("parseHeaderVersion(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// Use of cmdRunner via context to keep gofmt happy when the import is
// only touched in handler files. Compile-time reference.
var _ cmdRunner = realCmdRunner{}
var _ context.Context = context.Background()
