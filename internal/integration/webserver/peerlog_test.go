package webserver

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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
	i.LstatAt = func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return peerDirectoryInfo{FileInfo: info}, nil
	}
	i.ChownAt = func(path string, uid, gid int) error {
		if path != i.PeerLogDir || uid != 0 || gid != 0 {
			t.Errorf("unexpected directory ownership: %s %d:%d", path, uid, gid)
		}
		return nil
	}
	return i
}

// Install writes the versioned snippet, makes sure the log directory exists
// before the web server reloads, then validates and reloads; a failing
// configtest restores the previous state without reloading it.
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
		!strings.Contains(string(data), "GlobalLog "+filepath.Join(i.PeerLogDir, filepath.Base(PeerLogFile))+" csmpeer") {
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
// LiteSpeed get none. Front-proxied hosts retain the path for removal.
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
		{"fronted", platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSApache, FrontProxied: true}, "/etc/apache2/conf.d/csm-peer-log.conf"},
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

// The peer log has its own verbs (operator ruling 2026-11-21): the challenge
// verbs leave it alone, except that upgrade refreshes an installed one, and
// its verbs need no challenge settings.
func TestPeerLogHasItsOwnVerbs(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newPeerLogInstaller(t, h)
	if res, err := i.Run("install"); err != nil || res.PeerLog != nil {
		t.Fatalf("install = %+v, %v; want the challenge only", res, err)
	}
	if _, err := os.Stat(i.PeerLogPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("install added the peer log: %v", err)
	}
	if res, err := i.Run("upgrade"); err != nil || res.PeerLog != nil {
		t.Fatalf("upgrade without a peer log = %+v, %v; want it left alone", res, err)
	}
	for _, tc := range []struct{ verb, want string }{
		{"install", "ok"}, {"status", "ok"}, {"remove", "ok"}, {"status", "missing"}, {"install", "ok"},
	} {
		res, err := i.RunPeerLog(tc.verb)
		if err != nil || res.Status != tc.want || res.Action != "peer-log "+tc.verb {
			t.Fatalf("peer-log %s = %+v, %v; want %s", tc.verb, res, err, tc.want)
		}
	}
	if res, err := i.Run("upgrade"); err != nil || res.PeerLog == nil || res.PeerLog.Status != "no-op" {
		t.Fatalf("upgrade with a peer log = %+v (peer log %+v), %v; want it refreshed", res, res.PeerLog, err)
	}
	if res, err := i.Run("remove"); err != nil || res.PeerLog != nil {
		t.Fatalf("remove = %+v, %v; want the challenge only", res, err)
	}
	if _, err := os.Stat(i.PeerLogPath); err != nil {
		t.Fatalf("challenge remove took the peer log: %v", err)
	}
	if _, err := i.RunPeerLog("upgrade"); err == nil {
		t.Fatal("an unknown peer-log verb was accepted")
	}
	j := newPeerLogInstaller(t, &fakeHandler{kind: "apache"})
	j.Config.ChallengePublicURL = ""
	if res, err := j.RunPeerLog("install"); err != nil || res.Status != "ok" {
		t.Fatalf("peer-log install without a challenge URL = %+v, %v; want ok", res, err)
	}
}

// The snippet the web server loads, byte for byte.
func TestPeerLogTemplateBody(t *testing.T) {
	for _, kind := range []string{"apache", "lsws"} {
		i := &Installer{PeerLogDir: peerLogDir, Handler: &fakeHandler{kind: kind}}
		got, err := i.peerLogBody()
		want := "# csm-managed-version: 3\n" +
			"LogFormat \"%{%s}t %v %{c}a %a\" csmpeer\n" +
			"<IfModule LiteSpeed>\nCustomLog /var/log/csm-web/peer.log csmpeer\n</IfModule>\n" +
			"<IfModule !LiteSpeed>\n<IfFile \"/var/log/csm-web/\">\nGlobalLog /var/log/csm-web/peer.log csmpeer\n</IfFile>\n</IfModule>\n"

		if err != nil || string(got) != want || PeerLogFile != "/var/log/csm-web/peer.log" {
			t.Fatalf("%s peer snippet = %q, %v; want %q", kind, got, err, want)
		}
	}
}

// A snippet from a newer CSM is not downgraded by an older binary.
func TestPeerLogInstallKeepsANewerSnippet(t *testing.T) {
	h := &fakeHandler{kind: "apache"}
	i := newPeerLogInstaller(t, h)
	newer := templateHeaderPrefix + "99\nCustomLog /var/log/csm-web/peer.log csmpeer\n"
	if err := os.MkdirAll(i.PeerLogDir, 0o750); err != nil {
		t.Fatal(err)
	}
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

func TestPeerLogRepairsMissingDirectory(t *testing.T) {
	for _, version := range []int{PeerLogTemplateVersion, 99} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			h := &fakeHandler{kind: "apache"}
			i := newPeerLogInstaller(t, h)
			original := []byte(fmt.Sprintf("# csm-managed-version: %d\n# retained\n", version))
			if err := os.MkdirAll(filepath.Dir(i.PeerLogPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(i.PeerLogPath, original, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := i.InstallPeerLog(); err != nil {
				t.Fatal(err)
			}
			if st, err := os.Stat(i.PeerLogDir); err != nil || !st.IsDir() {
				t.Fatalf("missing log directory: %v", err)
			}
			if body, err := os.ReadFile(i.PeerLogPath); err != nil || !bytes.Equal(body, original) {
				t.Fatalf("snippet changed: %q, %v", body, err)
			}
			if h.validates.Load() != 1 || h.reloads.Load() != 1 {
				t.Fatalf("directory repair must activate logging: validate/reload %d/%d", h.validates.Load(), h.reloads.Load())
			}
		})
	}
}

func TestPeerLogRollback(t *testing.T) {
	for _, operation := range []string{"install", "upgrade", "remove"} {
		for _, stage := range []string{"configtest", "reload", "recovery configtest", "recovery reload", "restore"} {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				failure := errors.New("apply failed")
				recovery := errors.New("recovery failed")
				h := &fakeHandler{kind: "apache"}
				i := newPeerLogInstaller(t, h)
				original := []byte("# csm-managed-version: 1\n# old body\n")
				existed := operation != "install"
				if existed {
					if err := os.MkdirAll(filepath.Dir(i.PeerLogPath), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(i.PeerLogPath, original, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				wantValidates, wantReloads := int32(1), int32(0)
				if stage == "configtest" {
					h.validateErr = []error{failure}
				} else {
					h.reloadErr = []error{failure}
					wantValidates, wantReloads = 2, 2
					switch stage {
					case "recovery configtest":
						h.validateErr = []error{nil, recovery}
						wantReloads = 1
					case "recovery reload":
						h.reloadErr = []error{failure, recovery}
					case "restore":
						wantValidates, wantReloads = 1, 1
						if existed {
							i.WriteAt = func(path string, b []byte, mode os.FileMode) error {
								if bytes.Equal(b, original) {
									return recovery
								}
								return os.WriteFile(path, b, mode)
							}
						} else {
							i.RemoveAt = func(string) error { return recovery }
						}
					}
				}
				var err error
				if operation == "remove" {
					_, err = i.RemovePeerLog()
				} else {
					_, err = i.InstallPeerLog()
				}
				if !errors.Is(err, failure) {
					t.Fatalf("lost original error: %v", err)
				}
				if strings.HasPrefix(stage, "recovery") || stage == "restore" {
					if !errors.Is(err, recovery) {
						t.Fatalf("lost recovery error: %v", err)
					}
				}
				if stage != "restore" {
					body, readErr := os.ReadFile(i.PeerLogPath)
					if existed && (readErr != nil || !bytes.Equal(body, original)) {
						t.Fatalf("previous bytes not restored: %q, %v", body, readErr)
					}
					if !existed && !errors.Is(readErr, os.ErrNotExist) {
						t.Fatalf("fresh snippet survived: %v", readErr)
					}
				}
				if h.validates.Load() != wantValidates || h.reloads.Load() != wantReloads {
					t.Fatalf("validate/reload = %d/%d, want %d/%d", h.validates.Load(), h.reloads.Load(), wantValidates, wantReloads)
				}
			})
		}
	}
}

func TestPeerLogApacheCoversVirtualHostsAndMissingDirectory(t *testing.T) {
	i := newPeerLogInstaller(t, &fakeHandler{kind: "apache"})
	body, err := i.peerLogBody()
	if err != nil {
		t.Fatal(err)
	}
	want := "<IfModule !LiteSpeed>\n<IfFile \"" + i.PeerLogDir + "/\">\nGlobalLog " + filepath.Join(i.PeerLogDir, filepath.Base(PeerLogFile)) + " csmpeer\n</IfFile>\n</IfModule>\n"
	if !strings.HasSuffix(string(body), want) {
		t.Fatalf("Apache must guard the directory and log all virtual hosts: %s", body)
	}
}

func TestPeerLogFrontProxyCanRemoveEarlierSnippet(t *testing.T) {
	info := platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSApache, FrontProxied: true}
	i, err := New(info, nil)
	if err != nil {
		t.Fatal(err)
	}
	if i.PeerLogPath == "" {
		t.Fatal("front-proxied host cannot locate an earlier peer snippet for removal")
	}
	h := &fakeHandler{kind: "apache"}
	i.Handler = h
	i.PeerLogPath = filepath.Join(t.TempDir(), "peer.conf")
	i.PeerLogDir = filepath.Join(t.TempDir(), "logs")
	if res, err := i.InstallPeerLog(); err != nil || res.Status != "skipped" {
		t.Fatalf("front-proxy install = %+v, %v", res, err)
	}
	if _, err := os.Stat(i.PeerLogPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("front-proxy installed a snippet: %v", err)
	}
	if err := os.WriteFile(i.PeerLogPath, []byte("# csm-managed-version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if res, err := i.RemovePeerLog(); err != nil || res.Status != "ok" {
		t.Fatalf("front-proxy remove = %+v, %v", res, err)
	}
	if _, err := os.Stat(i.PeerLogPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old snippet remains: %v", err)
	}
	if h.reloads.Load() != 1 {
		t.Fatalf("removal reloads = %d", h.reloads.Load())
	}
}

func TestRunReportsChallengeFailure(t *testing.T) {
	for _, verb := range []string{"install", "upgrade", "status", "remove"} {
		t.Run(verb, func(t *testing.T) {
			h := &fakeHandler{kind: "apache"}
			i := newPeerLogInstaller(t, h)
			if _, err := i.InstallPeerLog(); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("challenge unreadable")
			i.ReadAt = func(path string) ([]byte, error) {
				if path == h.path {
					return nil, failure
				}
				return os.ReadFile(path)
			}
			res, err := i.Run(verb)
			if !errors.Is(err, failure) || res.Status != "fail" {
				t.Fatalf("challenge error lost: %+v, %v", res, err)
			}
			// Only upgrade refreshes the installed peer log; the other
			// challenge verbs leave it to its own verbs (operator ruling
			// 2026-11-21).
			if verb == "upgrade" {
				if res.PeerLog == nil || res.PeerLog.Status != "no-op" {
					t.Fatalf("upgrade did not refresh the peer log: %+v", res.PeerLog)
				}
			} else if res.PeerLog != nil {
				t.Fatalf("%s touched the peer log: %+v", verb, res.PeerLog)
			}
			if _, statErr := os.Stat(i.PeerLogPath); statErr != nil {
				t.Fatalf("%s removed the peer snippet: %v", verb, statErr)
			}
		})
	}
}

// LiteSpeed's workers open the log by path as nobody, so on cPanel the
// directory carries the web server's group; other local users never reach
// it. An existing directory with a looser mode or another group is corrected.
func TestPeerLogInstallRestrictsTheLogDirectory(t *testing.T) {
	h := &fakeHandler{kind: "lsws"}
	i := newPeerLogInstaller(t, h)
	group, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	i.PeerLogGroup = group.Name
	var chowned []string
	i.ChownAt = func(path string, uid, gid int) error {
		chowned = append(chowned, fmt.Sprintf("%s %d %d", path, uid, gid))
		return nil
	}
	if err = os.MkdirAll(i.PeerLogDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(i.PeerLogDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err = i.InstallPeerLog(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(i.PeerLogDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("log directory mode = %v; want 0750", info.Mode().Perm())
	}
	if want := fmt.Sprintf("%s 0 %d", i.PeerLogDir, os.Getgid()); len(chowned) != 1 || chowned[0] != want {
		t.Fatalf("chown calls = %q, want [%q]", chowned, want)
	}
}

func TestPeerLogGroupFor(t *testing.T) {
	for _, tc := range []struct {
		info platform.Info
		want string
	}{
		{platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed}, "nobody"},
		// Apache's root parent opens its logs; its workers need no access.
		{platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSApache}, ""},
		{platform.Info{OS: platform.OSDebian, WebServer: platform.WSApache}, ""},
	} {
		if got := peerLogGroupFor(tc.info); got != tc.want {
			t.Errorf("peerLogGroupFor(%+v) = %q, want %q", tc.info, got, tc.want)
		}
	}
}

// Only a directory this install created needs CSM restarted: the sandbox
// grant applies to directories that existed when the daemon started.
func TestPeerLogRestartMessageOnlyWhenCreated(t *testing.T) {
	i := newPeerLogInstaller(t, &fakeHandler{kind: "apache"})
	res, err := i.InstallPeerLog()
	if err != nil || !strings.Contains(res.Message, "restart") {
		t.Fatalf("first install = %+v, %v; want the restart advice", res, err)
	}
	j := newPeerLogInstaller(t, &fakeHandler{kind: "apache"})
	if err := os.MkdirAll(j.PeerLogDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(j.PeerLogDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if res, err := j.InstallPeerLog(); err != nil || strings.Contains(res.Message, "restart") {
		t.Fatalf("install over an existing directory = %+v, %v; want no restart advice", res, err)
	}
}
