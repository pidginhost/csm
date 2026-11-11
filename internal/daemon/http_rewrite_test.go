package daemon

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// withHostHTTPRewrite replaces the host detector and counts its reads.
func withHostHTTPRewrite(t *testing.T, r checks.HTTPRewrite) *int {
	t.Helper()
	calls := 0
	prev, prevState := detectHostHTTPRewrite, checks.CurrentHTTPRewrite()
	detectHostHTTPRewrite = func() checks.HTTPRewrite { calls++; return r }
	t.Cleanup(func() {
		detectHostHTTPRewrite = prev
		checks.SetHTTPRewrite(prevState)
	})
	return &calls
}

// productionDetectHostHTTPRewrite is the production reader, saved by
// TestMain before it pins the detector.
var productionDetectHostHTTPRewrite func() checks.HTTPRewrite

var nginxRewrite = checks.HTTPRewrite{State: checks.RewriteActive, Server: "nginx", Directive: "real_ip_header CF-Connecting-IP", File: "/etc/nginx/conf.d/realip.conf"}

func TestRefreshHTTPRewritePublishesTheDetectedState(t *testing.T) {
	withHostHTTPRewrite(t, nginxRewrite)
	(&Daemon{}).refreshHTTPRewrite()
	if got := checks.CurrentHTTPRewrite(); got != nginxRewrite {
		t.Fatalf("published rewrite state = %+v, want %+v", got, nginxRewrite)
	}
}

// Admission reads the web server's state from its first mint.
func TestAdmissionStartReadsHTTPRewrite(t *testing.T) {
	dir := t.TempDir()
	db, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	cfg := &config.Config{StatePath: dir}
	useActiveConfig(t, cfg)
	d := New(cfg, st, nil, "")
	calls := withHostHTTPRewrite(t, nginxRewrite)
	prev := detectHostHTTPRewrite
	ownerAtRead := true
	detectHostHTTPRewrite = func() checks.HTTPRewrite { ownerAtRead = d.admission != nil; return prev() }
	d.startAdmissionWith(testAdmissionOptions(d, db))
	defer d.stopAdmission()
	if *calls != 1 || checks.CurrentHTTPRewrite() != nginxRewrite || ownerAtRead || d.admission == nil {
		t.Fatalf("admission start read the web server %d times (owner present at read %v), state %+v", *calls, ownerAtRead, checks.CurrentHTTPRewrite())
	}
	owner := d.admission
	d.startAdmissionWith(testAdmissionOptions(d, db))
	if *calls != 1 || d.admission != owner {
		t.Fatalf("a second start read again (%d reads) or replaced the owner", *calls)
	}
}

// Every reload attempt re-reads the web server, also one that changes no
// setting, needs a restart or fails, and so does a web UI save: an operator
// who changed the web server reloads CSM to have it read again. The reload's
// own outcome is unchanged.
func TestConfigReloadReadsHTTPRewrite(t *testing.T) {
	for name, edit := range map[string]func(t *testing.T, path string, loaded *config.Config){
		"unchanged": func(*testing.T, string, *config.Config) {},
		"safe change": func(t *testing.T, path string, loaded *config.Config) {
			edited := &config.Config{Hostname: "host-a"}
			edited.Thresholds.MailQueueWarn = 250
			edited.Integrity = loaded.Integrity
			seedConfigAtPath(t, path, edited)
		},
		"restart required": func(t *testing.T, path string, loaded *config.Config) {
			edited := &config.Config{Hostname: "host-b"}
			edited.Integrity = loaded.Integrity
			seedConfigAtPath(t, path, edited)
		},
		"bad yaml": func(t *testing.T, path string, _ *config.Config) {
			if err := os.WriteFile(path, []byte("not: valid: yaml:\n  :\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "csm.yaml")
			seedConfigAtPath(t, path, &config.Config{Hostname: "host-a"})
			loaded, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			d := newDaemonForReloadTest(t, loaded)
			edit(t, path, loaded)
			checks.SetHTTPRewrite(checks.HTTPRewrite{State: checks.RewriteNone})
			calls := withHostHTTPRewrite(t, nginxRewrite)
			d.reloadConfig()
			if *calls != 1 || checks.CurrentHTTPRewrite() != nginxRewrite {
				t.Fatalf("reload read the web server %d times, state %+v", *calls, checks.CurrentHTTPRewrite())
			}
			if got := config.Active(); got == nil || got.Hostname != "host-a" {
				t.Fatalf("reload outcome changed: live hostname %q", getHostname(got))
			}
		})
	}
	t.Run("web ui save", func(t *testing.T) {
		d := newTestDaemon(t)
		useActiveConfig(t, d.cfg)
		calls := withHostHTTPRewrite(t, nginxRewrite)
		d.applySavedConfig()
		if *calls != 1 || checks.CurrentHTTPRewrite() != nginxRewrite {
			t.Fatalf("save read the web server %d times, state %+v", *calls, checks.CurrentHTTPRewrite())
		}
	})
}

// A slower read never overwrites a newer one: the second refresh cannot
// read the web server while the first is still reading.
func TestHTTPRewriteRefreshSerializesReadAndPublish(t *testing.T) {
	prev, prevState := detectHostHTTPRewrite, checks.CurrentHTTPRewrite()
	t.Cleanup(func() {
		detectHostHTTPRewrite = prev
		checks.SetHTTPRewrite(prevState)
	})
	var entered atomic.Int32
	firstIn, release, secondReady := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	detectHostHTTPRewrite = func() checks.HTTPRewrite {
		if entered.Add(1) == 1 {
			close(firstIn)
			<-release
			return checks.HTTPRewrite{State: checks.RewriteNone}
		}
		return nginxRewrite
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); (&Daemon{}).refreshHTTPRewrite() }()
	<-firstIn
	go func() { defer wg.Done(); close(secondReady); (&Daemon{}).refreshHTTPRewrite() }()
	<-secondReady
	time.Sleep(time.Second)
	if n := entered.Load(); n != 1 {
		t.Fatalf("a second read entered while the first was reading (%d reads)", n)
	}
	releaseOnce.Do(func() { close(release) })
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("refreshes did not finish")
	}
	if got := checks.CurrentHTTPRewrite(); got != nginxRewrite {
		t.Fatalf("final state %+v, want the newer read %+v", got, nginxRewrite)
	}
}

// Every critical tick re-reads the web server, even one that stops at a
// failed integrity check; the deep tier does not.
func TestCriticalTickReadsHTTPRewrite(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	cfg := &config.Config{StatePath: dir}
	cfg.Integrity.BinaryHash = "deadbeef"
	d := New(cfg, st, nil, "/nonexistent/binary")
	calls := withHostHTTPRewrite(t, nginxRewrite)
	d.runPeriodicChecks(checks.TierCritical)
	d.runPeriodicChecks(checks.TierDeep)
	if *calls != 1 || checks.CurrentHTTPRewrite() != nginxRewrite {
		t.Fatalf("ticks read the web server %d times, state %+v", *calls, checks.CurrentHTTPRewrite())
	}
	for _, next := range []checks.HTTPRewrite{{State: checks.RewriteUnknown, Server: "nginx", Reason: "unreadable"}, {State: checks.RewriteNone, Server: "nginx"}} {
		withHostHTTPRewrite(t, next)
		d.runPeriodicChecks(checks.TierCritical)
		if got := checks.CurrentHTTPRewrite(); got != next {
			t.Fatalf("tick published %+v, want %+v", got, next)
		}
	}
}

// The production reader follows the web server the config names, at the
// root web_server.config_dir sets, as the files change.
func TestHTTPRewriteProductionHostReader(t *testing.T) {
	prevState := checks.CurrentHTTPRewrite()
	platform.ResetForTest()
	t.Cleanup(func() {
		platform.ResetForTest()
		checks.SetHTTPRewrite(prevState)
	})
	root := t.TempDir()
	cfg := &config.Config{}
	cfg.WebServer.Type = "nginx"
	cfg.WebServer.ConfigDir = root
	if !InstallPlatformOverrides(cfg) {
		t.Fatal("platform overrides were not installed")
	}
	main := filepath.Join(root, "nginx.conf")
	for _, tc := range []struct {
		body  string
		state checks.RewriteState
	}{
		{"http { server { listen 80; } }\n", checks.RewriteNone},
		{"http { set_real_ip_from 192.0.2.0/24; }\n", checks.RewriteActive},
		{"http { include missing.conf; }\n", checks.RewriteUnknown},
	} {
		if err := os.WriteFile(main, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := productionDetectHostHTTPRewrite(); got.State != tc.state || got.Server != platform.WSNginx {
			t.Fatalf("%q read as %+v, want state %d from nginx", tc.body, got, tc.state)
		}
	}
}
