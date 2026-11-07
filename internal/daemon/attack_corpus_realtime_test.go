//go:build linux && yara

package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackcorpus"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/wpcheck"
	"github.com/pidginhost/csm/internal/yara"
)

// corpusAccount owns every planted sample.
const corpusAccount = "corpus"

func TestAttackCorpusRealtime(t *testing.T) {
	useShippedRealtimeEngines(t)
	attackcorpus.Drive(t, attackcorpus.Realtime, runRealtimeSample)
}

// useShippedRealtimeEngines installs the shipped signature and YARA-X rules
// for the test. An engine that loaded no rules fails the test: the run would
// pass every sample only that engine catches.
func useShippedRealtimeEngines(t *testing.T) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	configs := filepath.Join(filepath.Dir(file), "..", "..", "configs")

	sigs := signatures.NewScanner(configs)
	if sigs.RuleCount() == 0 {
		t.Fatalf("no signature rules loaded from %s: %v", configs, sigs.LoadError())
	}
	previousSigs := signatures.SetGlobal(sigs)
	t.Cleanup(func() { signatures.SetGlobal(previousSigs) })

	rules, err := yara.NewScanner(configs)
	if err != nil {
		t.Fatalf("YARA-X rules from %s: %v", configs, err)
	}
	if rules.RuleCount() == 0 {
		t.Fatalf("no YARA-X rules compiled from %s", configs)
	}
	previousYARA := yara.Active()
	yara.SetActive(rules)
	t.Cleanup(func() { yara.SetActive(previousYARA) })
	if yara.Active() != yara.Backend(rules) {
		t.Fatal("the realtime analyzer does not scan with the shipped YARA-X rules")
	}
}

// runRealtimeSample replays one sample as the fanotify event loop meets it:
// each planted file passes the admission filter handleEvent applies and, when
// admitted, the analyzer worker with a read-only descriptor.
func runRealtimeSample(t *testing.T, s attackcorpus.Sample) attackcorpus.Outcome {
	fail := func(err error) attackcorpus.Outcome { return attackcorpus.Outcome{Err: err} }
	// Event paths are read back from /proc/self/fd, which resolves symlinks.
	// A canonical base keeps them inside the roots findings are attributed to.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		return fail(err)
	}
	root, cronDir := filepath.Join(base, "home"), filepath.Join(base, "cron")
	quarantineDir, stateDir := filepath.Join(base, "quarantine"), filepath.Join(base, "state")
	docroot := filepath.Join(root, corpusAccount, "public_html")
	// A live account has its home and document root before any write. Modes
	// are set after creation so the umask cannot narrow them.
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{stateDir, 0o700}, {cronDir, 0o700},
		{root, 0o755}, {filepath.Join(root, corpusAccount), 0o755}, {docroot, 0o755},
	} {
		if err = os.Mkdir(d.path, d.mode); err == nil {
			err = os.Chmod(d.path, d.mode)
		}
		if err != nil {
			return fail(err)
		}
	}
	cfg, err := attackcorpus.Config(stateDir)
	if err != nil {
		return fail(err)
	}

	t.Cleanup(checks.SetAccountHomeRootsForTest([]string{root}))
	t.Cleanup(checks.SetQuarantineDirForTest(quarantineDir))
	previousCron, previousTemp, previousCfg := cronSpoolWatchDir, tempRootPrefixes, config.Active()
	// t.TempDir() is under /tmp, a shared temp tree to the analyzer; account homes never are.
	cronSpoolWatchDir, tempRootPrefixes = cronDir, nil
	config.SetActive(cfg)
	t.Cleanup(func() {
		cronSpoolWatchDir, tempRootPrefixes = previousCron, previousTemp
		config.SetActive(previousCfg)
	})
	// The panel decides the document roots, which gate php.ini admission and
	// the dropper detector. Pin the primary target, not whatever runs the test.
	platform.ResetForTest()
	cpanel := platform.PanelCPanel
	platform.SetOverrides(platform.Overrides{Panel: &cpanel})
	t.Cleanup(platform.ResetForTest)

	planted, err := s.Plant(root, cronDir, corpusAccount)
	if err != nil {
		return fail(err)
	}
	original := make(map[string][]byte, len(s.Files))
	for _, f := range s.Files {
		if original[f.Path], err = s.Content(f); err != nil {
			return fail(err)
		}
	}

	// The dropper detector indexes document roots when the monitor is built.
	alerts := make(chan alert.Finding, 4096)
	fm := newFileMonitorCore(cfg, alerts)
	// A detector the config enables must cover the account, or the run would
	// pass without it.
	if cfg.Thresholds.DropperDetection && (fm.dropper == nil || fm.dropperDocrootFor(filepath.Join(docroot, "index.php")) != docroot) {
		return fail(fmt.Errorf("dropper detector does not cover %s", docroot))
	}
	// Offline, a checksum fetch fails and the verdict stays pending. A stopped
	// fetcher gives the same verdict without a retry goroutine outliving the test.
	stopped := make(chan struct{})
	close(stopped)
	fm.wpCache.(*wpcheck.Cache).SetStopCh(stopped)

	var notAdmitted []string
	for _, f := range s.Files {
		fd, openErr := unix.Open(planted[f.Path], unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return fail(openErr)
		}
		// The event path comes from the descriptor, as in handleEvent.
		link, linkErr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if linkErr != nil {
			_ = unix.Close(fd)
			return fail(linkErr)
		}
		if ev, admit := fm.classifyEvent(normalizeFanotifyEventPath(link), fd); admit {
			fm.analyzeFileSafe(ev)
		} else {
			notAdmitted = append(notAdmitted, f.Path)
		}
		_ = unix.Close(fd)
	}

	// Finish what the monitor's loops would report later: staged package
	// files past their checksum timeout, and dropper candidates past their
	// TTL, every probe retry and the grace window.
	fm.drainStagedPackages(time.Now().Add(stagedPackageTimeout + time.Second))
	if fm.dropper != nil {
		prober, at := fm.newDropperFSProbe(), time.Now()
		for range maxDropperProbeAttempts + 1 {
			at = at.Add(fm.dropper.ttl + dropperGraceWindow)
			fm.dropper.probeStep(at, prober, at)
		}
	}
	if n := atomic.LoadInt64(&fm.droppedAlerts); n != 0 {
		return fail(fmt.Errorf("%d findings did not fit the alert channel", n))
	}

	close(alerts)
	var findings []attackcorpus.Observed
	for f := range alerts {
		findings = append(findings, attackcorpus.ObservedFrom(f, attackcorpus.Attribute(f.FilePath, root, cronDir, corpusAccount)))
	}
	remediation, cleaned, err := attackcorpus.ObserveRemediation(planted, original, quarantineDir)
	if err != nil {
		return fail(err)
	}
	return attackcorpus.Outcome{Findings: findings, Remediation: remediation, CleanedSHA256: cleaned, NotAdmitted: notAdmitted}
}

// The driver itself must work before any corpus relies on it: a web shell
// in uploads is reported on its own path and quarantined, and a plain plugin
// is admitted, analyzed and left alone.
func TestAttackCorpusRealtimeDriver(t *testing.T) {
	useShippedRealtimeEngines(t)
	attempts := attackcorpus.Offline(t)

	const (
		shell  = "public_html/wp-content/uploads/2026/11/cache.php"
		plugin = "public_html/wp-content/plugins/example-widget/example-widget.php"
	)
	dir := t.TempDir()
	writeCorpusManifest(t, dir, "uploads_request_eval", fmt.Sprintf(`{
		"name": "uploads_request_eval", "category": "webshell", "kind": "malicious", "source": "fixture",
		"description": "request parameter evaluated by a PHP file in uploads", "provenance": "self-test bundle",
		"files": [{"path": %q, "selftest": "webshell_request_eval"}],
		"expect": {
			"realtime": {"findings": [{"check": "php_in_uploads_realtime", "file": %[1]q, "min_severity": "critical"}], "remediation": {%[1]q: "quarantined"}},
			"tier": {"gap": "not driven by this test"},
			"fullscan": {"gap": "not driven by this test"}
		}}`, shell))
	writeCorpusManifest(t, dir, "plugin_control", fmt.Sprintf(`{
		"name": "plugin_control", "category": "webshell", "kind": "control", "source": "fixture",
		"description": "an ordinary plugin file", "provenance": "self-test bundle",
		"files": [{"path": %q, "selftest": "benign_wordpress_plugin"}],
		"expect": {"realtime": {}, "tier": {}, "fullscan": {}}}`, plugin))
	samples, err := attackcorpus.Load(dir, "private")
	if err != nil || len(samples) != 2 {
		t.Fatalf("Load = %d samples, %v; want 2", len(samples), err)
	}

	for _, s := range samples {
		t.Run(s.Name, func(t *testing.T) {
			o := runRealtimeSample(t, s)
			// The JSON form leaves out finding text, which can quote sample bytes.
			observed, _ := json.Marshal(o.Findings)
			if o.Err != nil {
				t.Fatalf("driver error: %v", o.Err)
			}
			if len(o.NotAdmitted) != 0 {
				t.Errorf("not admitted: %v", o.NotAdmitted)
			}
			switch s.Kind {
			case "malicious":
				if !slices.ContainsFunc(o.Findings, func(f attackcorpus.Observed) bool {
					return f.File == shell && f.Check == "php_in_uploads_realtime" && f.Severity == alert.Critical
				}) {
					t.Errorf("no Critical php_in_uploads_realtime on %s: %s", shell, observed)
				}
				if o.Remediation[shell] != attackcorpus.Quarantined {
					t.Errorf("%s is %s, want quarantined", shell, o.Remediation[shell])
				}
			case "control":
				if len(o.Findings) != 0 {
					t.Errorf("control findings: %s", observed)
				}
				if o.Remediation[plugin] != attackcorpus.Untouched {
					t.Errorf("%s is %s, want untouched", plugin, o.Remediation[plugin])
				}
			}
			if r := attackcorpus.Judge(s, attackcorpus.Realtime, o); !r.Pass {
				t.Errorf("judge: %v", r.Failures)
			}
		})
	}
	if n := attempts.Load(); n != 0 {
		t.Errorf("%d network attempts, want none", n)
	}
}

func writeCorpusManifest(t *testing.T, corpus, name, manifest string) {
	t.Helper()
	dir := filepath.Join(corpus, "webshell", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sample.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}
