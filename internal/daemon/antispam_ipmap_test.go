package daemon

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/ipmap"
)

// installTestIPMap uses the real reconciliation decision, with host probes
// replaced so no test needs Exim, rspamd or changes to the host.
func installTestIPMap(t *testing.T, cfg *config.Config, r reconcile.Reconciler) {
	t.Helper()
	parents := []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}}
	r.Invalidate = func(context.Context) error { return nil }
	r.Now = time.Now
	r.Collect = func(context.Context, string) antispam.HostFacts {
		var targets []antispam.TargetFacts
		for _, target := range antispam.MutationTargets() {
			targets = append(targets, antispam.TargetFacts{Target: target, Missing: true, Parents: parents})
		}
		return antispam.HostFacts{
			CPanel: true, MTAExim: true, SpamdDisabled: true,
			EximVersion:     antispam.CommandResult{Stdout: "Exim version 4.100.1\nSupport for: Content_Scanning\n"},
			EximOptions:     antispam.CommandResult{Stdout: "no_prdr_enable\nchunking_advertise_hosts =\n"},
			EximSettings:    antispam.CommandResult{Stdout: "message_size_limit = 50M\nlog_file_path = /var/log/exim_%slog\n"},
			MonitoredLog:    "/var/log/exim_mainlog",
			RspamdOptions:   antispam.CommandResult{Stdout: `{"max_message":62914560,"task_timeout":8}`},
			RspamdVersion:   antispam.CommandResult{Stdout: "Rspamd daemon version 4.2.2"},
			RspamadmVersion: antispam.CommandResult{Stdout: "Rspamadm 4.2.2"},
			RspamdService:   antispam.CommandResult{Stdout: "User=_rspamd\nLoadState=loaded\nCanReload=yes\n"},
			EximService:     antispam.CommandResult{Stdout: "User=\nLoadState=loaded\nCanReload=yes\n"},
			NamedLists:      []antispam.CommandResult{{Stdout: "n\n"}, {Stdout: "n\n"}, {Stdout: "y\n"}},
			Targets:         targets, Record: antispam.RecordFacts{Missing: true}, RspamdGID: 974,
			Socket: antispam.SocketFacts{
				Socket:  antispam.PathFacts{Path: testScanSocket, UID: 974, Mode: fs.ModeSocket | 0o666},
				Parents: parents, RspamdUID: 974, PeerUID: 974, EximUID: 47, EximGID: 12,
			},
			IPMap: antispam.FileFacts{
				File: antispam.PathFacts{Path: ipmap.DefaultPath, GID: 974, Mode: 0o640}, Parents: parents,
			},
		}
	}
	calls := 0
	r.Run = func(_ context.Context, req antispam.Request) (antispam.Result, error) {
		calls++
		if req.Operation != antispam.OpApply {
			t.Fatalf("unexpected request: %+v", req)
		}
		return antispam.Result{Operation: antispam.OpApply, OK: true}, nil
	}
	out := r.Pass(context.Background(), reconcile.DesiredFromConfig(cfg))
	if calls != 1 || out.Err != nil || len(out.Findings) != 0 || !r.Feeds.IPMapActive() {
		t.Fatalf("map not installed: calls=%d active=%v outcome=%+v", calls, r.Feeds.IPMapActive(), out)
	}
}

func TestIPMapLoopReportsStalledCanaryBeforeNextWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, cfg, r := ipmapTestDaemon(t)
		useActiveConfig(t, cfg)
		installTestIPMap(t, cfg, r)
		prev := antispamCanary
		t.Cleanup(func() { antispamCanary = prev })
		var loaded atomic.Bool
		antispamCanary = func(context.Context, string) (string, error) {
			if loaded.Load() {
				return d.ipmapWriter.Load().State().Gen, nil
			}
			return "", nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go d.antispamIPMapLoop(ctx)
		synctest.Wait()
		time.Sleep(ipmap.CanaryGrace + antispamCanaryDelay)
		synctest.Wait()
		if got := latestChecks(d)[reconcile.CheckIPMap]; got != 1 {
			t.Fatalf("stalled canary did not raise a finding after grace: %d", got)
		}
		loaded.Store(true)
		time.Sleep(antispamCanaryDelay)
		synctest.Wait()
		if got := latestChecks(d)[reconcile.CheckIPMap]; got != 0 {
			t.Fatalf("loaded map did not clear finding: %d", got)
		}
		cancel()
		synctest.Wait()
	})
}

func TestIPMapRemovalWaitsForInFlightRefresh(t *testing.T) {
	d, cfg, r := ipmapTestDaemon(t)
	useActiveConfig(t, cfg)
	if err := r.IPMap.Write(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	antispamRspamdGroup = func(context.Context) int { close(entered); <-release; return os.Getgid() }
	refreshed := make(chan struct{})
	go func() {
		d.refreshIPMap(context.Background(), time.Now())
		close(refreshed)
	}()
	<-entered
	removed := make(chan error, 1)
	go func() { removed <- r.IPMap.Remove() }()
	select {
	case err := <-removed:
		t.Errorf("removal overtook a pending refresh: %v", err)
		close(release)
		<-refreshed
		return
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-refreshed
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(antispamIPMapPath); !os.IsNotExist(err) {
		t.Fatalf("in-flight refresh outlived map removal: %v", err)
	}
}

// One failed canary probe, such as during an rspamd reload, is not an IP
// map problem; two in a row are.
func TestCanaryProbeFailureNeedsTwoInARow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, cfg, r := ipmapTestDaemon(t)
		useActiveConfig(t, cfg)
		installTestIPMap(t, cfg, r)
		prev := antispamCanary
		t.Cleanup(func() { antispamCanary = prev })
		var failures atomic.Int32
		antispamCanary = func(context.Context, string) (string, error) {
			if failures.Load() > 0 {
				failures.Add(-1)
				return "", errors.New("connection refused")
			}
			return d.ipmapWriter.Load().State().Gen, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go d.antispamIPMapLoop(ctx)
		synctest.Wait()
		time.Sleep(ipmap.CanaryGrace + antispamCanaryDelay)
		synctest.Wait()
		failures.Store(1)
		time.Sleep(antispamCanaryDelay)
		synctest.Wait()
		if got := latestChecks(d)[reconcile.CheckIPMap]; got != 0 {
			t.Fatalf("one failed probe raised %d findings", got)
		}
		time.Sleep(antispamCanaryDelay)
		synctest.Wait()
		failures.Store(2)
		time.Sleep(2 * antispamCanaryDelay)
		synctest.Wait()
		if got := latestChecks(d)[reconcile.CheckIPMap]; got != 1 {
			t.Fatalf("two failed probes raised %d findings, want 1", got)
		}
		cancel()
		synctest.Wait()
	})
}

func TestCanaryMissesResetWhenTrackingStops(t *testing.T) {
	for _, change := range []string{"removed", "disabled", "observe", "socket"} {
		t.Run(change, func(t *testing.T) {
			d, cfg, r := ipmapTestDaemon(t)
			useActiveConfig(t, cfg)
			installTestIPMap(t, cfg, r)
			prev := antispamCanary
			t.Cleanup(func() { antispamCanary = prev })
			antispamCanary = func(context.Context, string) (string, error) { return "", errors.New("connection refused") }
			ctx := context.Background()
			check := func(want int) {
				t.Helper()
				d.checkIPMap(ctx, d.ipmapWriter.Load().State().WrittenAt.Add(ipmap.CanaryGrace), false)
				if got := latestChecks(d)[reconcile.CheckIPMap]; got != want {
					t.Fatalf("canary findings = %d, want %d", got, want)
				}
			}
			check(0)
			check(1)
			next := *cfg
			switch change {
			case "removed":
				if err := r.IPMap.Remove(); err != nil {
					t.Fatal(err)
				}
				if err := r.IPMap.Write(ctx); err != nil {
					t.Fatal(err)
				}
			case "disabled", "observe":
				if change == "disabled" {
					next.EmailProtection.Antispam.Enabled = false
				} else {
					next.Mode = "observe"
				}
				useActiveConfig(t, &next)
				d.checkIPMap(ctx, time.Now(), false)
				useActiveConfig(t, cfg)
			case "socket":
				next.EmailProtection.Antispam.RspamdSocket = "/run/rspamd/other.sock"
				useActiveConfig(t, &next)
			}
			check(0)
			check(1)
		})
	}
}

// A failed removal can leave a valid map for the next apply to reuse even
// if its write fails. The active rule still needs monitoring and subtraction.
func TestIPMapMonitorsRetainedMapAfterFailedRemoval(t *testing.T) {
	d, cfg, r := ipmapTestDaemon(t)
	useActiveConfig(t, cfg)
	prev := antispamCanary
	t.Cleanup(func() { antispamCanary = prev })
	antispamCanary = func(context.Context, string) (string, error) { return "", errors.New("connection refused") }
	adb := useTestAttackDB(t)
	w := d.ipmapWriter.Load()
	m := ipmap.Build(ipmap.Sources{Entries: map[string][]string{ipmap.Spam.Name: {"203.0.113.130"}}})
	if _, err := w.Write(m, os.Getgid(), time.Now()); err != nil {
		t.Fatal(err)
	}
	// A nonempty directory gives a deterministic removal error, including
	// when tests run as root. The old map and writer state remain intact.
	path := w.Path
	w.Path = t.TempDir()
	if err := os.WriteFile(filepath.Join(w.Path, "occupied"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := r.IPMap.Remove()
	w.Path = path
	if err == nil {
		t.Fatal("expected removal failure")
	}
	antispamRspamdGroup = func(context.Context) int { return -1 }
	installTestIPMap(t, cfg, r)
	d.checkIPMap(context.Background(), time.Now(), false)
	if got := latestChecks(d)[reconcile.CheckIPMap]; got != 1 {
		t.Errorf("active retained map write failure raised %d findings, want 1", got)
	}
	line := strings.Replace(spamLine("203.0.113.130"), "score=200", "score=170", 1)
	d.recordSpamEvidence(line, time.Now(), cfg)
	if rec := adb.LookupIP("203.0.113.130"); rec != nil {
		t.Errorf("retained map's own score became spam evidence: %+v", rec.Mail)
	}
	antispamRspamdGroup = func(context.Context) int { return os.Getgid() }
	if !d.refreshIPMap(context.Background(), time.Now()) {
		t.Error("active retained map did not retry its failed write")
	}
	if got := latestChecks(d)[reconcile.CheckIPMap]; got != 0 {
		t.Errorf("successful retry left %d write failure findings", got)
	}
}

func TestIPMapDismissalEndsAfterRecovery(t *testing.T) {
	d, cfg, _ := ipmapTestDaemon(t)
	useActiveConfig(t, cfg)
	antispamRspamdGroup = func(context.Context) int { return -1 }
	d.refreshIPMap(context.Background(), time.Now())
	findings := d.store.LatestFindings()
	if len(findings) != 1 || findings[0].Check != reconcile.CheckIPMap {
		t.Fatalf("write failure findings: %+v", findings)
	}
	d.dispatchBatch(findings)
	if !d.store.DismissFindingIfLatest(findings[0]) {
		t.Fatalf("could not dismiss the write failure: %+v", findings)
	}
	d.checkIPMap(context.Background(), time.Now(), false)
	if got := d.store.FilterNew(findings); len(got) != 0 {
		t.Fatal("ongoing failure lost its dismissal")
	}
	antispamRspamdGroup = func(context.Context) int { return os.Getgid() }
	if !d.refreshIPMap(context.Background(), time.Now()) {
		t.Fatal("map did not recover")
	}
	d.ipmapWriter.Load().Path = filepath.Join(t.TempDir(), "missing", "csm_ip.map")
	d.refreshIPMap(context.Background(), time.Now())
	st := d.ipmapWriter.Load().State()
	if st.Err == nil {
		t.Fatal("expected a new write failure")
	}
	next := reconcile.IPMapFinding(st.Err.Error(), time.Now())
	if got := d.store.FilterNew([]alert.Finding{next}); len(got) != 1 {
		t.Fatal("recovered episode's dismissal hid the next failure")
	}
}
