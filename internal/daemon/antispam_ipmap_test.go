package daemon

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

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
