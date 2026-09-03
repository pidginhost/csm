package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func perfWPCronFinding(account, path string) alert.Finding {
	return alert.Finding{
		Severity:  alert.Warning,
		Check:     "perf_wp_cron",
		Message:   "WP-Cron not disabled for " + account,
		Details:   "File: " + path + " - add define('DISABLE_WP_CRON', true); and use a real cron job instead",
		Timestamp: time.Now(),
	}
}

func stubAutoFixWPCron(fn func(*config.Config, []alert.Finding) ([]alert.Finding, []string)) func() {
	orig := autoFixWPCron
	autoFixWPCron = fn
	return func() { autoFixWPCron = orig }
}

func drainAlertCh(d *Daemon) []alert.Finding {
	var out []alert.Finding
	for {
		select {
		case f := <-d.alertCh:
			out = append(out, f)
		default:
			return out
		}
	}
}

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(&config.Config{}, st, nil, "")
}

// A warning-severity perf_wp_cron finding stays off the alert channel. The
// scan-output handler must still forward it to the auto-fix.
func TestProcessScanFindings_TriggersWPCronAutoFix(t *testing.T) {
	d := newTestDaemon(t)

	var seen []alert.Finding
	defer stubAutoFixWPCron(func(_ *config.Config, fs []alert.Finding) ([]alert.Finding, []string) {
		seen = fs
		return nil, nil
	})()

	wpcron := perfWPCronFinding("alice", "/home/alice/public_html/wp-config.php")
	d.processScanFindings(&config.Config{}, []alert.Finding{wpcron}, nil, "test")

	if len(seen) != 1 || seen[0].Check != "perf_wp_cron" {
		t.Fatalf("WP-Cron auto-fix not invoked with the perf_wp_cron finding; got %+v", seen)
	}
}

func TestRecordTierRunFindingsLiveTriggersWPCronAutoFix(t *testing.T) {
	d := newTestDaemon(t)
	c := &ControlListener{d: d}

	var seen []alert.Finding
	defer stubAutoFixWPCron(func(_ *config.Config, fs []alert.Finding) ([]alert.Finding, []string) {
		seen = fs
		return nil, nil
	})()

	wpcron := perfWPCronFinding("alice", "/home/alice/public_html/wp-config.php")
	// live, alerts off: auto-fix is gated on the run being live, not on alerts.
	c.recordTierRunFindings(&config.Config{}, []alert.Finding{wpcron}, nil, true, false)

	if len(seen) != 1 || seen[0].Check != "perf_wp_cron" {
		t.Fatalf("live control tier run did not invoke WP-Cron auto-fix; got %+v", seen)
	}
}

func TestRecordTierRunFindingsDryRunSkipsWPCronAutoFix(t *testing.T) {
	d := newTestDaemon(t)
	c := &ControlListener{d: d}

	called := false
	defer stubAutoFixWPCron(func(*config.Config, []alert.Finding) ([]alert.Finding, []string) {
		called = true
		return nil, nil
	})()

	wpcron := perfWPCronFinding("alice", "/home/alice/public_html/wp-config.php")
	c.recordTierRunFindings(&config.Config{}, []alert.Finding{wpcron}, nil, false, false)

	if called {
		t.Fatal("dry-run control tier run must not invoke WP-Cron auto-fix")
	}
	if got := d.store.LatestFindings(); len(got) != 1 || got[0].Check != "perf_wp_cron" {
		t.Fatalf("dry-run control tier run should still record latest findings, got %+v", got)
	}
	if got := drainAlertCh(d); len(got) != 0 {
		t.Fatalf("dry-run control tier run should not enqueue alerts, got %+v", got)
	}
}

// A dry run must never edit a customer's wp-config.php, even when the caller
// also asked for alerts: auto-fix is gated on the run being live, the alert
// push on the alerts flag. The two are independent.
func TestRecordTierRunFindingsDryRunWithAlertsSkipsAutoFix(t *testing.T) {
	d := newTestDaemon(t)
	c := &ControlListener{d: d}

	called := false
	defer stubAutoFixWPCron(func(*config.Config, []alert.Finding) ([]alert.Finding, []string) {
		called = true
		return nil, nil
	})()

	wpcron := perfWPCronFinding("alice", "/home/alice/public_html/wp-config.php")
	critical := alert.Finding{Severity: alert.Critical, Check: "webshell", Message: "shell", Timestamp: time.Now()}
	c.recordTierRunFindings(&config.Config{}, []alert.Finding{wpcron, critical}, nil, false, true)

	if called {
		t.Fatal("dry-run tier run must not invoke WP-Cron auto-fix even with alerts on")
	}
	got := drainAlertCh(d)
	if len(got) != 1 || got[0].Check != "webshell" {
		t.Fatalf("alerts-on run should still push the actionable finding, got %+v", got)
	}
}

func TestProcessScanFindings_DoesNotAutoFixSuppressedWPCron(t *testing.T) {
	d := newTestDaemon(t)
	wpcron := perfWPCronFinding("alice", "/home/alice/public_html/wp-config.php")
	if err := d.store.SaveSuppressions([]state.SuppressionRule{
		{
			ID:          "s1",
			Check:       "perf_wp_cron",
			PathPattern: "/home/alice/public_html/wp-config.php",
			Reason:      "operator suppressed",
		},
	}); err != nil {
		t.Fatalf("save suppressions: %v", err)
	}

	var seen []alert.Finding
	defer stubAutoFixWPCron(func(_ *config.Config, fs []alert.Finding) ([]alert.Finding, []string) {
		seen = fs
		return nil, nil
	})()

	d.processScanFindings(&config.Config{}, []alert.Finding{wpcron}, nil, "test")

	if len(seen) != 0 {
		t.Fatalf("suppressed perf_wp_cron finding must not be auto-fixed, got %+v", seen)
	}
	if got := drainAlertCh(d); len(got) != 0 {
		t.Fatalf("perf_wp_cron warning should still stay off alert channel, got %+v", got)
	}
}

// Routing perf findings to the auto-fix must not regress the email-suppression
// the alert-channel filter provides: warning-severity perf findings still never
// reach the dispatcher, only actionable findings do.
func TestProcessScanFindings_KeepsPerfWarningsOffAlertChannel(t *testing.T) {
	d := newTestDaemon(t)
	defer stubAutoFixWPCron(func(*config.Config, []alert.Finding) ([]alert.Finding, []string) {
		return nil, nil
	})()

	wpcron := perfWPCronFinding("alice", "/home/alice/public_html/wp-config.php")
	critical := alert.Finding{Severity: alert.Critical, Check: "webshell", Message: "shell", Timestamp: time.Now()}

	d.processScanFindings(&config.Config{}, []alert.Finding{wpcron, critical}, nil, "test")

	got := drainAlertCh(d)
	if len(got) != 1 || got[0].Check != "webshell" {
		t.Fatalf("expected only the non-perf finding on the alert channel, got %+v", got)
	}
}

// Once the auto-fix reports a fixed finding, the scan-output handler must clear
// it from the latest-findings surface so the Web UI does not keep showing a
// warning that is already resolved.
func TestProcessScanFindings_DismissesFixedFindingFromLatest(t *testing.T) {
	d := newTestDaemon(t)

	wpcron := perfWPCronFinding("alice", "/home/alice/public_html/wp-config.php")
	defer stubAutoFixWPCron(func(_ *config.Config, fs []alert.Finding) ([]alert.Finding, []string) {
		return []alert.Finding{{Check: "auto_response", Message: "AUTO-FIX: disabled WP-Cron", Severity: alert.Warning}},
			[]string{wpcron.Key()}
	})()

	d.processScanFindings(&config.Config{}, []alert.Finding{wpcron}, []string{"perf_wp_cron"}, "test")

	for _, f := range d.store.LatestFindings() {
		if f.Check == "perf_wp_cron" {
			t.Fatalf("fixed perf_wp_cron finding should have been dismissed from latest findings")
		}
	}

	hist, _ := d.store.ReadHistory(10, 0)
	found := false
	for _, f := range hist {
		if f.Check == "auto_response" {
			found = true
		}
	}
	if !found {
		t.Fatalf("auto-fix action should be recorded in history")
	}
}
