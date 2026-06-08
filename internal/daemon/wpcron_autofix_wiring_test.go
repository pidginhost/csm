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

// A perf_wp_cron finding is warning severity and is intentionally kept off the
// alert channel, so before this fix the WP-Cron auto-fix (only reachable from
// dispatchBatch, which the alert channel feeds) never saw it. The scan-output
// handler must forward scan findings to the auto-fix where they still exist.
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
