//go:build linux

package daemon

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/metrics"
)

// lastWatcher reports a fixed last pass.
type lastWatcher struct {
	fakeWatcher
	report learnwatch.PassReport
	at     time.Time
}

func (w *lastWatcher) Last() (learnwatch.PassReport, time.Time) { return w.report, w.at }

func withLastWatcher(t *testing.T, r learnwatch.PassReport, at time.Time) {
	t.Helper()
	saved := newLearnWatcher
	newLearnWatcher = func(cfg learnwatch.WatcherConfig) learnWatcher {
		return &lastWatcher{fakeWatcher: fakeWatcher{cfg: cfg, stopped: make(chan struct{})}, report: r, at: at}
	}
	t.Cleanup(func() { newLearnWatcher = saved })
}

func TestLearningHealthWhilePaused(t *testing.T) {
	withFakeEngines(t)
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	oldest := at.Add(-time.Hour)
	withLastWatcher(t, learnwatch.PassReport{Pending: 4, OldestPending: oldest}, at)
	d := newLearningDaemon(t)
	if d.LearningStatus() != nil {
		t.Fatal("learning status without a learner")
	}
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	d.syncLearner(learnedOutcome(antispam.LearningGate{}, testTarget))
	s := d.LearningStatus()
	if s == nil || s.Publishing || !s.LastPass.Equal(at) || s.PendingReports == nil || *s.PendingReports != 4 || !s.OldestPending.Equal(oldest) {
		t.Fatalf("paused learning status %+v", s)
	}
}

func TestLearningStatusUnfinishedPassHasNoPendingCount(t *testing.T) {
	withFakeEngines(t)
	withLastWatcher(t, learnwatch.PassReport{Pending: 0, Unfinished: true}, time.Now())
	d := newLearningDaemon(t)
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	if s := d.LearningStatus(); s == nil || s.PendingReports != nil || !s.PassUnfinished {
		t.Fatalf("status %+v", s)
	}
}

var labelSet = regexp.MustCompile(`\{([^}]*)\}`)

func TestLearningMetricsHaveNoTenantLabels(t *testing.T) {
	m := learningMetricsSet()
	recordLearningPass(learnwatch.PassReport{
		Accounts: 1, Submitted: 2, Committed: 3, Pending: 1,
		Skipped:       map[string]int{"tagged": 1, learnwatch.SkipOptedOut: 2},
		OldestPending: time.Now().Add(-time.Minute),
	}, time.Now())
	if m.Admitted.Value() < 2 || m.Committed.Value() < 3 {
		t.Fatalf("counters %v %v", m.Admitted.Value(), m.Committed.Value())
	}
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.HasPrefix(line, "csm_antispam_learning_") {
			continue
		}
		seen++
		for _, l := range labelSet.FindAllStringSubmatch(line, -1) {
			for _, pair := range strings.Split(l[1], ",") {
				if key, _, _ := strings.Cut(pair, "="); key != "reason" {
					t.Errorf("tenant-capable label %q in %s", key, line)
				}
			}
		}
	}
	for _, name := range []string{"reports_admitted_total", "contributions_committed_total", "skips_total", "pending_reports", "backlog_age_seconds", "last_pass_timestamp_seconds", "live_clusters", "zero_target_records", "body_bytes", "uncertain_intents", "oldest_unchecked_timestamp_seconds", "audit_completed_timestamp_seconds", "reconstructed_clusters"} {
		if !strings.Contains(buf.String(), "csm_antispam_learning_"+name) {
			t.Errorf("metric %s missing", name)
		}
	}
	if seen == 0 {
		t.Fatal("no learning metrics written")
	}
}
