//go:build linux

package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/store"
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

func TestLearningStatusReportsReconcilePause(t *testing.T) {
	d := newLearningDaemon(t)
	// Use the daemon's real ledger without starting background work.
	e := learn.NewEngine(learn.EngineConfig{Ledger: learn.Open(store.Global())})
	r := &learnerRunner{engine: e, watcher: &fakeWatcher{}}
	r.setGate(antispam.LearningGate{Install: true, Publish: true})
	d.antispamLearner.Store(r)
	t.Cleanup(func() { d.antispamLearner.Store(nil) })
	if !d.LearningStatus().Publishing {
		t.Fatal("open engine did not report publishing")
	}
	d.pauseLearner()
	if d.LearningStatus().Publishing {
		t.Fatal("paused engine still reports publishing")
	}
	r.setGate(antispam.LearningGate{Install: true, Publish: true})
	if !d.LearningStatus().Publishing {
		t.Fatal("resumed engine did not report publishing")
	}
}

type statsFailureEngine struct{ fakeEngine }

func (*statsFailureEngine) Stats() (learn.Stats, error) {
	return learn.Stats{}, errors.New("unreadable ledger")
}

func TestLearningStatusDoesNotReportZeroOnStateError(t *testing.T) {
	d := &Daemon{}
	d.antispamLearner.Store(&learnerRunner{engine: &statsFailureEngine{}, watcher: &fakeWatcher{}})
	data, err := json.Marshal(d.LearningStatus())
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["state_error"] != "state_io" {
		t.Fatalf("state failure is not visible: %s", data)
	}
	for _, name := range []string{"live_clusters", "zero_target_records", "uncertain_intents", "body_bytes"} {
		if _, ok := got[name]; ok {
			t.Errorf("unavailable %s reported as a count: %s", name, data)
		}
	}
}

var labelSet = regexp.MustCompile(`\{([^}]*)\}`)

func TestLearningMetricsHaveNoTenantLabels(t *testing.T) {
	m := learningMetricsSet()
	admitted, committed := m.Admitted.Value(), m.Committed.Value()
	recordLearningPass(learnwatch.PassReport{
		Accounts: 1, Submitted: 2, Committed: 3, Pending: 1,
		Skipped:       map[string]int{"tagged": 1, learnwatch.SkipOptedOut: 2},
		OldestPending: time.Now().Add(-time.Minute),
	}, time.Now())
	if m.Admitted.Value()-admitted != 2 || m.Committed.Value() != committed {
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

func TestLearningCommitMetricsUseEngineNotifications(t *testing.T) {
	engines := withFakeEngines(t)
	withFakeWatchers(t)
	d := newLearningDaemon(t)
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	callback := (*engines)[0].cfg.OnReportCommit
	if callback == nil {
		t.Fatal("engine commits are not wired to metrics")
	}
	m := learningMetricsSet()
	before := m.Committed.Value()
	callback()
	callback()
	if got := m.Committed.Value() - before; got != 2 {
		t.Fatalf("commit counter increment = %v, want 2", got)
	}
}

func TestLearningMetricsInvalidateUnreadableState(t *testing.T) {
	watchers := withFakeWatchers(t)
	r := &learnerRunner{engine: &statsFailureEngine{}}
	newRunnerWatcher(nil, r)
	m := learningMetricsSet()
	recordLearningStats(learn.Stats{LiveClusters: 7, BodyBytes: 123})
	(*watchers)[0].cfg.OnPass(learnwatch.PassReport{})
	for _, g := range []*metrics.Gauge{m.LiveClusters, m.ZeroTargets, m.BodyBytes, m.Uncertain, m.OldestUnchecked, m.AuditCompleted, m.Reconstructed} {
		if !math.IsNaN(g.Value()) {
			t.Errorf("unavailable engine state reported as %v", g.Value())
		}
	}
	recordLearningStats(learn.Stats{})
	if m.LiveClusters.Value() != 0 || m.Uncertain.Value() != 0 {
		t.Fatal("successful read did not restore empty counts")
	}
}

func TestLearningCapacityWarningFromWatcher(t *testing.T) {
	withFakeEngines(t)
	withLastWatcher(t, learnwatch.PassReport{Skipped: map[string]int{learn.SkipAccountCapacity: 2}}, time.Now())
	d := newLearningDaemon(t)
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	var found []antispam.Problem
	for _, p := range d.learnerProblems() {
		if p.Key == antispam.ReasonAccountCapacity {
			found = append(found, p)
		}
	}
	if len(found) != 1 || found[0].Severity != antispam.Warning || found[0].Code != antispam.CodeLearning || !strings.Contains(found[0].Detail, "2") {
		t.Fatalf("capacity problems %+v", found)
	}
}
