package daemon

import (
	"math"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/metrics"
)

// learningMetrics are the learner's series. No series carries an account,
// mailbox or UID label; skips are labeled by reason only.
type learningMetrics struct {
	Admitted        *metrics.Counter
	Committed       *metrics.Counter
	Skips           *metrics.CounterVec
	Pending         *metrics.Gauge
	BacklogAge      *metrics.Gauge
	LastPass        *metrics.Gauge
	LiveClusters    *metrics.Gauge
	ZeroTargets     *metrics.Gauge
	BodyBytes       *metrics.Gauge
	Uncertain       *metrics.Gauge
	OldestUnchecked *metrics.Gauge
	AuditCompleted  *metrics.Gauge
	Reconstructed   *metrics.Gauge
}

var (
	learningMetricsOnce     sync.Once
	learningMetricsInstance *learningMetrics
)

func learningMetricsSet() *learningMetrics {
	learningMetricsOnce.Do(func() {
		m := &learningMetrics{
			Admitted:        metrics.NewCounter("csm_antispam_learning_reports_admitted_total", "Spam folder reports the learner accepted."),
			Committed:       metrics.NewCounter("csm_antispam_learning_contributions_committed_total", "Cluster contributions committed from Spam folder reports."),
			Skips:           metrics.NewCounterVec("csm_antispam_learning_skips_total", "Spam folder entries and reports skipped, by reason.", []string{"reason"}),
			Pending:         metrics.NewGauge("csm_antispam_learning_pending_reports", "Reports waiting after the last pass; a lower bound when it was unfinished."),
			BacklogAge:      metrics.NewGauge("csm_antispam_learning_backlog_age_seconds", "Age of the oldest waiting report at the last pass."),
			LastPass:        metrics.NewGauge("csm_antispam_learning_last_pass_timestamp_seconds", "When the last Spam folder pass completed."),
			LiveClusters:    metrics.NewGauge("csm_antispam_learning_live_clusters", "Learned clusters not retired."),
			ZeroTargets:     metrics.NewGauge("csm_antispam_learning_zero_target_records", "Zero-target guard records."),
			BodyBytes:       metrics.NewGauge("csm_antispam_learning_body_bytes", "Bytes of stored anchor messages."),
			Uncertain:       metrics.NewGauge("csm_antispam_learning_uncertain_intents", "Anchor writes with an unknown outcome."),
			OldestUnchecked: metrics.NewGauge("csm_antispam_learning_oldest_unchecked_timestamp_seconds", "Latest time every anchor not yet audited in this rotation was checked."),
			AuditCompleted:  metrics.NewGauge("csm_antispam_learning_audit_completed_timestamp_seconds", "When the anchor audit last completed a rotation."),
			Reconstructed:   metrics.NewGauge("csm_antispam_learning_reconstructed_clusters", "Anchors scheduled for reconstruction since the learner started."),
		}
		for name, c := range map[string]metrics.Collector{
			"csm_antispam_learning_reports_admitted_total":             m.Admitted,
			"csm_antispam_learning_contributions_committed_total":      m.Committed,
			"csm_antispam_learning_skips_total":                        m.Skips,
			"csm_antispam_learning_pending_reports":                    m.Pending,
			"csm_antispam_learning_backlog_age_seconds":                m.BacklogAge,
			"csm_antispam_learning_last_pass_timestamp_seconds":        m.LastPass,
			"csm_antispam_learning_live_clusters":                      m.LiveClusters,
			"csm_antispam_learning_zero_target_records":                m.ZeroTargets,
			"csm_antispam_learning_body_bytes":                         m.BodyBytes,
			"csm_antispam_learning_uncertain_intents":                  m.Uncertain,
			"csm_antispam_learning_oldest_unchecked_timestamp_seconds": m.OldestUnchecked,
			"csm_antispam_learning_audit_completed_timestamp_seconds":  m.AuditCompleted,
			"csm_antispam_learning_reconstructed_clusters":             m.Reconstructed,
		} {
			metrics.MustRegister(name, c)
		}
		learningMetricsInstance = m
	})
	return learningMetricsInstance
}

// recordLearningPass folds one completed pass into the series.
func recordLearningPass(r learnwatch.PassReport, now time.Time) {
	m := learningMetricsSet()
	m.Admitted.Add(float64(r.Submitted))
	for reason, n := range r.Skipped {
		m.Skips.With(reason).Add(float64(n))
	}
	m.Pending.Set(float64(r.Pending))
	age := 0.0
	if !r.OldestPending.IsZero() {
		age = now.Sub(r.OldestPending).Seconds()
	}
	m.BacklogAge.Set(age)
	m.LastPass.Set(float64(now.Unix()))
}

func unixOrZero(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.Unix())
}

// recordLearningStats sets the engine-state series.
func recordLearningStats(s learn.Stats) {
	m := learningMetricsSet()
	m.LiveClusters.Set(float64(s.LiveClusters))
	m.ZeroTargets.Set(float64(s.ZeroTargets))
	m.BodyBytes.Set(float64(s.BodyBytes))
	m.Uncertain.Set(float64(s.UncertainIntents))
	m.OldestUnchecked.Set(unixOrZero(s.OldestUnchecked))
	m.AuditCompleted.Set(unixOrZero(s.AuditCompleted))
	m.Reconstructed.Set(float64(s.Reconstructed))
}

func invalidateLearningStats() {
	m := learningMetricsSet()
	for _, g := range []*metrics.Gauge{m.LiveClusters, m.ZeroTargets, m.BodyBytes, m.Uncertain, m.OldestUnchecked, m.AuditCompleted, m.Reconstructed} {
		g.Set(math.NaN())
	}
}

// LearningStatus is the learner's health for status output, paused or
// not; nil while learning does not run.
func (d *Daemon) LearningStatus() *health.LearningStatus {
	r := d.antispamLearner.Load()
	if r == nil {
		return nil
	}
	rep, at := r.watcher.Last()
	s := &health.LearningStatus{
		Publishing:     r.engine.Publishing(),
		LastPass:       at,
		PassUnfinished: rep.Unfinished,
		OldestPending:  rep.OldestPending,
	}
	if !at.IsZero() && !rep.Unfinished {
		n := rep.Pending
		s.PendingReports = &n
	}
	if st, err := r.engine.Stats(); err == nil {
		s.LiveClusters, s.ZeroTargets, s.UncertainIntents = &st.LiveClusters, &st.ZeroTargets, &st.UncertainIntents
		s.BodyBytes, s.OldestUnchecked, s.AuditCompleted = &st.BodyBytes, st.OldestUnchecked, st.AuditCompleted
	} else {
		s.StateError = antispam.ReasonStateIO
	}
	return s
}
