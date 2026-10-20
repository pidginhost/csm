package health

import "time"

// LearningStatus is the anti-spam learner's health while it runs, paused
// or not. PendingReports is nil when the last pass did not enumerate every
// folder, so an unknown backlog never reads as zero.
type LearningStatus struct {
	Publishing     bool      `json:"publishing"`
	LastPass       time.Time `json:"last_pass,omitzero"`
	PassUnfinished bool      `json:"pass_unfinished,omitempty"`
	PendingReports *int      `json:"pending_reports,omitempty"`
	OldestPending  time.Time `json:"oldest_pending,omitzero"`
	// StateError is a fixed code. Ledger counts are absent if they could
	// not be read, so unavailable state never looks empty.
	StateError       string    `json:"state_error,omitempty"`
	LiveClusters     *int      `json:"live_clusters,omitempty"`
	ZeroTargets      *int      `json:"zero_target_records,omitempty"`
	UncertainIntents *int      `json:"uncertain_intents,omitempty"`
	BodyBytes        *int64    `json:"body_bytes,omitempty"`
	OldestUnchecked  time.Time `json:"oldest_unchecked,omitzero"`
	AuditCompleted   time.Time `json:"audit_completed,omitzero"`
}

// LearningProvider is implemented by a daemon that can run the learner.
type LearningProvider interface {
	LearningStatus() *LearningStatus
}

// Clone copies s, including its optional counts.
func (s *LearningStatus) Clone() *LearningStatus {
	if s == nil {
		return nil
	}
	out := *s
	out.PendingReports = clonePtr(s.PendingReports)
	out.LiveClusters = clonePtr(s.LiveClusters)
	out.ZeroTargets = clonePtr(s.ZeroTargets)
	out.UncertainIntents = clonePtr(s.UncertainIntents)
	out.BodyBytes = clonePtr(s.BodyBytes)
	return &out
}
