package health

import "time"

// LearningStatus is the anti-spam learner's health while it runs, paused
// or not. PendingReports is nil when the last pass did not enumerate every
// folder, so an unknown backlog never reads as zero.
type LearningStatus struct {
	Publishing       bool      `json:"publishing"`
	LastPass         time.Time `json:"last_pass,omitzero"`
	PassUnfinished   bool      `json:"pass_unfinished,omitempty"`
	PendingReports   *int      `json:"pending_reports,omitempty"`
	OldestPending    time.Time `json:"oldest_pending,omitzero"`
	LiveClusters     int       `json:"live_clusters"`
	ZeroTargets      int       `json:"zero_target_records"`
	UncertainIntents int       `json:"uncertain_intents"`
	BodyBytes        int64     `json:"body_bytes"`
	OldestUnchecked  time.Time `json:"oldest_unchecked,omitzero"`
	AuditCompleted   time.Time `json:"audit_completed,omitzero"`
}

// LearningProvider is implemented by a daemon that can run the learner.
type LearningProvider interface {
	LearningStatus() *LearningStatus
}

// Clone copies s, including its pending count.
func (s *LearningStatus) Clone() *LearningStatus {
	if s == nil {
		return nil
	}
	out := *s
	if s.PendingReports != nil {
		n := *s.PendingReports
		out.PendingReports = &n
	}
	return &out
}
