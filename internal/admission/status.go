package admission

import (
	"fmt"
	"strings"
	"time"
)

// MaxRecoveryNeed is the most room one reservation needs in the recovery
// and outbox reserve: its candidate's largest history and its attempt's
// audit rows.
const MaxRecoveryNeed = MaxHistoryBytes + AttemptAuditBytes

// LedgerStatus is a read-only view of the admission ledger (spec 5.17,
// ruling 8). Each section is read on its own and carries its own error,
// so one damaged record never hides the others. Times are the ledger's
// stored admission time, never a current reading.
type LedgerStatus struct {
	Clock    ClockStatus    `json:"clock"`
	Queue    QueueStatus    `json:"queue"`
	Counters CountersStatus `json:"counters"`
	Outcomes OutcomesStatus `json:"outcomes"`
	Ingress  IngressSection `json:"ingress"`
	Ceiling  CeilingStatus  `json:"ceiling"`
	Storage  StorageStatus  `json:"storage"`
	Outbox   OutboxStatus   `json:"outbox"`
	Notices  NoticesStatus  `json:"notices"`
}

// ClockStatus is the stored high-water mark; zero before the first
// reading.
type ClockStatus struct {
	Now   time.Time `json:"now"`
	Error string    `json:"error,omitempty"`
}

// QueueStatus counts live candidates and their positions.
type QueueStatus struct {
	Queued    int `json:"queued"`
	Reserved  int `json:"reserved"`
	Executing int `json:"executing"`
	// Retrying counts queued candidates waiting out a retry backoff.
	Retrying int `json:"retrying"`
	// Oldest is the first queued time of the oldest queued candidate.
	Oldest    time.Time        `json:"oldest,omitempty"`
	Occupancy []QueueOccupancy `json:"occupancy,omitempty"`
	Error     string           `json:"error,omitempty"`
}

// QueueOccupancy is the live candidates of one kind in one partition.
type QueueOccupancy struct {
	Kind      string `json:"kind"`
	Partition string `json:"partition"`
	Count     int    `json:"count"`
}

// CountRow is one lifetime queue counter.
type CountRow struct {
	Event    string `json:"event"`
	Reason   string `json:"reason"`
	Class    string `json:"class,omitempty"`
	Severity string `json:"severity,omitempty"`
	N        uint64 `json:"n"`
}

// CountersStatus is the lifetime queue counters.
type CountersStatus struct {
	Rows  []CountRow `json:"rows,omitempty"`
	Error string     `json:"error,omitempty"`
}

// OutcomeStatusRow is one windowed outcome count.
type OutcomeStatusRow struct {
	Event    string `json:"event,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
	Class    string `json:"class,omitempty"`
	Severity string `json:"severity,omitempty"`
	N        uint64 `json:"n"`
}

// OutcomesStatus is the outcome counts of the last hour, day and 30 days,
// each to the resolution of its buckets.
type OutcomesStatus struct {
	Hour  []OutcomeStatusRow `json:"hour,omitempty"`
	Day   []OutcomeStatusRow `json:"day,omitempty"`
	Month []OutcomeStatusRow `json:"month,omitempty"`
	Error string             `json:"error,omitempty"`
}

// IngressSection is the ledger's record of ingress generations.
type IngressSection struct {
	Generation  uint64 `json:"generation"`
	Open        bool   `json:"open"`
	Persisted   uint64 `json:"persisted"`
	Interrupted uint64 `json:"interrupted"`
	// Resumed is the generation that began after the latest interruption;
	// cleared when a clean generation follows.
	Resumed uint64 `json:"resumed,omitempty"`
	Error   string `json:"error,omitempty"`
}

// LaneStatus is one ceiling allowance.
type LaneStatus struct {
	Size   uint32 `json:"size"`
	Used   uint32 `json:"used"`
	Credit uint32 `json:"credit"`
	// Next is how long until the lane can charge one more unit; zero when
	// it can now.
	Next time.Duration `json:"next"`
}

// CeilingStatus is the hourly ceiling.
type CeilingStatus struct {
	Limit    uint32     `json:"limit"`
	General  LaneStatus `json:"general"`
	Reserved LaneStatus `json:"reserved"`
	Error    string     `json:"error,omitempty"`
}

// AllowanceStatus is one history allowance.
type AllowanceStatus struct {
	Size   uint64 `json:"size"`
	Used   uint64 `json:"used"`
	Credit uint64 `json:"credit"`
	Room   uint64 `json:"room"`
}

// StorageStatus is the history budget and the recovery reserve.
type StorageStatus struct {
	General  AllowanceStatus `json:"general"`
	Reserved AllowanceStatus `json:"reserved"`
	// Pinned is the history of unresolved outcomes.
	Pinned uint64 `json:"pinned"`
	// Outstanding is what reserved and executing attempts hold.
	Outstanding uint64 `json:"outstanding"`
	// RecoveryRoom is what the reserve has left after pinned history,
	// outstanding attempts and the outbox.
	RecoveryRoom uint64 `json:"recovery_room"`
	Ended        uint32 `json:"ended"`
	Loose        uint32 `json:"loose"`
	// ReviewHorizon is when the oldest retained ended history ended: how
	// far back review reaches.
	ReviewHorizon time.Time `json:"review_horizon,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// OutboxStatus is what the outbox holds: unacknowledged audit rows and
// notice records, each at its slot. The slots outstanding attempts hold
// for rows they have not written count in the storage section's room.
type OutboxStatus struct {
	AuditRows     uint64 `json:"audit_rows"`
	AuditBytes    uint64 `json:"audit_bytes"`
	NoticeRecords uint64 `json:"notice_records"`
	NoticeBytes   uint64 `json:"notice_bytes"`
	Error         string `json:"error,omitempty"`
}

// NoticeStatusRow is one notice record.
type NoticeStatusRow struct {
	Kind    string    `json:"kind"`
	Reason  string    `json:"reason,omitempty"`
	Outcome string    `json:"outcome,omitempty"`
	Check   string    `json:"check,omitempty"`
	Effect  string    `json:"effect,omitempty"`
	Count   uint64    `json:"count"`
	Unsent  uint64    `json:"unsent"`
	Last    time.Time `json:"last,omitempty"`
}

// NoticesStatus is the notice records and the latest Critical gap.
type NoticesStatus struct {
	Records []NoticeStatusRow `json:"records,omitempty"`
	// LastCriticalGap is the latest Critical response gap any record saw.
	LastCriticalGap time.Time `json:"last_critical_gap,omitempty"`
	Error           string    `json:"error,omitempty"`
}

// tierNames renders a tier; empty for an unassessed one.
func tierNames(c Class, s Severity) (string, string) {
	if c == 0 && s == 0 {
		return "", ""
	}
	return c.String(), s.String()
}

// CountRows renders queue counters for status.
func CountRows(rows []QueueCount) []CountRow {
	out := make([]CountRow, 0, len(rows))
	for _, r := range rows {
		class, sev := tierNames(r.Key.Class, r.Key.Severity)
		out = append(out, CountRow{Event: r.Key.Event.String(), Reason: r.Key.Reason.String(), Class: class, Severity: sev, N: r.N})
	}
	return out
}

// OutcomeRows renders outcome counts for status.
func OutcomeRows(c OutcomeCounts) []OutcomeStatusRow {
	rows := c.Rows()
	out := make([]OutcomeStatusRow, 0, len(rows))
	for _, r := range rows {
		row := OutcomeStatusRow{N: r.N}
		row.Class, row.Severity = tierNames(r.Key.Class, r.Key.Severity)
		if r.Key.Event != 0 {
			row.Event, row.Reason = r.Key.Event.String(), r.Key.Reason.String()
		} else {
			row.Outcome = r.Key.Outcome.String()
		}
		out = append(out, row)
	}
	return out
}

// NoticeRow renders a notice record for status.
func NoticeRow(r NoticeRecord) NoticeStatusRow {
	row := NoticeStatusRow{Kind: r.Key.Kind.String(), Check: r.Key.Check, Count: r.Count, Unsent: r.Unsent(), Last: r.Last}
	if r.Key.Reason != 0 {
		row.Reason = r.Key.Reason.String()
	}
	if r.Key.Outcome != 0 {
		row.Outcome = r.Key.Outcome.String()
	}
	if r.Key.Effect != 0 {
		row.Effect = r.Key.Effect.String()
	}
	return row
}

// IngressHealth is the in-memory ingress's admission state (ruling 9).
// It is process-local: the ledger may be the damaged part.
type IngressHealth struct {
	Admitting bool `json:"admitting"`
	// StoppedSince is when the ingress stopped admitting; zero while it
	// admits.
	StoppedSince time.Time `json:"stopped_since,omitempty"`
	// CriticalRefused counts Critical arrivals refused since it stopped.
	CriticalRefused uint64 `json:"critical_refused"`
}

// Doctor statuses, as `csm doctor` prints them.
const (
	DoctorOK   = "ok"
	DoctorWarn = "warn"
	DoctorFail = "fail"
)

// DoctorRow is one doctor check.
type DoctorRow struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// DoctorChecks turns a ledger status and the ingress health into fixed
// doctor rows (ruling 10). Either may be nil: then its rows are left out,
// so a daemon without an admission owner prints none. now is the time the
// Critical-gap rule looks back from.
func DoctorChecks(s *LedgerStatus, in *IngressHealth, now time.Time) []DoctorRow {
	var rows []DoctorRow
	if s != nil {
		rows = append(rows, ledgerRow(s))
	}
	if in != nil {
		rows = append(rows, ingressRow(s, in))
	}
	if s == nil {
		return rows
	}
	gap := DoctorRow{Name: "admission response gaps", Status: DoctorOK}
	if last := s.Notices.LastCriticalGap; !last.IsZero() && now.Before(last.Add(time.Hour)) {
		gap.Status = DoctorFail
		gap.Message = "a Critical finding did not receive its response at " + last.UTC().Format(time.RFC3339)
		gap.Fix = "inspect the auto_response_withheld and response_capacity_exhausted notices for the reason"
	}
	reserve := DoctorRow{Name: "admission recovery reserve", Status: DoctorOK}
	if s.Storage.Pinned > 0 || s.Storage.RecoveryRoom < MaxRecoveryNeed {
		reserve.Status = DoctorWarn
		reserve.Message = fmt.Sprintf("%d bytes of unresolved outcomes are pinned; %d bytes of room remain", s.Storage.Pinned, s.Storage.RecoveryRoom)
		reserve.Fix = "resolve unknown outcomes and confirm the audit consumer acknowledges rows; new reservations wait while the reserve is full"
	}
	outbox := DoctorRow{Name: "admission outbox", Status: DoctorOK}
	if used := s.Outbox.AuditBytes + s.Outbox.NoticeBytes; used > RecoveryReserveBytes/2 {
		outbox.Status = DoctorWarn
		outbox.Message = fmt.Sprintf("the outbox holds %d bytes, over half the reserve", used)
		outbox.Fix = "confirm audit and notice delivery is running and acknowledging"
	}
	return append(rows, gap, reserve, outbox)
}

func ledgerRow(s *LedgerStatus) DoctorRow {
	var damaged []string
	for _, section := range []struct{ name, err string }{
		{"clock", s.Clock.Error}, {"queue", s.Queue.Error}, {"counters", s.Counters.Error},
		{"outcomes", s.Outcomes.Error}, {"ingress", s.Ingress.Error}, {"ceiling", s.Ceiling.Error},
		{"storage", s.Storage.Error}, {"outbox", s.Outbox.Error}, {"notices", s.Notices.Error},
	} {
		if section.err != "" {
			damaged = append(damaged, section.name+": "+section.err)
		}
	}
	if len(damaged) == 0 {
		return DoctorRow{Name: "admission ledger", Status: DoctorOK}
	}
	return DoctorRow{
		Name: "admission ledger", Status: DoctorFail, Message: strings.Join(damaged, "; "),
		Fix: "automatic responses are refused while the ledger is damaged; stop csm.service and restore the state database from a backup",
	}
}

func ingressRow(s *LedgerStatus, in *IngressHealth) DoctorRow {
	switch {
	case !in.Admitting:
		return DoctorRow{
			Name: "admission ingress", Status: DoctorFail,
			Message: fmt.Sprintf("refusing every automatic response since %s; %d Critical arrivals refused", in.StoppedSince.UTC().Format(time.RFC3339), in.CriticalRefused),
			Fix:     "the ledger owner has no usable queue snapshot; inspect the daemon log and the admission ledger row",
		}
	case s != nil && s.Ingress.Resumed != 0 && s.Ingress.Resumed == s.Ingress.Generation:
		return DoctorRow{
			Name: "admission ingress", Status: DoctorWarn,
			Message: "the previous ingress generation was interrupted; its held arrivals were lost and counts are lower bounds",
			Fix:     "stop csm.service cleanly next time; the warning clears after a clean restart",
		}
	}
	return DoctorRow{Name: "admission ingress", Status: DoctorOK}
}
