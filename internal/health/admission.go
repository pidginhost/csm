package health

import (
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// AdmissionStatus is the admission ledger's status and the ingress health
// (spec 5.17). CheckedAt is when the daemon read them; doctor judges the
// Critical-gap rule from it.
type AdmissionStatus struct {
	CheckedAt time.Time                `json:"checked_at"`
	Ledger    *admission.LedgerStatus  `json:"ledger,omitempty"`
	Ingress   *admission.IngressHealth `json:"ingress,omitempty"`
	Owner     *AdmissionOwner          `json:"owner,omitempty"`
}

// AdmissionOwner is what the ledger's owner knows that the ledger cannot
// show: why it is not running, its clock readings, where the ceiling came
// from, the legacy import and the inventory reads.
type AdmissionOwner struct {
	// Error is why the owner is not running; empty once it is.
	Error string `json:"error,omitempty"`
	// TickError is why the last clock reading was refused. Nothing is
	// admitted until a reading succeeds.
	TickError string `json:"tick_error,omitempty"`
	// ClockDegraded is set while the wall clock is behind the ledger's
	// high-water mark or disagrees with the time since boot (spec 5.4).
	ClockDegraded bool      `json:"clock_degraded"`
	LastTick      time.Time `json:"last_tick,omitempty"`
	// CeilingSource says whether the ceiling is max_blocks_per_hour, its
	// default or the largest ceiling the ledger accepts.
	CeilingSource string `json:"ceiling_source,omitempty"`
	// Import describes this process's import or retained charges found at
	// startup. An initial read error is process-local; restart restores a
	// known horizon without re-reading the legacy file.
	Import         *AdmissionImport `json:"import,omitempty"`
	InventoryAt    time.Time        `json:"inventory_at,omitempty"`
	InventoryError string           `json:"inventory_error,omitempty"`
	// DamageError is the latest drain cause that discarded damaged arrivals.
	// It survives recovery from any later failure in that drain and is kept
	// until the owner restarts.
	DamageError string `json:"damage_error,omitempty"`
	// ExecutionHeld is why automatic execution is held: block work waits,
	// deferred as an unavailable engine, until a probe succeeds.
	ExecutionHeld string `json:"execution_held,omitempty"`
	// Verdict is the panel verdict stage of an owner that executes.
	Verdict *AdmissionVerdict `json:"verdict,omitempty"`
}

// AdmissionVerdict is the verdict callback stage (spec 4.4). The gauges
// are its current state. The counters and the failure window count this
// process's calls and start from zero at a restart; committed refusals
// stay in the ledger. Errors are fixed classes, never response text.
type AdmissionVerdict struct {
	Enabled       bool   `json:"enabled"`
	Epoch         uint64 `json:"epoch"`
	Pending       int    `json:"pending"`
	InFlight      uint64 `json:"in_flight"`
	Ready         int    `json:"ready"`
	StageRetiring bool   `json:"stage_retiring"`
	// Asked counts calls a worker started; each ends as one response,
	// failure or cancellation.
	Asked            uint64 `json:"asked"`
	ResponsesAllow   uint64 `json:"responses_allow"`
	ResponsesDefault uint64 `json:"responses_default"`
	Failed           uint64 `json:"failed"`
	Cancelled        uint64 `json:"cancelled"`
	// Discarded counts jobs cancelled before their call and answers no
	// longer usable when they arrived or were due.
	Discarded    uint64 `json:"discarded"`
	ReadyEvicted uint64 `json:"ready_evicted"`
	// AllowEndings counts committed verdict_allow refusals.
	AllowEndings uint64     `json:"allow_endings"`
	LastError    *string    `json:"last_error"`
	LastErrorAt  *time.Time `json:"last_error_at"`
	// LastHourFailed counts failures in the sixty minutes of process
	// monotonic time up to now.
	LastHourFailed uint64 `json:"last_hour_failed"`
}

// AdmissionImport is the legacy hour's spend imported as charges. They
// count at least until an hour after At, the end of that legacy hour;
// conservative elapsed-time retention can hold them longer.
type AdmissionImport struct {
	Units uint32    `json:"units"`
	At    time.Time `json:"at,omitempty"`
	// Error is why the legacy counter could not be read: the ledger then
	// started without credit.
	Error string `json:"error,omitempty"`
}

// AdmissionProvider is implemented by a daemon that owns an admission
// ledger. Without one the snapshot carries no admission view, which must
// not read as a healthy ledger.
type AdmissionProvider interface {
	AdmissionStatus() *AdmissionStatus
}

func cloneAdmissionStatus(in *AdmissionStatus) *AdmissionStatus {
	if in == nil {
		return nil
	}
	out := *in
	if in.Ledger != nil {
		ledger := *in.Ledger
		ledger.Queue.Occupancy = slices.Clone(ledger.Queue.Occupancy)
		ledger.Counters.Rows = slices.Clone(ledger.Counters.Rows)
		ledger.Outcomes.Hour = slices.Clone(ledger.Outcomes.Hour)
		ledger.Outcomes.Day = slices.Clone(ledger.Outcomes.Day)
		ledger.Outcomes.Month = slices.Clone(ledger.Outcomes.Month)
		ledger.Notices.Records = slices.Clone(ledger.Notices.Records)
		out.Ledger = &ledger
	}
	if in.Ingress != nil {
		ingress := *in.Ingress
		out.Ingress = &ingress
	}
	if in.Owner != nil {
		owner := *in.Owner
		if in.Owner.Import != nil {
			imp := *in.Owner.Import
			owner.Import = &imp
		}
		if in.Owner.Verdict != nil {
			v := *in.Owner.Verdict
			if v.LastError != nil {
				class := *v.LastError
				v.LastError = &class
			}
			if v.LastErrorAt != nil {
				at := *v.LastErrorAt
				v.LastErrorAt = &at
			}
			owner.Verdict = &v
		}
		out.Owner = &owner
	}
	return &out
}
