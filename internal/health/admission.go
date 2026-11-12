package health

import (
	"maps"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// AdmissionStatus is the admission ledger's status and the ingress health.
// CheckedAt is when the daemon read them; doctor judges the
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
	// AuditError is the last delivery failure, including applied consumers.
	// It clears only when a delivery pass succeeds.
	AuditError string `json:"audit_error,omitempty"`
	// Executing is set when admission runs automatic blocks rather than
	// previewing or forecasting them: an outage of admission is then an
	// outage of automatic blocking, and doctor fails where a preview only
	// warns.
	Executing bool `json:"executing"`
	// Error is why the owner is not running; empty once it is.
	Error string `json:"error,omitempty"`
	// TurnError is why the owner's last turn failed while the owner runs.
	// The turn is retried from one second, backing off to once a minute;
	// it clears when a turn succeeds.
	TurnError string `json:"turn_error,omitempty"`
	// RetirementError is the last fault reported while retiring uncertain
	// blocks. Each affected block stays held and is retried; it clears once
	// none is left faulted.
	RetirementError string `json:"retirement_error,omitempty"`
	// TickError is why the last clock reading or its live start failed.
	// Nothing is admitted until both succeed.
	TickError string `json:"tick_error,omitempty"`
	// ClockDegraded is set while the wall clock is behind the ledger's
	// high-water mark or disagrees with the time since boot.
	ClockDegraded bool      `json:"clock_degraded"`
	LastTick      time.Time `json:"last_tick,omitempty"`
	// CeilingSource says whether the ceiling is max_blocks_per_hour, its
	// default or the largest ceiling the ledger accepts.
	CeilingSource string `json:"ceiling_source,omitempty"`
	// Import describes this process's import or retained charges found at
	// startup, or why the legacy state could not be read when execution
	// began. A read error is process-local; restart restores a known
	// horizon without re-reading the legacy file.
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
	// ExecutionHeldBy names what holds execution: "policy" for a refused
	// execution policy, "firewall" for the firewall engine.
	ExecutionHeldBy string `json:"execution_held_by,omitempty"`
	// Verdict is the panel verdict stage of an owner with an engine.
	Verdict *AdmissionVerdict `json:"verdict,omitempty"`
	// DryRun is the dry-run forecast of an owner with an engine.
	DryRun *AdmissionDryRun `json:"dry_run,omitempty"`
	// Set combines the last scheduling turn's non-admission snapshot with
	// current ledger holds outside a dry run; SetError is why that turn
	// could not read the set.
	Set      *AdmissionSet `json:"set,omitempty"`
	SetError string        `json:"set_error,omitempty"`
	// PreviewReplacements counts this process's previews that took the
	// temporary slot of a lower-priority automatic block, which live
	// admission would replace; PreviewReplacementsLastHour counts those of
	// the last sixty one-minute buckets of process monotonic time.
	PreviewReplacements         uint64 `json:"preview_replacements"`
	PreviewReplacementsLastHour uint64 `json:"preview_replacements_last_hour"`
	// PreviewRotations and PreviewRotationsLastHour count the previews
	// that took the slot of an equal-priority automatic block, which live
	// admission would rotate out, in the same way.
	PreviewRotations         uint64 `json:"preview_rotations"`
	PreviewRotationsLastHour uint64 `json:"preview_rotations_last_hour"`
}

// AdmissionSet is the temporary block set as automatic admission divides
// it: the firewall's entries and the ledger's automatic blocks,
// pending and verified. Capacity is the limit, or 10000 for an unlimited
// set; Unclaimed counts the entries admission never evicts (operator
// blocks, blocks of unknown origin and two per timed subnet) and Imported
// the legacy automatic blocks; DrainSeconds is how long the last of them
// has left, or -1 when a kernel expiry is unavailable. The partitions'
// free slots bound the block work a schedule serves.
type AdmissionSet struct {
	Limit        int                      `json:"limit"`
	Unlimited    bool                     `json:"unlimited"`
	Capacity     int                      `json:"capacity"`
	Unclaimed    int                      `json:"unclaimed"`
	Imported     int                      `json:"imported"`
	DrainSeconds int64                    `json:"drain_seconds"`
	General      AdmissionDryRunPartition `json:"general"`
	Reserved     AdmissionDryRunPartition `json:"reserved"`
}

// AdmissionDryRun is an executing owner's dry-run forecast: a
// model of the hourly ceiling and the temporary block capacity, never a
// record of applied blocks. The session fields and counts are the current
// forecast session's; a session starts at startup, on entry into dry run
// or after its model failed, and leaving dry run clears the forecast but
// keeps the last session's identity. The loss and error counters count
// this process and survive mode changes. LastHour sums sixty one-minute
// buckets of process monotonic time, so a wall-clock change cannot age
// them and a restart starts them at zero.
type AdmissionDryRun struct {
	// Active is set while the owner forecasts instead of running blocks.
	Active      bool       `json:"active"`
	SessionID   *string    `json:"session_id"`
	Since       *time.Time `json:"since"`
	ResetReason *string    `json:"reset_reason"`
	// ModelledKinds and PredictionScope name what the model covers.
	ModelledKinds   []string                  `json:"modelled_kinds"`
	PredictionScope string                    `json:"prediction_scope"`
	Occupancy       *AdmissionDryRunOccupancy `json:"occupancy"`
	Ceiling         *AdmissionDryRunCeiling   `json:"ceiling"`
	// Picks and LastHour count the session's predictions by name, every
	// prediction present.
	Picks         map[string]uint64 `json:"picks"`
	LastHour      map[string]uint64 `json:"last_hour"`
	ExamplesLost  uint64            `json:"examples_lost"`
	SummariesLost uint64            `json:"summaries_lost"`
	RecordErrors  uint64            `json:"record_errors"`
	// ExamplesStale is set while a purge of earlier sessions' examples is
	// pending.
	ExamplesStale bool `json:"examples_stale"`
	// ForecastError is a fixed code for why forecasting last failed,
	// cleared by a good turn; LastErrorAt keeps its time until the next
	// session starts.
	ForecastError *string    `json:"forecast_error"`
	LastErrorAt   *time.Time `json:"last_error_at"`
	// ComparisonIncomplete is set after a restart or a lost example,
	// summary or comparison row.
	ComparisonIncomplete bool `json:"comparison_incomplete"`
}

// AdmissionDryRunOccupancy is the temporary block capacity as the last
// snapshot of the forecast saw it: the real timed blocks, the forecast
// blocks the real sets do not hold, the listed legacy automatic blocks the
// forecast replaced, and what is left against the limit. Unlimited marks
// a zero limit; Limited marks a model that holds as many forecast blocks
// as it can.
type AdmissionDryRunOccupancy struct {
	Actual     int  `json:"actual"`
	ShadowOnly int  `json:"shadow_only"`
	Replaced   int  `json:"replaced"`
	Predicted  int  `json:"predicted"`
	Limit      int  `json:"limit"`
	Unlimited  bool `json:"unlimited"`
	Limited    bool `json:"limited"`
	// Capacity is the finite capacity automatic admission is modelled
	// within: the limit, or 10000 for an unlimited set. Unclaimed counts
	// the real timed entries it never evicts (operator blocks, blocks of
	// unknown origin and two per timed subnet) and Imported the real
	// legacy automatic blocks; DrainSeconds is how long the last of them
	// has left, or -1 when a kernel expiry is unavailable.
	Capacity     int   `json:"capacity"`
	Unclaimed    int   `json:"unclaimed"`
	Imported     int   `json:"imported"`
	DrainSeconds int64 `json:"drain_seconds"`
	// General and Reserved divide the slots the unclaimed entries leave:
	// a fifth, rounded up, is reserved for direct or corroborated work.
	General  AdmissionDryRunPartition `json:"general"`
	Reserved AdmissionDryRunPartition `json:"reserved"`
	// Shares is how the forecast shares each partition among its scopes.
	Shares AdmissionDryRunShares `json:"shares"`
}

// AdmissionDryRunShares is how the forecast shares each partition among
// its scopes for equal-tier rotation.
type AdmissionDryRunShares struct {
	General  AdmissionDryRunShare `json:"general"`
	Reserved AdmissionDryRunShare `json:"reserved"`
}

// AdmissionDryRunShare is one partition's sharing: the scopes holding its
// forecast blocks or waiting at the last turn, and the fewest slots each
// is due, its size divided among them; the remainder goes one each to the
// scopes after the session's cursor. Both are zero without a scope.
type AdmissionDryRunShare struct {
	Scopes int `json:"scopes"`
	Share  int `json:"share"`
}

// AdmissionDryRunPartition is one modelled partition of the automatic
// slots: its size and the real and forecast automatic blocks in it.
type AdmissionDryRunPartition struct {
	Size int `json:"size"`
	Used int `json:"used"`
	Free int `json:"free"`
}

// AdmissionDryRunCeiling is the forecast's own copy of the hourly ceiling.
type AdmissionDryRunCeiling struct {
	Limit          uint32 `json:"limit"`
	GeneralUsed    uint32 `json:"general_used"`
	ReservedUsed   uint32 `json:"reserved_used"`
	GeneralBudget  uint32 `json:"general_budget"`
	ReservedBudget uint32 `json:"reserved_budget"`
}

// clone copies d, its collections and pointers included.
func (d *AdmissionDryRun) clone() *AdmissionDryRun {
	if d == nil {
		return nil
	}
	out := *d
	out.SessionID, out.Since, out.ResetReason = clonePtr(d.SessionID), clonePtr(d.Since), clonePtr(d.ResetReason)
	out.ForecastError, out.LastErrorAt = clonePtr(d.ForecastError), clonePtr(d.LastErrorAt)
	out.Occupancy, out.Ceiling = clonePtr(d.Occupancy), clonePtr(d.Ceiling)
	out.ModelledKinds = slices.Clone(d.ModelledKinds)
	out.Picks, out.LastHour = maps.Clone(d.Picks), maps.Clone(d.LastHour)
	return &out
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// AdmissionVerdict is the verdict callback stage. The gauges
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

// Clone returns a snapshot whose pointers and collections belong to the caller.
func (in *AdmissionStatus) Clone() *AdmissionStatus {
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
		if in.Owner.Set != nil {
			set := *in.Owner.Set
			owner.Set = &set
		}
		owner.DryRun = in.Owner.DryRun.clone()
		out.Owner = &owner
	}
	return &out
}
