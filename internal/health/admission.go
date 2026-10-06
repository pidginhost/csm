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
	// DamageError is the latest damaged ledger record a drain isolated:
	// arrivals naming it were discarded and admission stayed open. It is
	// kept until the owner restarts.
	DamageError string `json:"damage_error,omitempty"`
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
		out.Owner = &owner
	}
	return &out
}
