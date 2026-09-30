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
	return &out
}
