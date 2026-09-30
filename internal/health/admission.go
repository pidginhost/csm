package health

import (
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
