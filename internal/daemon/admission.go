package daemon

import (
	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admissionowner"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/health"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
)

var _ health.AdmissionProvider = (*Daemon)(nil)

// startAdmission makes the daemon the owner of the admission ledger: the
// one handle on the state database's ledger. Nothing submits to it yet.
func (d *Daemon) startAdmission() {
	d.startAdmissionWith(d.admissionOptions(store.Global()))
}

func (d *Daemon) admissionOptions(db *store.DB) admissionowner.Options {
	return admissionowner.Options{
		DB: db, StatePath: d.cfg.StatePath,
		Ceiling:     func() (uint32, string) { return d.currentCfg().AdmissionCeiling() },
		Clock:       admissionowner.ReadClock,
		Inventory:   admissionowner.Inventory,
		LegacySpend: checks.LegacyBlockSpend,
		WriteAudit:  actionlog.WriteDurableBatch,
		Deliver:     d.deliverAdmissionNotices,
	}
}

func (d *Daemon) startAdmissionWith(opts admissionowner.Options) {
	if d.admission != nil {
		return
	}
	d.admission = admissionowner.Start(opts)
	d.registerQueueSource("admission", d.admission)
	if st := d.admission.Status(); st != nil && st.Owner != nil && st.Owner.Error != "" {
		csmlog.Warn("admission ledger unavailable; retrying", "err", st.Owner.Error)
	}
}

// deliverAdmissionNotices is the independent health path: history and a
// direct dispatch, as protection_queue_degraded is sent. The finding
// channel, suppressions and automatic response are never involved, since
// the failure being reported may be in them.
func (d *Daemon) deliverAdmissionNotices(findings []alert.Finding) error {
	d.store.AppendHistory(findings)
	return alert.Dispatch(d.currentCfg(), findings)
}

// AdmissionStatus is the owner's last reading of the ledger, refreshed on
// its timer rather than per request.
func (d *Daemon) AdmissionStatus() *health.AdmissionStatus {
	if d.admission == nil {
		return nil
	}
	return d.admission.Status()
}

func (d *Daemon) reloadAdmission() {
	if d.admission == nil {
		return
	}
	if err := d.admission.Reload(); err != nil {
		csmlog.Warn("admission ceiling not reloaded", "err", err)
	}
}

func (d *Daemon) stopAdmission() {
	if d.admission != nil {
		d.admission.Stop()
	}
}
