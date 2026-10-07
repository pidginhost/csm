package daemon

import (
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/admissionowner"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
)

var _ health.AdmissionProvider = (*Daemon)(nil)

// setResponseAdmission wires the response funnels; tests observe it.
var setResponseAdmission = checks.SetResponseAdmission

// startAdmission makes the daemon the owner of the admission ledger: the
// one handle on the state database's ledger. Every automatic response the
// legacy funnels select is also handed to it, which previews and never
// executes it (R1).
func (d *Daemon) startAdmission() {
	d.startAdmissionWith(d.admissionOptions(store.Global()))
}

func (d *Daemon) admissionOptions(db *store.DB) admissionowner.Options {
	// The firewall reads its family settings at start, as this does.
	ipv6 := d.cfg.Firewall != nil && d.cfg.Firewall.IPv6
	return admissionowner.Options{
		DB: db, StatePath: d.cfg.StatePath,
		Ceiling:     func() (uint32, string) { return d.currentCfg().AdmissionCeiling() },
		Clock:       admissionowner.ReadClock,
		Inventory:   admissionowner.Inventory,
		LegacySpend: checks.LegacyBlockSpend,
		WriteAudit:  actionlog.WriteDurableBatch,
		Deliver:     d.deliverAdmissionNotices,
		Expiry:      func(c admission.Candidate) time.Duration { return previewExpiry(d.currentCfg(), c) },
		Caps:        func() admission.Caps { return admission.Caps{IPv6: ipv6} },
	}
}

// previewExpiry is how long the response c asks for would last under cfg:
// each entry keeps the lifetime its legacy path applies.
func previewExpiry(cfg *config.Config, c admission.Candidate) time.Duration {
	switch {
	case c.Entry == admission.EntryCentral && c.Key.Kind == admission.KindChallenge:
		return centralChallengeTTL
	case c.Entry == admission.EntryCentral:
		return centralBlockTTL
	case c.Key.Kind == admission.KindChallenge:
		return checks.ChallengeDuration
	case c.Entry == admission.EntryASNCrawl:
		return parseBlockExpiry(cfg.AutoResponse.HTTPASNCrawlTempban)
	}
	return parseBlockExpiry(cfg.AutoResponse.BlockExpiry)
}

func (d *Daemon) startAdmissionWith(opts admissionowner.Options) {
	if d.admission != nil {
		return
	}
	d.admission = admissionowner.Start(opts)
	setResponseAdmission(d.admission)
	d.registerQueueSource("admission", d.admission)
	if st := d.admission.Status(); st != nil && st.Owner != nil && st.Owner.Error != "" {
		csmlog.Warn("admission ledger unavailable; retrying", "err", st.Owner.Error)
	}
}

// deliverAdmissionNotices is the independent health path: history and a
// direct dispatch, as protection_queue_degraded is sent. The finding
// channel, suppressions and automatic response are never involved, since
// the failure being reported may be in them. A preview is recorded only.
func (d *Daemon) deliverAdmissionNotices(findings []alert.Finding, preview bool) error {
	if preview {
		return d.store.AppendHistoryDurable(findings)
	}
	d.store.AppendHistory(findings)
	return alert.DispatchNotices(d.currentCfg(), findings)
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
		setResponseAdmission(nil)
		d.admission.Stop()
	}
}
