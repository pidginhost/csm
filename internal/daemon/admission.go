package daemon

import (
	"context"
	"errors"
	"sync/atomic"
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
	"github.com/pidginhost/csm/internal/verdict"
)

var _ health.AdmissionProvider = (*Daemon)(nil)

// ownerKeepsDryRunExamples is set once an admission owner that runs blocks
// starts. It then writes, prunes and purges the dry_run_blocks bucket alone
// (spec 3.6), and the legacy prune and purge leave the bucket to it.
var ownerKeepsDryRunExamples atomic.Bool

// pruneLegacyDryRunBlocks ages out dry_run_blocks records older than a
// week, unless an admission owner keeps the bucket.
func pruneLegacyDryRunBlocks() {
	if sdb := store.Global(); sdb != nil && !ownerKeepsDryRunExamples.Load() {
		sdb.PurgeDryRunBlocksOlderThan(time.Now().Add(-7 * 24 * time.Hour))
	}
}

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
		Applied:     d.consumeAppliedBlocks,
		Deliver:     d.deliverAdmissionNotices,
		Expiry:      func(c admission.Candidate) time.Duration { return previewExpiry(d.currentCfg(), c) },
		Caps:        func() admission.Caps { return admission.Caps{IPv6: ipv6} },
		Policy:      d.executionPolicy,
	}
}

// executionPolicy is the execution policy of the live config, read with its
// response epoch from one publication (D11).
func (d *Daemon) executionPolicy() admissionowner.ExecutionPolicy {
	cfg, epoch := config.ActiveEpoch()
	if cfg == nil {
		return admissionowner.ExecutionPolicy{}
	}
	limit, source := cfg.AdmissionCeiling()
	// The epoch-bound client preserves the configured signature policy.
	client := newVerdictClient(cfg)
	return admissionowner.ExecutionPolicy{
		Epoch: epoch, Observe: cfg.ObserveMode(), DryRun: cfg.AutoResponseDryRunEnabled(),
		VerdictEnabled: cfg.AutoResponse.VerdictCallback.Enabled,
		VerdictTimeout: time.Duration(cfg.AutoResponse.VerdictCallback.TimeoutSec) * time.Second,
		CeilingLimit:   limit, CeilingSource: source,
		Expiry: func(c admission.Candidate) time.Duration { return previewExpiry(cfg, c) },
		AskVerdict: func(ctx context.Context, ip, reason string) (verdict.Response, error) {
			return client.Ask(ctx, verdict.Request{IP: ip, Reason: reason, Severity: "auto", Source: "auto_response"})
		},
		Allows: func(c admission.Candidate) bool {
			return checks.AutomaticResponseAllowed(cfg, c.Key.Kind, c.Entry, c.Check)
		},
	}
}

// newVerdictClient is the verdict callback client cfg configures.
func newVerdictClient(cfg *config.Config) *verdict.Client {
	vc := cfg.AutoResponse.VerdictCallback
	return verdict.New(verdict.Config{
		URL:                      vc.URL,
		HMACSecret:               vc.HMACSecret,
		HMACSecretEnv:            vc.HMACSecretEnv,
		RequireResponseSignature: vc.RequireResponseSignature,
		AllowUnsigned:            vc.AllowUnsigned,
		Timeout:                  time.Duration(vc.TimeoutSec) * time.Second,
	})
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
	ownerKeepsDryRunExamples.Store(d.admission.OwnsDryRunExamples())
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
	err := d.admission.Reload()
	switch {
	case errors.Is(err, admissionowner.ErrPolicy):
		d.emitReloadFinding(alert.Critical, "config_reload_error",
			"config reload: automatic execution is held: "+err.Error())
	case err != nil:
		csmlog.Warn("admission ceiling not reloaded", "err", err)
	}
}

func (d *Daemon) stopAdmission() {
	if d.admission != nil {
		setResponseAdmission(nil)
		d.admission.Stop()
	}
}
