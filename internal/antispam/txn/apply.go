package txn

import (
	"context"
	"errors"
	"strings"

	"github.com/pidginhost/csm/internal/antispam"
)

var errEximInactive = errors.New("exim is not running; CSM changes its configuration only while it can confirm the reload")

// Apply installs or updates CSM's integration for s (spec section 6.3). An
// equal installation changes nothing and reloads nothing (spec 6.5).
func (h *Host) Apply(s antispam.Settings) antispam.Result {
	t := h.begin()
	defer t.cancel()
	t.rspamdProbe = func(ctx context.Context) error {
		return retry(ctx, h.rspamdWait, func(ctx context.Context) error { return h.ping(ctx, s.Socket) })
	}
	f, problems := h.preflight(t.fwd, s)
	if err := t.fwd.Err(); err != nil {
		return failed(StepPreconditions, err)
	}
	if err := blocking(problems); err != nil {
		return failed(StepPreconditions, err)
	}
	installed := antispam.InstalledContent(f.Targets)
	rollbackSocket := s.Socket
	// An update can select a new socket. Rollback must probe the scanner
	// referenced by the hooks it restores, rather than the failed update.
	address := antispam.ParseEximOptions(installed[antispam.LocalEximConfPath])["spamd_address"]
	if fields := strings.Fields(address); len(fields) > 0 && antispam.ValidateSocket(fields[0]) == nil {
		rollbackSocket = fields[0]
	}
	t.rspamdRollbackProbe = func(ctx context.Context) error {
		return retry(ctx, h.rspamdWait, func(ctx context.Context) error { return h.ping(ctx, rollbackSocket) })
	}
	hooks, err := antispam.RenderExim(s)
	if err != nil {
		return failed(StepPreconditions, err)
	}
	managed, err := antispam.ManagedContent(s)
	if err != nil {
		return failed(StepPreconditions, err)
	}
	generation := antispam.Generation(managed)
	changes, err := plan(f.Targets, managed)
	if err != nil {
		return failed(StepPreconditions, err)
	}
	rspamdChanges, eximChanges := split(changes)
	record, valid, err := t.readRecord()
	if err != nil {
		return failed(StepRecord, err)
	}
	// A complete record that matches the installed text proves the last
	// transaction reloaded both services with it.
	matches := valid && record.Complete() && *record.Generation == antispam.Generation(installed)
	opts, err := t.eximSettings(t.fwd)
	if err != nil {
		return failed(StepPreconditions, err)
	}
	t.rememberEximBlocks(f.Targets, opts)
	current, err := readFile(h.path(antispam.GeneratedEximConfPath))
	generated := err == nil && antispam.CheckGenerated(current.content, hooks, opts["acl_smtp_rcpt"], opts["acl_smtp_data"]) == nil
	reloadRspamd := len(rspamdChanges) > 0 || !matches
	rebuildExim := len(eximChanges) > 0 || !matches || !generated
	if !reloadRspamd && !rebuildExim {
		return antispam.Result{OK: true, Generation: generation}
	}
	if err := t.listenerProbe(opts); err != nil {
		return failed(StepPreconditions, err)
	}
	if !t.eximActive {
		return failed(StepPreconditions, errEximInactive)
	}

	if err := t.writeRecord(""); err != nil {
		return t.fail(StepRecord, err)
	}
	if reloadRspamd {
		for _, c := range rspamdChanges {
			if err := t.write(c); err != nil {
				return t.fail(StepRspamdFiles, err)
			}
		}
		if err := t.checkRspamd(t.fwd, &s); err != nil {
			return t.fail(StepRspamdCheck, err)
		}
		if err := t.reloadRspamd(t.fwd, t.rspamdProbe); err != nil {
			return t.fail(StepRspamdReload, err)
		}
	}
	if rebuildExim {
		verify := func(conf, rcptACL, dataACL string) error {
			return antispam.CheckGenerated(conf, hooks, rcptACL, dataACL)
		}
		if step, err := t.exim(eximChanges, true, verify); err != nil {
			return t.fail(step, err)
		}
	}
	if err := t.writeRecord(generation); err != nil {
		return t.fail(StepComplete, err)
	}
	return antispam.Result{OK: true, Generation: generation}
}
