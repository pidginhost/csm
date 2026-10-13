package txn

import (
	"context"
	"errors"
	"strings"

	"github.com/pidginhost/csm/internal/antispam"
)

// Remove takes out CSM's integration (spec section 6.4): Exim first, then
// CSM's rspamd files, then the record. Foreign local.d files stay. A stopped
// service is not reloaded, and the scan socket is not needed.
func (h *Host) Remove() antispam.Result {
	t := h.begin()
	defer t.cancel()
	t.rspamdProbe = func(ctx context.Context) error {
		if r := t.cmd(ctx, commandLimit, "systemctl", "is-active", antispam.RspamdUnit); r.Err != nil {
			return errors.New("rspamd is not active after reload")
		}
		return nil
	}
	// A remove request carries no socket, so rollback checks rspamd the same way.
	t.rspamdRollbackProbe = t.rspamdProbe
	targets := h.targets()
	if err := blocking(antispam.CheckRemoval(targets)); err != nil {
		return failed(StepPreconditions, err)
	}
	changes, err := plan(targets, nil)
	if err != nil {
		return failed(StepPreconditions, err)
	}
	rspamdChanges, eximChanges := split(changes)
	if _, _, err = t.readRecord(); err != nil {
		return failed(StepRecord, err)
	}
	conf, err := readFile(h.path(antispam.GeneratedEximConfPath))
	generated := err == nil && conf.exists && !strings.Contains(conf.content, antispam.MarkerBegin) && !strings.Contains(conf.content, antispam.MarkerEnd)
	// A record, complete or not, means an earlier transaction may have
	// changed files without a confirmed reload.
	rebuildExim := len(eximChanges) > 0 || t.record.exists || !generated
	reloadRspamd := len(rspamdChanges) > 0 || t.record.exists
	if !rebuildExim && !reloadRspamd {
		return antispam.Result{OK: true}
	}
	// A broken generated configuration must not prevent removing its hooks:
	// without listener settings the probe after reload checks activity only.
	opts, _ := t.eximSettings(t.fwd)
	t.rememberEximBlocks(targets, opts)
	if t.eximActive, err = t.serviceActive(t.fwd, antispam.EximUnit); err != nil {
		return failed(StepPreconditions, err)
	}
	if t.eximActive {
		_ = t.listenerGreeting(opts)
	}
	if t.rspamdActive, err = t.serviceActive(t.fwd, antispam.RspamdUnit); err != nil {
		return failed(StepPreconditions, err)
	}

	if err := t.writeRecord(""); err != nil {
		return t.fail(StepRecord, err)
	}
	if rebuildExim {
		verify := func(conf, _, _ string) error {
			if strings.Contains(conf, antispam.MarkerBegin) || strings.Contains(conf, antispam.MarkerEnd) {
				return errors.New("the generated configuration still holds CSM blocks")
			}
			return nil
		}
		if step, err := t.exim(eximChanges, false, verify); err != nil {
			return t.fail(step, err)
		}
	}
	if reloadRspamd {
		for _, c := range rspamdChanges {
			if err := t.write(c); err != nil {
				return t.fail(StepRspamdFiles, err)
			}
		}
		if t.rspamdActive {
			if err := t.checkRspamd(t.fwd, nil); err != nil {
				return t.fail(StepRspamdCheck, err)
			}
			if err := t.reloadRspamd(t.fwd, t.rspamdProbe); err != nil {
				return t.fail(StepRspamdReload, err)
			}
		}
	}
	if err := t.removeRecord(); err != nil {
		return t.fail(StepComplete, err)
	}
	return antispam.Result{OK: true}
}
