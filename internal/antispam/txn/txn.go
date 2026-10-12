package txn

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/hostfacts"
	"github.com/pidginhost/csm/internal/platform"
)

// Time limits from spec section 6.3.
const (
	// forwardBudget is when rollback must start at the latest.
	forwardBudget = 150 * time.Second
	// totalBudget ends rollback before the worker's 5-minute unit limit,
	// leaving time to report.
	totalBudget  = 290 * time.Second
	buildLimit   = 120 * time.Second
	commandLimit = 10 * time.Second
	rspamdWait   = 20 * time.Second
	eximWait     = 3 * time.Second
)

// BuildEximConf is cPanel's Exim configuration builder.
const BuildEximConf = "/scripts/buildeximconf"

// Steps a failed result names.
const (
	StepPreconditions = "preconditions"
	StepRecord        = "record"
	StepRspamdFiles   = "rspamd_files"
	StepRspamdCheck   = "rspamd_check"
	StepRspamdReload  = "rspamd_reload"
	StepEximFiles     = "exim_files"
	StepEximBuild     = "exim_build"
	StepEximReload    = "exim_reload"
	StepEximProbe     = "exim_probe"
	StepComplete      = "complete"
)

// Host runs transactions against the host. Every function field is a side
// effect; tests replace them and set root to a temporary directory.
type Host struct {
	// root prefixes every host path; it is "" on a live host.
	root      string
	run       func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult
	preflight func(ctx context.Context, s antispam.Settings) (antispam.HostFacts, []antispam.Problem)
	targets   func() []antispam.TargetFacts
	ping      func(ctx context.Context, socket string) error
	greet     func(ctx context.Context, addr string) error
	now       func() time.Time
	// rspamdWait and eximWait bound the service probes after a reload.
	rspamdWait, eximWait time.Duration
}

// New returns a Host for the live cPanel paths.
func New() *Host {
	return &Host{
		run: hostfacts.RunCommand,
		preflight: func(ctx context.Context, s antispam.Settings) (antispam.HostFacts, []antispam.Problem) {
			f := hostfacts.Collect(ctx, s.Socket)
			return f, antispam.CheckHost(f)
		},
		targets: func() []antispam.TargetFacts { return hostfacts.Targets(antispam.MutationTargets()) },
		ping: func(ctx context.Context, socket string) error {
			_, err := hostfacts.Ping(ctx, socket)
			return err
		},
		greet:      smtpGreeting,
		now:        time.Now,
		rspamdWait: rspamdWait,
		eximWait:   eximWait,
	}
}

func (h *Host) path(p string) string { return h.root + p }

// change is one planned file edit.
type change struct {
	target antispam.TargetFacts
	next   fileState
}

// written is one file edit made, for rollback.
type written struct {
	path         string
	before, next fileState
}

// tx is one transaction's progress, which rollback reads.
type tx struct {
	h     *Host
	start time.Time
	// fwd ends at forwardBudget; every forward step runs under it.
	fwd    context.Context
	cancel context.CancelFunc

	record        fileState
	recordWritten bool
	writes        []written
	eximTouched   bool
	eximReloaded  bool
	eximActive    bool
	// greeting is the listener that answered before any change; "" when
	// Exim was not running.
	greeting       string
	rspamdReloaded bool
	// rspamdProbe confirms rspamd after a reload.
	rspamdProbe func(context.Context) error
}

func (h *Host) begin() *tx {
	t := &tx{h: h, start: h.now()}
	t.fwd, t.cancel = context.WithDeadline(context.Background(), t.start.Add(forwardBudget))
	return t
}

func (t *tx) cmd(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
	return t.h.run(ctx, limit, name, args...)
}

// cmdErr describes a failed command by name and exit status only: command
// output can carry configuration text (spec section 7).
func cmdErr(what string, r antispam.CommandResult) error {
	return fmt.Errorf("%s failed: %w", what, r.Err)
}

func failed(step string, err error) antispam.Result {
	return antispam.Result{FailedStep: step, Rollback: antispam.RollbackNone, Error: err.Error()}
}

// blocking returns the Definite and Temporary problem codes as one error.
// Warnings never block a transaction.
func blocking(problems []antispam.Problem) error {
	var codes []string
	for _, p := range problems {
		if p.Severity != antispam.Warning && !slices.Contains(codes, p.Code) {
			codes = append(codes, p.Code)
		}
	}
	if len(codes) == 0 {
		return nil
	}
	return fmt.Errorf("preconditions not met: %s", strings.Join(codes, ", "))
}

// plan lists the edits that bring targets to managed, keyed by target
// path. A nil managed map plans removal: CSM blocks are stripped, managed
// local.d files deleted and foreign ones left in place.
func plan(targets []antispam.TargetFacts, managed map[string]string) ([]change, error) {
	var out []change
	for _, t := range targets {
		before := fileState{exists: !t.Missing, content: t.Content}
		switch {
		case t.Kind == antispam.TargetRspamd && managed != nil:
			if want := managed[t.Path]; !sameContent(before, fileState{exists: true, content: want}) {
				out = append(out, change{t, fileState{exists: true, content: want}})
			}
		case t.Kind == antispam.TargetRspamd:
			if !t.Missing && antispam.IsManaged(t.Content) {
				out = append(out, change{t, fileState{}})
			}
		case t.Missing && managed == nil:
		default:
			base := t.Content
			if t.Missing && t.Kind == antispam.TargetEximLocal {
				base = platform.EximLocalSkeleton
			}
			next, err := antispam.SetBlock(t.Kind, base, managed[t.Path])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", t.Path, err)
			}
			if !sameContent(before, fileState{exists: true, content: next}) {
				out = append(out, change{t, fileState{exists: true, content: next}})
			}
		}
	}
	return out, nil
}

// split separates rspamd edits from Exim edits.
func split(changes []change) (rspamd, exim []change) {
	for _, c := range changes {
		if c.target.Kind == antispam.TargetRspamd {
			rspamd = append(rspamd, c)
		} else {
			exim = append(exim, c)
		}
	}
	return rspamd, exim
}

// write applies one planned edit unless another writer changed the file
// since the snapshot.
func (t *tx) write(c change) error {
	p := t.h.path(c.target.Path)
	before := fileState{exists: !c.target.Missing, content: c.target.Content}
	if err := replaceFile(p, before, c.next); err != nil {
		return err
	}
	t.writes = append(t.writes, written{path: p, before: before, next: c.next})
	return nil
}

// readRecord reads the completion record into t.record.
func (t *tx) readRecord() (antispam.Record, bool, error) {
	st, err := readFile(t.h.path(antispam.RecordPath))
	if err != nil {
		return antispam.Record{}, false, fmt.Errorf("cannot read %s: %w", antispam.RecordPath, err)
	}
	t.record = st
	if !st.exists {
		return antispam.Record{}, false, nil
	}
	r, err := antispam.DecodeRecord([]byte(st.content))
	return r, err == nil, nil
}

// writeRecord persists a record; an empty generation marks work in progress.
func (t *tx) writeRecord(generation string) error {
	p := t.h.path(antispam.RecordPath)
	if err := privateDir(filepath.Dir(p)); err != nil {
		return err
	}
	t.recordWritten = true
	return writeAtomic(p, string(antispam.EncodeRecord(generation)), 0o600, -1, -1)
}

// listenerProbe reads where Exim listens and checks that one listener greets
// before anything changes, so the probe after reload compares like with like.
func (t *tx) listenerProbe(opts map[string]string) error {
	t.eximActive = t.cmd(t.fwd, commandLimit, "systemctl", "is-active", antispam.EximUnit).Err == nil
	if !t.eximActive {
		return nil
	}
	for _, addr := range listeners(opts) {
		ctx, cancel := context.WithTimeout(t.fwd, t.h.eximWait)
		err := t.h.greet(ctx, addr)
		cancel()
		if err == nil {
			t.greeting = addr
			return nil
		}
	}
	return errors.New("no configured Exim listener answered with an SMTP greeting")
}

// listenerSettings are the `exim -bP` options that say where the daemon
// accepts SMTP, read with the ACL names before any change.
var listenerSettings = []string{"daemon_smtp_ports", "local_interfaces", "tls_on_connect_ports"}

// eximSettings reads the ACL names and listener options from the
// configuration Exim would load now.
func (t *tx) eximSettings(ctx context.Context) (map[string]string, error) {
	r := t.cmd(ctx, commandLimit, "exim", append([]string{"-bP", "acl_smtp_rcpt", "acl_smtp_data"}, listenerSettings...)...)
	if r.Err != nil {
		return nil, cmdErr("exim -bP", r)
	}
	return antispam.ParseEximOptions(r.Stdout), nil
}

// exim writes the Exim edits, rebuilds and validates the configuration, then
// reloads Exim and probes it (spec section 6.3 steps 3 to 5).
func (t *tx) exim(changes []change, verify func(conf, rcptACL, dataACL string) error) (string, error) {
	for _, c := range changes {
		if err := t.write(c); err != nil {
			return StepEximFiles, err
		}
		t.eximTouched = true
	}
	t.eximTouched = true
	if r := t.cmd(t.fwd, buildLimit, BuildEximConf); r.Err != nil {
		return StepEximBuild, cmdErr("buildeximconf", r)
	}
	if err := t.validateExim(t.fwd); err != nil {
		return StepEximBuild, err
	}
	opts, err := t.eximSettings(t.fwd)
	if err != nil {
		return StepEximBuild, err
	}
	conf, err := readFile(t.h.path(antispam.GeneratedEximConfPath))
	if err != nil {
		return StepEximBuild, err
	}
	if err := verify(conf.content, opts["acl_smtp_rcpt"], opts["acl_smtp_data"]); err != nil {
		return StepEximBuild, err
	}
	if !t.eximActive {
		return "", nil
	}
	t.eximReloaded = true
	if r := t.cmd(t.fwd, commandLimit, "systemctl", "reload", antispam.EximUnit); r.Err != nil {
		return StepEximReload, cmdErr("systemctl reload exim", r)
	}
	if err := t.probeExim(t.fwd); err != nil {
		return StepEximProbe, err
	}
	return "", nil
}

// validateExim checks the generated configuration and the named lists the
// hooks use (spec section 6.2 item 7).
func (t *tx) validateExim(ctx context.Context) error {
	if r := t.cmd(ctx, commandLimit, "exim", "-bV"); r.Err != nil {
		return cmdErr("exim -bV", r)
	}
	for _, probe := range antispam.NamedListProbes() {
		r := t.cmd(ctx, commandLimit, "exim", "-C", t.h.path(antispam.GeneratedEximConfPath), "-be", probe)
		if r.Err != nil || antispam.ParseBeResult(r.Stdout, r.Stderr) != nil {
			return fmt.Errorf("exim -be %s did not print y or n", probe)
		}
	}
	return nil
}

// probeExim confirms Exim is active and greets on the listener that
// answered before the change.
func (t *tx) probeExim(ctx context.Context) error {
	if r := t.cmd(ctx, commandLimit, "systemctl", "is-active", antispam.EximUnit); r.Err != nil {
		return errors.New("exim is not active after reload")
	}
	if t.greeting == "" {
		return nil
	}
	if err := retry(ctx, t.h.eximWait, func(ctx context.Context) error { return t.h.greet(ctx, t.greeting) }); err != nil {
		return fmt.Errorf("exim did not greet on %s after reload", t.greeting)
	}
	return nil
}

// checkRspamd validates staged rspamd files and, for an apply, compares the
// loaded thresholds and modules with CSM's settings (spec 6.2 item 10).
func (t *tx) checkRspamd(ctx context.Context, s *antispam.Settings) error {
	if r := t.cmd(ctx, commandLimit, "rspamadm", "configtest"); r.Err != nil {
		return cmdErr("rspamadm configtest", r)
	}
	if s == nil {
		return nil
	}
	mods := t.cmd(ctx, commandLimit, "rspamadm", "configdump", "-m")
	if mods.Err != nil {
		return cmdErr("rspamadm configdump -m", mods)
	}
	enabled, err := antispam.EnabledModules(mods.Stdout)
	if err != nil {
		return err
	}
	acts := t.cmd(ctx, commandLimit, "rspamadm", "configdump", "-j", "actions")
	if acts.Err != nil {
		return cmdErr("rspamadm configdump -j actions", acts)
	}
	actions, err := antispam.ParseActions([]byte(acts.Stdout))
	if err != nil {
		// Object-form actions hide their thresholds: a conflict, not drift.
		return fmt.Errorf("rspamd actions cannot be compared with CSM's: %w", err)
	}
	if conflicts := antispam.CheckRspamd(enabled, actions, *s); len(conflicts) > 0 {
		return errors.New(strings.Join(conflicts, "; "))
	}
	return nil
}

// reloadRspamd reloads rspamd and waits for its probe (spec 6.3 step 2).
func (t *tx) reloadRspamd(ctx context.Context) error {
	t.rspamdReloaded = true
	if r := t.cmd(ctx, commandLimit, "systemctl", "reload", antispam.RspamdUnit); r.Err != nil {
		return cmdErr("systemctl reload rspamd", r)
	}
	return t.rspamdProbe(ctx)
}

// fail rolls back and reports step as the failed step.
func (t *tx) fail(step string, err error) antispam.Result {
	state, rbErr := t.rollback()
	msg := err.Error()
	if rbErr != nil {
		msg += "; rollback: " + rbErr.Error()
	}
	return antispam.Result{FailedStep: step, Rollback: state, Error: msg}
}

// rollback restores every change in reverse and reloads each service whose
// reload was attempted. "verified" needs every restore, rebuild, reload and
// probe to succeed; otherwise the incomplete record stays for reconcile.
func (t *tx) rollback() (string, error) {
	if !t.recordWritten && len(t.writes) == 0 && !t.eximTouched && !t.rspamdReloaded {
		return antispam.RollbackNone, nil
	}
	ctx, cancel := context.WithDeadline(context.Background(), t.start.Add(totalBudget))
	defer cancel()
	var errs []error
	for i := len(t.writes) - 1; i >= 0; i-- {
		w := t.writes[i]
		if err := replaceFile(w.path, w.next, w.before); err != nil {
			errs = append(errs, fmt.Errorf("restoring %s: %w", strings.TrimPrefix(w.path, t.h.root), err))
		}
	}
	if t.eximTouched {
		if r := t.cmd(ctx, buildLimit, BuildEximConf); r.Err != nil {
			errs = append(errs, cmdErr("buildeximconf", r))
		} else if r := t.cmd(ctx, commandLimit, "exim", "-bV"); r.Err != nil {
			errs = append(errs, cmdErr("exim -bV", r))
		}
	}
	if t.eximReloaded {
		t.cmd(ctx, commandLimit, "systemctl", "reload", antispam.EximUnit)
		if r := t.cmd(ctx, commandLimit, "systemctl", "is-active", antispam.EximUnit); r.Err != nil {
			t.cmd(ctx, commandLimit, "systemctl", "start", antispam.EximUnit)
		}
		if err := t.probeExim(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if t.rspamdReloaded {
		if err := t.checkRspamd(ctx, nil); err != nil {
			errs = append(errs, err)
		} else if err := t.reloadRspamd(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return antispam.RollbackFailed, errors.Join(errs...)
	}
	if t.recordWritten {
		if err := t.restoreRecord(); err != nil {
			return antispam.RollbackFailed, err
		}
	}
	return antispam.RollbackVerified, nil
}

func (t *tx) restoreRecord() error {
	p := t.h.path(antispam.RecordPath)
	if !t.record.exists {
		return deleteFile(p)
	}
	return writeAtomic(p, t.record.content, 0o600, -1, -1)
}
