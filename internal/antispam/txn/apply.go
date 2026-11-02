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
	// Takeovers re-check the files of the worker's own detection, so it
	// must match the stack preflight collected.
	if f.Stack != h.stack() {
		return failed(StepPreconditions, errors.New("the host's mail stack changed while CSM checked it"))
	}
	// The host's mail stack picks the files CSM renders; a request never
	// names it.
	s.Stack = f.Stack
	// The host can change while the resolved request waits for the worker.
	if len(s.DNSFeeds()) > 0 || s.Redirects() || s.HasFeed(antispam.FeedCSMIPMap) {
		if ok, why := antispam.FeedsSupported(f.RspamdVersion); !ok {
			return failed(StepPreconditions, errors.New(why+"; CSM's feeds and map redirects need rspamd 4 or later"))
		}
	}
	if s.HasFeed(antispam.FeedCSMIPMap) {
		if err := f.IPMap.UsableByRspamd(f.RspamdGID); err != nil {
			return failed(StepPreconditions, err)
		}
	}
	if s.HasFeed(antispam.FeedSpamhausDQS) {
		key, err := antispam.LoadDQSKey(f.DQSKey)
		if err != nil {
			return failed(StepPreconditions, err)
		}
		if exposed, why := f.RspamdLog.Exposed(f.Socket.RspamdUID, f.RspamdGID); exposed {
			return failed(StepPreconditions, errors.New(why+"; refusing to enable DQS lookups"))
		}
		s.DQSKey = key
	}
	if s.Learning {
		if f.LearningKeysErr != nil {
			return failed(StepPreconditions, f.LearningKeysErr)
		}
		s.LearningKeys = f.LearningKeys
	}
	installed := antispam.InstalledContent(f.Targets)
	if f.Stack == antispam.StackPostfix {
		return t.applyPostfix(s, f, installed)
	}
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
	managed, changes, err := changesFor(s, f)
	if err != nil {
		return failed(StepPreconditions, err)
	}
	generation := antispam.Generation(managed)
	rspamdChanges, eximChanges, roundcubeChanges := split(changes)
	matches, err := t.recorded(installed, generation)
	if err != nil {
		return failed(StepRecord, err)
	}
	opts, err := t.eximSettings(t.fwd)
	if err != nil {
		return failed(StepPreconditions, err)
	}
	t.rememberEximBlocks(f.Targets, opts)
	current, err := readFile(h.path(antispam.GeneratedEximConfPath))
	generated := err == nil && antispam.CheckGenerated(current.content, hooks, opts["acl_smtp_rcpt"], opts["acl_smtp_data"]) == nil
	reloadRspamd := len(rspamdChanges) > 0 || !matches
	rebuildExim := len(eximChanges) > 0 || !matches || !generated
	if !reloadRspamd && !rebuildExim && len(roundcubeChanges) == 0 {
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
		if step, err := t.rspamd(rspamdChanges, &s, f); err != nil {
			return t.fail(step, err)
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
	roundcube, rcErr := t.roundcube(roundcubeChanges)
	if rcErr != nil {
		return t.fail(StepRoundcube, rcErr)
	}
	if roundcube != "" && s.Roundcube {
		// Verification restored the snapshot, which may hold an older
		// owned include rather than absence. Record that exact state.
		if prior, present := installed[antispam.RoundcubeIncludePath]; present {
			managed[antispam.RoundcubeIncludePath] = prior
		} else {
			delete(managed, antispam.RoundcubeIncludePath)
		}
		generation = antispam.Generation(managed)
	}
	if err := t.writeRecord(generation); err != nil {
		return t.fail(StepComplete, err)
	}
	return antispam.Result{OK: true, Generation: generation, Roundcube: roundcube}
}

// applyPostfix installs or updates CSM's rspamd files on a Postfix host.
// rspamd's milter enforces there, so the transaction never touches Exim or
// postfix's configuration; probes after each reload include a connection to
// every milter postfix passes mail to rspamd through.
func (t *tx) applyPostfix(s antispam.Settings, f antispam.HostFacts, installed map[string]string) antispam.Result {
	milters, _, err := antispam.RspamdMilters(f)
	if err != nil {
		return failed(StepPreconditions, err)
	}
	reachable := func(ctx context.Context) error {
		for _, m := range milters {
			if t.h.milter(ctx, m) != nil {
				return errors.New("rspamd's milter does not accept connections")
			}
		}
		return nil
	}
	ping := t.rspamdProbe
	t.rspamdProbe = func(ctx context.Context) error {
		if pingErr := ping(ctx); pingErr != nil {
			return pingErr
		}
		return retry(ctx, t.h.rspamdWait, reachable)
	}
	t.rspamdRollbackProbe = t.rspamdProbe
	managed, changes, err := changesFor(s, f)
	if err != nil {
		return failed(StepPreconditions, err)
	}
	if s.HostActions() {
		// The host's own thresholds decide again, not rspamd's built-in ones
		// (spec 9.2).
		if err = t.restoreCopies(changes, func(p string) bool { return p == antispam.ActionsPath }); err != nil {
			return failed(StepPreconditions, err)
		}
	}
	generation := antispam.Generation(managed)
	matches, err := t.recorded(installed, generation)
	if err != nil {
		return failed(StepRecord, err)
	}
	if len(changes) == 0 && matches {
		return antispam.Result{OK: true, Generation: generation}
	}
	// As with Exim's listener, the probe after the reload compares like
	// with like.
	if err := retry(t.fwd, t.h.rspamdWait, reachable); err != nil {
		return failed(StepPreconditions, err)
	}
	if err := t.writeRecord(""); err != nil {
		return t.fail(StepRecord, err)
	}
	if step, err := t.rspamd(changes, &s, f); err != nil {
		return t.fail(step, err)
	}
	if err := t.consumeRestored(); err != nil {
		return t.fail(StepComplete, err)
	}
	if err := t.writeRecord(generation); err != nil {
		return t.fail(StepComplete, err)
	}
	return antispam.Result{OK: true, Generation: generation}
}

// changesFor renders s and plans the edits that bring f's targets to it.
func changesFor(s antispam.Settings, f antispam.HostFacts) (map[string]string, []change, error) {
	managed, err := antispam.ManagedContent(s)
	if err != nil {
		return nil, nil, err
	}
	changes, err := plan(f.Targets, managed)
	if err != nil {
		return nil, nil, err
	}
	if secrets := s.SecretTargets(); len(secrets) > 0 {
		if f.RspamdGID < 0 {
			return nil, nil, errors.New("rspamd's group is unknown, so secret files cannot be restricted to it")
		}
		changes = secureSecret(changes, f.Targets, f.RspamdGID, secrets)
	}
	return managed, changes, nil
}

// recorded reads the record and reports whether it completed installed or
// generation. Either proves the unchanged services were already reloaded,
// so repairing drift in just one target must not reload the others. An
// incomplete record proves neither.
func (t *tx) recorded(installed map[string]string, generation string) (bool, error) {
	record, valid, err := t.readRecord()
	if err != nil {
		return false, err
	}
	return valid && record.Complete() &&
		(*record.Generation == antispam.Generation(installed) || *record.Generation == generation), nil
}

// rspamd writes the rspamd edits, validates them against s, reloads rspamd
// and probes it, then verifies learning as loaded (spec 6.3 step 2).
func (t *tx) rspamd(changes []change, s *antispam.Settings, f antispam.HostFacts) (string, error) {
	for _, c := range changes {
		if err := t.write(c); err != nil {
			return StepRspamdFiles, err
		}
	}
	if err := t.checkRspamd(t.fwd, s); err != nil {
		step := StepRspamdCheck
		if errors.Is(err, errFeedsLoaded) {
			step = StepFeedsCheck
		} else if errors.Is(err, errLearningLoaded) {
			step = StepLearningCheck
		}
		return step, err
	}
	if err := t.reloadRspamd(t.fwd, t.rspamdProbe); err != nil {
		return StepRspamdReload, err
	}
	if s.Learning {
		if err := t.checkLearning(t.fwd, f, s.LearningKeys); err != nil {
			step := StepLearningCheck
			if errors.Is(err, errLearningProbe) {
				step = StepLearningProbe
			}
			return step, err
		}
	}
	return "", nil
}
