package reconcile

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/eximlock"
)

// BusyRetry is how soon a pass runs again while another CSM transaction
// holds the Exim lock (spec section 6.5).
const BusyRetry = 20 * time.Second

// codeObserve reports an integration that observe mode leaves in place.
const codeObserve = "observe_mode"

// Desired is the antispam configuration a pass works towards.
type Desired struct {
	Enabled  bool
	Observe  bool
	Settings antispam.Settings
}

// DesiredFromConfig reads the antispam settings and mode from cfg.
func DesiredFromConfig(cfg *config.Config) Desired {
	as := cfg.EmailProtection.Antispam
	d := Desired{
		Enabled: as.Enabled,
		Observe: cfg.ObserveMode(),
		Settings: antispam.Settings{
			DryRun: as.DryRun, Socket: as.RspamdSocket,
			RejectScore: as.RejectScore, TagScore: as.TagScore,
			Feeds:      slices.Sorted(slices.Values(as.Feeds.Enabled)),
			DQSKeyFile: as.Feeds.SpamhausDQSKeyFile,
		},
	}
	if as.Learning.Enabled {
		d.Settings.Learning, d.Settings.LearningDir = true, antispam.DefaultLearningDir
	}
	return d
}

// Reconciler runs one pass at a time against the host its functions read
// and change.
type Reconciler struct {
	// Invalidate stops pending workers before the host is read, including
	// in observe mode. It changes only CSM's request record, not mail config.
	Invalidate func(context.Context) error
	// Collect reads every precondition fact for the scan socket.
	Collect func(ctx context.Context, socket string) antispam.HostFacts
	// Installed reads only what shows CSM's integration on the host.
	Installed func() antispam.HostFacts
	// Run sends one request to the root worker.
	Run func(ctx context.Context, req antispam.Request) (antispam.Result, error)
	// Now stamps findings.
	Now func() time.Time
	// ReadKey reads the Spamhaus DQS key file; nil disables spamhaus_dqs.
	ReadKey func(path string) antispam.KeyFacts
	// Feeds remembers feed holds and probe counts between passes.
	Feeds *FeedState
	// Probe asks server one DNS question; nil disables the feed probe.
	Probe func(ctx context.Context, server netip.AddrPort, name string) antispam.ProbeAnswer
	// IPMap writes and removes the CSM IP map; unset hooks do nothing.
	IPMap IPMapHooks
	// Learning remembers a learning configuration held after a failed check.
	Learning *LearningState
	// EnsureKeys creates the learning keys once and LoadKeys reads them;
	// CollectLearning adds the learning prerequisites to the core facts.
	// All run only while learning is requested.
	EnsureKeys      func(ctx context.Context, dir string) (bool, error)
	LoadKeys        func(dir string) (antispam.LearningKeys, error)
	CollectLearning func(ctx context.Context, f *antispam.HostFacts)
	// Learner returns the running learning engine's problems; nil when no
	// engine runs.
	Learner func() []antispam.Problem
	// resolveLearning replaces antispam.ResolveLearning in tests.
	resolveLearning func(s antispam.Settings, f antispam.HostFacts) (antispam.Settings, antispam.LearningGate, []antispam.Problem)
	// assess replaces antispam.Assess in tests.
	assess func(enabled bool, s antispam.Settings, f antispam.HostFacts) antispam.Assessment
}

// Outcome is what one pass found and did.
type Outcome struct {
	// Findings are the antispam conditions true after this pass.
	Findings []alert.Finding
	// Retry, when set, asks for another pass this soon.
	Retry time.Duration
	// Err is the cause of a pass that did not complete, for the daemon log.
	Err error
	// Checks are the checks this pass settled: a reporter replaces their
	// latest findings with Findings. A canceled pass settles none, and a
	// busy one leaves the last apply result until its retry.
	Checks []string
	// LearningProblems are this pass's learning conditions.
	LearningProblems []antispam.Problem
	// LearningGate says what learning may do after this pass.
	LearningGate antispam.LearningGate
	// Learner is where the learning engine runs, zero when no engine
	// should: learning not requested, observe mode, unreadable keys or no
	// private controller socket.
	Learner LearnerTarget
	// Stats is where the web UI reads rspamd's counters, and StatsReason
	// why there is no such place. Zero in a pass that did not collect the
	// controller.
	Stats       antispam.StatsEndpoint
	StatsReason string
}

// LearnerTarget is what a learning engine is built for. A change means a
// new engine.
type LearnerTarget struct {
	Controller     string
	RspamdUID      int
	HashGeneration string
	Prefix         string
}

// Pass brings the host towards d once (spec sections 6.1 and 6.5). A
// disabled pass reads only CSM's own files and runs no command unless it
// finds something to remove.
func (r Reconciler) Pass(ctx context.Context, d Desired) (out Outcome) {
	if err := ctx.Err(); err != nil {
		return Outcome{Err: err}
	}
	if !d.Enabled || d.Observe {
		r.Feeds.setProbeScope([32]byte{})
	}
	if !d.Enabled || !d.Settings.Learning {
		r.Learning.held("")
		r.Learning.roundcubeHeld("")
	}
	invalidateErr := r.Invalidate(ctx)
	if err := ctx.Err(); err != nil {
		return Outcome{Err: err}
	}
	if err := invalidateErr; err != nil {
		out = Outcome{Retry: BusyRetry}
		if !d.Enabled {
			// Disabling this warning depends only on configuration, not
			// on whether pending mail configuration changes can be canceled.
			// Learning findings wait for a completed pass: until removal
			// runs they can still describe installed scoring.
			out.Checks = []string{CheckControllerOpen}
		}
		if !errors.Is(err, eximlock.ErrBusy) {
			retryDetails := "CSM retries shortly."
			if !d.Enabled {
				// A broken state directory does not heal in seconds. With
				// antispam off, retry on the normal interval instead.
				out.Retry = 0
				retryDetails = "CSM retries at the next regular check or after a config reload."
			}
			out.Err = fmt.Errorf("invalidating pending antispam requests: %w", err)
			out.Findings = []alert.Finding{{
				Severity: alert.Warning, Check: CheckApplyFailed, Timestamp: r.Now(),
				Message: "Antispam could not cancel pending changes",
				Details: "Pending antispam workers may still change mail configuration. Check the daemon log for the recording error; " + retryDetails,
			}}
		}
		return out
	}
	var f antispam.HostFacts
	wantLearning := d.Enabled && d.Settings.Learning
	var keys antispam.LearningKeys
	var keysErr error
	var learnerProblems []antispam.Problem
	if wantLearning {
		keys, keysErr = r.learningKeys(ctx, d.Settings.LearningDir)
		if r.Learner != nil {
			learnerProblems = r.Learner()
		}
	}
	if d.Enabled {
		writable, _ := r.Feeds.apply(d.Settings, d.Settings, nil)
		if !d.Observe && writable.HasFeed(antispam.FeedCSMIPMap) && r.IPMap.Write != nil {
			// A write failure is the IP map loop's to report; the feed's
			// preconditions keep the rule off without its file.
			_ = r.IPMap.Write(ctx)
		}
		f = r.Collect(ctx, d.Settings.Socket)
		if d.Settings.HasFeed(antispam.FeedSpamhausDQS) && r.ReadKey != nil {
			f.DQSKey = r.ReadKey(d.Settings.DQSKeyFile)
		}
		if wantLearning {
			if r.CollectLearning != nil {
				r.CollectLearning(ctx, &f)
			}
			f.LearningKeys, f.LearningKeysErr = keys, keysErr
			f.RedisGuardPaused = r.Learning.redisPaused()
			f.LearnerMismatch = slices.ContainsFunc(learnerProblems, func(p antispam.Problem) bool {
				return p.Key == antispam.ReasonStateMismatch
			})
		}
	} else {
		f = r.Installed()
	}
	// Interrupted probes do not describe the host's preconditions.
	if err := ctx.Err(); err != nil {
		return Outcome{Err: err}
	}
	assess := r.assess
	if assess == nil {
		assess = antispam.Assess
	}
	settings, feedProblems := d.Settings, []antispam.Problem(nil)
	var scoreProblems, learningProblems []antispam.Problem
	var gate antispam.LearningGate
	if d.Enabled {
		settings, feedProblems = antispam.ResolveFeeds(d.Settings, f)
		settings, feedProblems = r.Feeds.apply(d.Settings, settings, feedProblems)
		settings, scoreProblems = antispam.ResolveScores(settings, f)
		settings, gate, learningProblems = r.resolveLearningState(settings, f, keys)
	}
	a := assess(d.Enabled, settings, f)
	now := r.Now()
	out = Outcome{Checks: []string{CheckPrecondition, CheckApplyFailed, CheckFeed, CheckLearning}, LearningGate: gate}
	if d.Enabled {
		out.Stats, out.StatsReason = antispam.StatsEndpointFor(f)
	}
	// Prerequisites alone do not prove that the requested integration is
	// active. A worker must finish an apply, or the installed state must
	// already be current, before the learner may publish.
	out.LearningGate.Publish = gate.Publish && a.Action == antispam.Keep && a.Installed && !blockingProblems(a.Problems)
	if d.Observe || a.Action == antispam.Uninstall {
		out.LearningGate = antispam.LearningGate{}
	}
	if wantLearning && !d.Observe && keysErr == nil {
		if socket, uid, ok := antispam.LearnerEndpoint(f); ok {
			out.Learner = LearnerTarget{Controller: socket, RspamdUID: uid, HashGeneration: antispam.HashGeneration(keys), Prefix: keys.Prefix}
		}
	}
	defer func() {
		// Worker verification can add problems. Busy and canceled passes
		// must not replace or add to the last completed learning findings.
		if !slices.Contains(out.Checks, CheckLearning) {
			return
		}
		out.LearningProblems = mergeByKey(append(learningProblems, learnerProblems...))
		for _, p := range out.LearningProblems {
			out.Findings = append(out.Findings, learningFinding(p, now))
		}
	}()
	// Controller exposure needs no install: it is reported whenever
	// antispam is on and cleared when it is off. An unreadable controller
	// keeps the last result.
	controllerSettled := !d.Enabled || f.ControllerErr == nil
	if controllerSettled {
		out.Checks = append(out.Checks, CheckControllerOpen)
	}
	switch {
	case !d.Enabled || f.ControllerErr != nil:
	case f.ControllerUnverifiable != nil:
		out.Findings = append(out.Findings, controllerFinding(antispam.ControllerUnverifiableProblem(), now))
	default:
		for _, p := range antispam.ControllerExposure(f.Controller, f.ControllerHost) {
			out.Findings = append(out.Findings, controllerFinding(p, now))
		}
	}
	for _, p := range a.Problems {
		if p.Code == antispam.CodeFeed {
			feedProblems = append(feedProblems, p)
		}
	}
	// Leftover maps mean something only once CSM's files are installed and
	// current, which a Keep without blocking problems shows.
	if d.Enabled && !d.Observe && settings.Redirects() && a.Action == antispam.Keep && a.Installed && !blockingProblems(a.Problems) {
		if p, ok := leftoverMaps(f); ok {
			feedProblems = append(feedProblems, p)
		}
	}
	for _, p := range mergeByKey(feedProblems) {
		out.Findings = append(out.Findings, feedFinding(p, now))
	}
	if d.Enabled && !d.Observe && a.Action == antispam.Keep && a.Installed && !blockingProblems(a.Problems) {
		out.Findings = append(out.Findings, r.probeFeeds(ctx, settings, f, now)...)
		if err := ctx.Err(); err != nil {
			return Outcome{Err: err}
		}
	} else {
		r.Feeds.setProbeScope([32]byte{})
	}
	for _, p := range slices.Concat(a.Problems, scoreProblems) {
		if p.Code == antispam.CodeFeed {
			continue
		}
		finding := problemFinding(p, now)
		if d.Observe {
			finding.Details = clean(p.Detail) + ". CSM changes nothing in observe mode."
		}
		out.Findings = append(out.Findings, finding)
	}
	// Learning off while rspamd still loads CSM's rules means a removal did
	// not finish, for example because a foreign file replaced one CSM
	// wrote. Judged from this pass's facts, so only when no removal succeeds.
	scoringLeft := d.Enabled && !settings.Learning && f.RspamdConfig.Err == nil && antispam.LearningScoringLoaded([]byte(f.RspamdConfig.Stdout))
	if scoringLeft && (d.Observe || a.Action == antispam.Keep) {
		learningProblems = append(learningProblems, removalIncomplete())
	}
	if d.Observe {
		if a.Installed {
			out.Findings = append(out.Findings, problemFinding(antispam.Problem{
				Code: codeObserve, Severity: antispam.Warning,
				Detail: "CSM's antispam integration is installed and observe mode leaves it in place; leave observe mode so CSM can update or remove it",
			}, now))
		}
		r.settleIPMap(d, settings, a, false, &out)
		return out
	}
	var req antispam.Request
	switch a.Action {
	case antispam.Install:
		req = antispam.ApplyRequest(settings)
	case antispam.Uninstall:
		req = antispam.RemoveRequest()
	default:
		r.settleIPMap(d, settings, a, false, &out)
		return out
	}
	result, err := r.Run(ctx, req)
	// A canceled caller needs no failure alert. Keep completed worker
	// reports, which can still carry a failed rollback requiring attention.
	if err != nil && ctx.Err() != nil {
		return Outcome{Err: err}
	}
	if result.Busy {
		out.Retry = BusyRetry
		// Learning findings depend on the apply as well; keep the last.
		out.Checks = []string{CheckPrecondition, CheckFeed}
		if controllerSettled {
			out.Checks = append(out.Checks, CheckControllerOpen)
		}
	}
	if result.FailedStep == antispam.FeedsCheckStep {
		r.Feeds.hold(d.Settings)
	}
	out.LearningGate.Publish = gate.Publish && req.Operation == antispam.OpApply && err == nil && result.OK
	switch result.FailedStep {
	case antispam.LearningCheckStep:
		r.Learning.hold(learningGeneration(settings))
		out.LearningGate = antispam.LearningGate{}
		learningProblems = append(learningProblems, learningHoldProblem())
	case antispam.LearningProbeStep:
		learningProblems = append(learningProblems, learningProbeProblem())
	}
	if strings.HasPrefix(result.Roundcube, antispam.RoundcubeUnavailable) {
		why := strings.TrimPrefix(result.Roundcube, antispam.RoundcubeUnavailable)
		p := antispam.Problem{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: antispam.ReasonRoundcube, Detail: why}
		if req.Operation == antispam.OpApply && settings.Roundcube {
			r.Learning.holdRoundcube(learningGeneration(settings), why)
			p = roundcubeHoldProblem(why)
		}
		out.LearningGate.Roundcube = false
		learningProblems = append(learningProblems, p)
	}
	if finding, ok := resultFinding(req.Operation, result, err, now); ok {
		out.Findings = append(out.Findings, finding)
	}
	if scoringLeft && !result.Busy && (err != nil || !result.OK) {
		learningProblems = append(learningProblems, removalIncomplete())
	}
	out.Err = err
	r.settleIPMap(d, settings, a, err == nil && result.OK, &out)
	return out
}

// settleIPMap records whether the CSM_IP rule is in use once a pass leaves
// the host matching settings: a Keep without blocking problems, or a
// successful apply or removal. The map is deleted once the host holds
// settings without the rule; observe mode changes nothing.
func (r Reconciler) settleIPMap(d Desired, settings antispam.Settings, a antispam.Assessment, applied bool, out *Outcome) {
	if !applied && (a.Action != antispam.Keep || blockingProblems(a.Problems)) {
		return
	}
	if a.Action != antispam.Uninstall && d.Enabled && !d.Observe && settings.HasFeed(antispam.FeedCSMIPMap) && (a.Installed || applied) {
		r.Feeds.setIPMapActive(true)
		return
	}
	r.Feeds.setIPMapActive(false)
	if !d.Observe && r.IPMap.Remove != nil {
		if err := r.IPMap.Remove(); err != nil {
			out.Err = errors.Join(out.Err, fmt.Errorf("removing the antispam IP map: %w", err))
			out.Findings = append(out.Findings, alert.Finding{
				Severity: alert.Warning, Check: CheckApplyFailed, Timestamp: r.Now(),
				Message: "Antispam IP map removal failed",
				Details: "The unused IP map remains on disk. Check the daemon log for the removal error; CSM retries on its next pass.",
			})
		}
	}
}

// learningKeys creates the keys on first use and reads them. A failure is
// returned for the resolver, which reports it as state_mismatch.
func (r Reconciler) learningKeys(ctx context.Context, dir string) (antispam.LearningKeys, error) {
	if r.EnsureKeys == nil || r.LoadKeys == nil {
		return antispam.LearningKeys{}, errors.New("learning keys are not available in this build")
	}
	if _, err := r.EnsureKeys(ctx, dir); err != nil {
		return antispam.LearningKeys{}, err
	}
	return r.LoadKeys(dir)
}

// resolveLearningState applies the learning hold, the prerequisites and the
// Roundcube hold, in that order, and remembers the Redis guard state.
func (r Reconciler) resolveLearningState(s antispam.Settings, f antispam.HostFacts, keys antispam.LearningKeys) (antispam.Settings, antispam.LearningGate, []antispam.Problem) {
	if !s.Learning {
		s.Roundcube = false
		return s, antispam.LearningGate{}, nil
	}
	s.LearningKeys = keys
	generation := learningGeneration(s)
	s, problems := r.Learning.applyLearningHold(s)
	if !s.Learning {
		return s, antispam.LearningGate{}, problems
	}
	resolve := r.resolveLearning
	if resolve == nil {
		resolve = antispam.ResolveLearning
	}
	s, gate, found := resolve(s, f)
	problems = append(problems, found...)
	if f.Redis.Err == nil && f.Redis.MaxMemoryKnown {
		r.Learning.setRedisPaused(antispam.RedisGuard(f.Redis.Used, f.Redis.MaxMemory, f.RedisGuardPaused))
	}
	s, held := r.Learning.applyRoundcubeHold(s, generation)
	if len(held) > 0 {
		gate.Roundcube = false
		problems = append(problems, held...)
	}
	return s, gate, problems
}

func removalIncomplete() antispam.Problem {
	return antispam.Problem{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: antispam.ReasonRemovalIncomplete,
		Detail: "learning is off but rspamd still loads CSM's learned scoring; a learning file CSM wrote may have been replaced, so CSM cannot remove it"}
}
