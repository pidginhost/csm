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
}

// Pass brings the host towards d once (spec sections 6.1 and 6.5). A
// disabled pass reads only CSM's own files and runs no command unless it
// finds something to remove.
func (r Reconciler) Pass(ctx context.Context, d Desired) Outcome {
	if err := ctx.Err(); err != nil {
		return Outcome{Err: err}
	}
	if !d.Enabled || d.Observe {
		r.Feeds.setProbeScope([32]byte{})
	}
	if !d.Enabled {
		r.Learning.held("")
	}
	invalidateErr := r.Invalidate(ctx)
	if err := ctx.Err(); err != nil {
		return Outcome{Err: err}
	}
	if err := invalidateErr; err != nil {
		out := Outcome{Retry: BusyRetry}
		if !d.Enabled {
			// Disabling this warning depends only on configuration, not
			// on whether pending mail configuration changes can be canceled.
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
	var learningProblems []antispam.Problem
	if d.Enabled {
		settings, feedProblems = antispam.ResolveFeeds(d.Settings, f)
		settings, feedProblems = r.Feeds.apply(d.Settings, settings, feedProblems)
		settings, learningProblems = r.Learning.applyLearningHold(settings)
	}
	a := assess(d.Enabled, settings, f)
	now := r.Now()
	out := Outcome{Checks: []string{CheckPrecondition, CheckApplyFailed, CheckFeed}, LearningProblems: learningProblems}
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
	for _, p := range append(slices.Clone(a.Problems), learningProblems...) {
		if p.Code == antispam.CodeFeed {
			continue
		}
		finding := problemFinding(p, now)
		if d.Observe {
			finding.Details = clean(p.Detail) + ". CSM changes nothing in observe mode."
		}
		out.Findings = append(out.Findings, finding)
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
		out.Checks = []string{CheckPrecondition, CheckFeed}
		if controllerSettled {
			out.Checks = append(out.Checks, CheckControllerOpen)
		}
	}
	if result.FailedStep == antispam.FeedsCheckStep {
		r.Feeds.hold(d.Settings)
	}
	if result.FailedStep == antispam.LearningCheckStep {
		r.Learning.hold(learningGeneration(settings))
	}
	if settings.Roundcube && strings.HasPrefix(result.Roundcube, antispam.RoundcubeUnavailable) {
		r.Learning.holdRoundcube(learningGeneration(settings), strings.TrimPrefix(result.Roundcube, antispam.RoundcubeUnavailable))
	}
	if finding, ok := resultFinding(req.Operation, result, err, now); ok {
		out.Findings = append(out.Findings, finding)
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
