package reconcile

import (
	"context"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/config"
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
	return Desired{
		Enabled: as.Enabled,
		Observe: cfg.ObserveMode(),
		Settings: antispam.Settings{
			DryRun: as.DryRun, Socket: as.RspamdSocket,
			RejectScore: as.RejectScore, TagScore: as.TagScore,
		},
	}
}

// Reconciler runs one pass at a time against the host its functions read
// and change.
type Reconciler struct {
	// Collect reads every precondition fact for the scan socket.
	Collect func(ctx context.Context, socket string) antispam.HostFacts
	// Installed reads only what shows CSM's integration on the host.
	Installed func() antispam.HostFacts
	// Run sends one request to the root worker.
	Run func(ctx context.Context, req antispam.Request) (antispam.Result, error)
	// Now stamps findings.
	Now func() time.Time
	// assess replaces antispam.Assess in tests.
	assess func(enabled bool, s antispam.Settings, f antispam.HostFacts) antispam.Assessment
}

// Outcome is what one pass found and did.
type Outcome struct {
	// Findings are the antispam conditions true after this pass.
	Findings []alert.Finding
	// Retry, when set, asks for another pass this soon.
	Retry time.Duration
	// Err is a canceled pass or the worker error behind a missing result,
	// for the daemon log.
	Err error
}

// Pass brings the host towards d once (spec sections 6.1 and 6.5). A
// disabled pass reads only CSM's own files and runs no command unless it
// finds something to remove.
func (r Reconciler) Pass(ctx context.Context, d Desired) Outcome {
	if err := ctx.Err(); err != nil {
		return Outcome{Err: err}
	}
	var f antispam.HostFacts
	if d.Enabled {
		f = r.Collect(ctx, d.Settings.Socket)
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
	a := assess(d.Enabled, d.Settings, f)
	now := r.Now()
	var out Outcome
	for _, p := range a.Problems {
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
		return out
	}
	var req antispam.Request
	switch a.Action {
	case antispam.Install:
		req = antispam.ApplyRequest(d.Settings)
	case antispam.Uninstall:
		req = antispam.RemoveRequest()
	default:
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
	}
	if finding, ok := resultFinding(req.Operation, result, err, now); ok {
		out.Findings = append(out.Findings, finding)
	}
	out.Err = err
	return out
}
