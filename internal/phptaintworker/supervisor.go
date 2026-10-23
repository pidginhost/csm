package phptaintworker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/phptaintipc"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/workerproc"
)

// ConsecutiveFailureLimit is how many failed workers in a row are tolerated
// before spawning pauses for one cooldown; see workerproc.
const ConsecutiveFailureLimit = workerproc.ConsecutiveFailureLimit

// SupervisorConfig describes how to start the worker process.
type SupervisorConfig struct {
	// Command and Args start the worker. In production this is the CSM binary
	// re-executing itself as a subcommand.
	Command string
	Args    []string
	Env     []string
	// Timeout bounds a single analysis. It must exceed the slowest legitimate
	// file by a wide margin: every expiry costs a killed process, so a value
	// tuned too tightly converts slow-but-fine files into coverage gaps.
	Timeout time.Duration
	// Log is optional.
	Log func(string, ...any)
}

// Supervisor runs PHP taint analysis in a worker process. Containment, the
// breaker and request health are workerproc's; this type adds the pre-filter,
// the payload schema and the mapping from failures to coverage gaps.
type Supervisor struct {
	cfg  SupervisorConfig
	proc *workerproc.Supervisor

	mu   sync.Mutex
	mode string
}

// NewSupervisor validates config. It does not start a worker: the first
// analysis does, so a scan that never admits a candidate never forks.
func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	if cfg.Command == "" {
		return nil, errors.New("phptaintworker: empty command")
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("phptaintworker: timeout must be positive")
	}
	s := &Supervisor{cfg: cfg}
	proc, err := workerproc.New(workerproc.Config{
		Name:    "phptaint worker",
		Launch:  s.launch,
		Timeout: cfg.Timeout,
		Limits:  workerproc.Limits{MaxFrameBytes: phptaintipc.MaxFrameBytes},
		Log:     cfg.Log,
	})
	if err != nil {
		return nil, err
	}
	s.proc = proc
	return s, nil
}

func (s *Supervisor) launch(ctx context.Context) (workerproc.Process, error) {
	s.mu.Lock()
	mode := s.mode
	s.mu.Unlock()
	env := s.cfg.Env
	if mode != "" {
		env = append(append([]string(nil), env...), "CSM_HELPER_WORKER="+mode)
	}
	return workerproc.ExecLauncher(s.cfg.Command, s.cfg.Args, env)(ctx)
}

// SetMode is a test seam for the helper child, which selects its behaviour
// from the environment. Production callers never use it.
func (s *Supervisor) SetMode(mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
}

// LastChildPID reports the pid of the most recently started worker.
func (s *Supervisor) LastChildPID() int { return s.proc.Stats().LastPID }

// SpawnCount reports how many workers have been started.
func (s *Supervisor) SpawnCount() int { return s.proc.Stats().Spawns }

// Stop shuts down the current worker.
func (s *Supervisor) Stop() error { return s.proc.Stop() }

// QueueStatuses does not take the supervisor lock or inspect child processes.
func (s *Supervisor) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return s.proc.QueueStatuses(now)
}

// Analyze runs one analysis in the worker. It never returns a status a caller
// could read as clean unless the worker actually produced one, or unless the
// pre-filter the worker applies before parsing already rejects the content.
func (s *Supervisor) Analyze(ctx context.Context, src []byte) phptaint.Report {
	// The deep scan hands every file it reads to this analyzer, and the
	// worker serves one request at a time. Content the pre-filter rejects
	// needs no parser, so answering it here keeps images and plain text from
	// queuing behind real analyses or forking a worker. Size and
	// cancellation are the answers the worker path gives first, so they
	// still take precedence.
	if len(src) <= phptaint.MaxSourceBytes && ctx.Err() == nil && !phptaint.IsCandidate(src) {
		// Cancellation may arrive during the byte scan. The IPC path
		// observes it while waiting for a reply; a local answer must too.
		if err := ctx.Err(); err != nil {
			return gap(phptaint.StatusCanceled, err.Error())
		}
		return phptaint.Report{Status: phptaint.StatusNotCandidate}
	}
	req, err := phptaintipc.EncodePayload(phptaintipc.OpAnalyze, phptaintipc.AnalyzeArgs{Source: src})
	if err != nil {
		// An oversize source is the caller's own ceiling, not a worker fault,
		// so it must not count toward the breaker. It never reaches a worker,
		// so it is the answer whatever state the worker side is in.
		return gap(phptaint.StatusOversize, err.Error())
	}
	var report phptaint.Report
	_, _, err = s.proc.Call(ctx, req, nil, func(reply workerproc.Frame, _ []*os.File) (bool, error) {
		var out phptaintipc.AnalyzeResult
		if decodeErr := phptaintipc.DecodePayload(reply, &out); decodeErr != nil {
			return false, decodeErr
		}
		if validErr := phptaintipc.ValidateReportForSource(out.Report, len(src)); validErr != nil {
			return false, validErr
		}
		report = out.Report
		return report.Status == phptaint.StatusPanic, nil
	})
	switch {
	case err == nil:
		return report
	case errors.Is(err, workerproc.ErrStopped):
		return gap(phptaint.StatusWorkerFailure, "supervisor stopped")
	case errors.Is(err, workerproc.ErrTimeout):
		return gap(phptaint.StatusTimeout, fmt.Sprintf("analysis exceeded %s; worker killed", s.cfg.Timeout))
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return gap(phptaint.StatusCanceled, err.Error())
	default:
		return gap(phptaint.StatusWorkerFailure, err.Error())
	}
}

func gap(status phptaint.Status, reason string) phptaint.Report {
	return phptaint.CoverageGap(status, reason)
}
