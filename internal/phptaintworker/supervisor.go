package phptaintworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/phptaintipc"
)

// ConsecutiveFailureLimit is how many failed workers in a row are tolerated
// before the supervisor stops spawning replacements.
//
// It is a constant rather than a setting because nothing an operator can
// observe would tell them a better value: the right number depends on how the
// parser fails, not on the host. It is also harmful in both directions -- too
// low and one transient failure blinds the rest of a scan, too high and a
// crafted account gets the exec storm the limit exists to prevent. When it
// trips, the coverage gap says so, so the condition stays visible even though
// the threshold is not tunable.
const ConsecutiveFailureLimit = 3

// reapTimeout bounds how long killLocked waits for a SIGKILLed child while
// holding the supervisor lock.
const reapTimeout = 10 * time.Second

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

// Supervisor runs one worker process at a time and guarantees that a request
// which does not return kills the process it was running in.
//
// The guarantee is the point. A deadline on its own is not containment: the
// call returns to the caller while the child keeps spinning on a core, and the
// next request starts another one. That is the failure mode of a timeout
// without a kill, and it is why this type does not reuse the YARA supervisor,
// which restarts a child on exit and never kills one that simply stops
// answering.
//
// A worker that misses its deadline is poisoned: killed, reaped, and never
// used again. Replacement is lazy, so a scan with no further candidates pays
// nothing for the last file's failure.
type Supervisor struct {
	cfg SupervisorConfig

	mu          sync.Mutex
	child       *child
	lastPID     int
	spawns      int
	consecutive int
	mode        string
	stopped     bool
}

type child struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	done   chan struct{}
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
	return &Supervisor{cfg: cfg}, nil
}

// SetMode is a test seam for the helper child, which selects its behaviour
// from the environment. Production callers never use it.
func (s *Supervisor) SetMode(mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
}

// LastChildPID reports the pid of the most recently started worker.
func (s *Supervisor) LastChildPID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPID
}

// SpawnCount reports how many workers have been started.
func (s *Supervisor) SpawnCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spawns
}

// Stop shuts down the current worker.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	s.killLocked()
	return nil
}

// Analyze runs one analysis in the worker. It never returns a status a caller
// could read as clean unless the worker actually produced one.
func (s *Supervisor) Analyze(ctx context.Context, src []byte) phptaint.Report {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return gap(phptaint.StatusWorkerFailure, "supervisor stopped")
	}
	if s.consecutive >= ConsecutiveFailureLimit {
		return gap(phptaint.StatusWorkerFailure, fmt.Sprintf(
			"worker failed %d times in a row; not analyzed", s.consecutive))
	}
	req, err := phptaintipc.EncodePayload(phptaintipc.OpAnalyze, phptaintipc.AnalyzeArgs{Source: src})
	if err != nil {
		// An oversize source is the caller's own ceiling, not a worker fault,
		// so it must not count toward the breaker.
		return gap(phptaint.StatusOversize, err.Error())
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return gap(phptaint.StatusCanceled, ctxErr.Error())
	}
	if startErr := s.ensureChildLocked(); startErr != nil {
		s.consecutive++
		return gap(phptaint.StatusWorkerFailure, startErr.Error())
	}

	report, err := s.roundTripLocked(ctx, req)
	if err != nil {
		// The child is not trusted after any failure: it may be mid-parse and
		// spinning, or it may have left a partial frame in the pipe that would
		// desynchronise every later request.
		s.killLocked()
		if errors.Is(err, errDeadline) {
			s.consecutive++
			return gap(phptaint.StatusTimeout, fmt.Sprintf(
				"analysis exceeded %s; worker killed", s.cfg.Timeout))
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return gap(phptaint.StatusCanceled, err.Error())
		}
		s.consecutive++
		return gap(phptaint.StatusWorkerFailure, err.Error())
	}
	s.consecutive = 0
	return report
}

var errDeadline = errors.New("phptaintworker: analysis deadline exceeded")

// roundTripLocked writes one request and waits for its reply, bounded by the
// configured timeout. The pipe round trip runs on its own goroutine because the
// child may stop before reading the complete request or never answer. The
// goroutine ends when killLocked closes the pipes.
func (s *Supervisor) roundTripLocked(ctx context.Context, req phptaintipc.Frame) (phptaint.Report, error) {
	c := s.child
	type result struct {
		frame phptaintipc.Frame
		err   error
	}
	timer := time.NewTimer(s.cfg.Timeout)
	defer timer.Stop()

	done := make(chan result, 1)
	go func() {
		if err := phptaintipc.WriteFrame(c.stdin, req); err != nil {
			done <- result{err: fmt.Errorf("phptaintworker: write request: %w", err)}
			return
		}
		f, err := phptaintipc.ReadFrame(c.stdout)
		done <- result{frame: f, err: err}
	}()

	select {
	case <-timer.C:
		return phptaint.Report{}, errDeadline
	case <-ctx.Done():
		return phptaint.Report{}, ctx.Err()
	case res := <-done:
		if res.err != nil {
			return phptaint.Report{}, fmt.Errorf("phptaintworker: read reply: %w", res.err)
		}
		if res.frame.Error != "" {
			return phptaint.Report{}, fmt.Errorf("phptaintworker: worker: %s", res.frame.Error)
		}
		if res.frame.Op != "" {
			return phptaint.Report{}, fmt.Errorf("phptaintworker: response carries op %q", res.frame.Op)
		}
		var out phptaintipc.AnalyzeResult
		if err := phptaintipc.DecodePayload(res.frame, &out); err != nil {
			return phptaint.Report{}, err
		}
		return out.Report, nil
	}
}

func (s *Supervisor) ensureChildLocked() error {
	if s.child != nil {
		return nil
	}
	env := s.cfg.Env
	if s.mode != "" {
		env = append(append([]string(nil), env...), "CSM_HELPER_WORKER="+s.mode)
	}
	cmd := exec.Command(s.cfg.Command, s.cfg.Args...) // #nosec G204 -- command comes from the daemon's own config, not from scanned content.
	cmd.Env = env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("phptaintworker: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("phptaintworker: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("phptaintworker: start worker: %w", err)
	}
	c := &child{cmd: cmd, stdin: stdin, stdout: stdout, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(c.done)
	}()
	s.child = c
	s.spawns++
	s.lastPID = cmd.Process.Pid
	return nil
}

// killLocked terminates the current worker and waits for it to be reaped.
//
// SIGKILL, not SIGTERM: the process this exists to stop is spinning inside a
// parser loop and never returns to a point where a catchable signal would be
// handled. Closing the pipes around the kill unblocks the round-trip goroutine
// so it cannot outlive the child.
func (s *Supervisor) killLocked() {
	c := s.child
	if c == nil {
		return
	}
	s.child = nil
	_ = c.stdin.Close()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	_ = c.stdout.Close()

	// Bounded, because this runs while the supervisor lock is held: an
	// unbounded wait would turn one unreapable child into a frozen analyzer
	// for every later file. SIGKILL cannot be caught or ignored, so the only
	// way to reach the timeout is a process wedged in uninterruptible sleep.
	// Giving up on the reap leaks one process; blocking here would stop the
	// scan, and the scan is what protects the host.
	select {
	case <-c.done:
	case <-time.After(reapTimeout):
		if s.cfg.Log != nil {
			s.cfg.Log("phptaint worker %d did not exit after SIGKILL", c.cmd.Process.Pid)
		}
		return
	}
	if s.cfg.Log != nil {
		s.cfg.Log("phptaint worker %d killed", c.cmd.Process.Pid)
	}
}

func gap(status phptaint.Status, reason string) phptaint.Report {
	return phptaint.CoverageGap(status, reason)
}
