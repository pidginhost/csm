package yaraworker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// SupervisorConfig parameterises the daemon-side lifecycle manager for
// the `csm yara-worker` child process.
//
// Restart backoff policy:
//
//   - The first crash triggers a restart after MinRestartInterval.
//   - Each consecutive crash doubles the delay up to MaxRestartInterval.
//   - A worker that stays up for StableDuration resets the backoff to
//     MinRestartInterval so a single bad rule deploy is not punished
//     forever.
type SupervisorConfig struct {
	BinaryPath string
	SocketPath string
	RulesDir   string

	StartTimeout       time.Duration
	MinRestartInterval time.Duration
	MaxRestartInterval time.Duration
	StableDuration     time.Duration

	// ExtraArgs appended to `csm yara-worker`. Tests use this to flag
	// the helper process into mock-worker mode.
	ExtraArgs []string

	// Env override; nil means inherit os.Environ.
	Env []string

	// OnRestart is called after each unplanned worker exit. Exit code
	// is the process exit status (or -1 if the process was killed by a
	// signal whose number is signal). Daemons wire this to a finding
	// emitter.
	OnRestart func(exitCode int, signal syscall.Signal, runDuration time.Duration)

	// Logf is an optional structured-log hook. Supervisor internals log
	// restarts + transient errors here. Nil is fine.
	Logf func(format string, args ...any)

	// ClientTimeout is the per-call read/write deadline the supervisor
	// imposes on the worker. Scan calls inherit this.
	ClientTimeout time.Duration
}

// Supervisor manages the `csm yara-worker` child process and exposes a
// Scanner-shaped surface to the rest of the daemon. One supervisor per
// daemon.
type Supervisor struct {
	cfg SupervisorConfig

	mu      sync.Mutex
	cmd     *exec.Cmd
	client  *yaraipc.Client
	started time.Time
	stopped bool

	running atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	// Restart counters for observability / tests. Under mu.
	restartCount   int
	lastExitCode   int
	lastExitSignal syscall.Signal
}

// NewSupervisor validates cfg and returns an unstarted supervisor.
// Defaults: StartTimeout 10s, MinRestartInterval 1s, MaxRestartInterval
// 60s, StableDuration 30s, ClientTimeout 30s.
func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	if cfg.BinaryPath == "" {
		return nil, errors.New("yaraworker: BinaryPath is required")
	}
	if cfg.SocketPath == "" {
		return nil, errors.New("yaraworker: SocketPath is required")
	}
	if cfg.StartTimeout == 0 {
		cfg.StartTimeout = 10 * time.Second
	}
	if cfg.MinRestartInterval == 0 {
		cfg.MinRestartInterval = time.Second
	}
	if cfg.MaxRestartInterval == 0 {
		cfg.MaxRestartInterval = 60 * time.Second
	}
	if cfg.StableDuration == 0 {
		cfg.StableDuration = 30 * time.Second
	}
	if cfg.ClientTimeout == 0 {
		cfg.ClientTimeout = 30 * time.Second
	}
	return &Supervisor{cfg: cfg}, nil
}

// Start launches the worker and blocks until the first Ping succeeds or
// StartTimeout elapses. Subsequent calls return an error.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running.Load() {
		s.mu.Unlock()
		return errors.New("yaraworker: supervisor already started")
	}
	if s.stopped {
		s.mu.Unlock()
		return errors.New("yaraworker: supervisor already stopped")
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	s.mu.Unlock()

	if err := s.spawnAndWaitReady(); err != nil {
		s.cancel()
		close(s.done)
		return err
	}

	s.running.Store(true)
	go s.supervise()
	return nil
}

// Stop signals the worker to exit, waits for it, and prevents further
// restarts. Safe to call multiple times; subsequent calls are no-ops.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	cancel := s.cancel
	done := s.done
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	s.mu.Lock()
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
	}
	if s.client != nil {
		_ = s.client.Close()
	}
	s.mu.Unlock()

	if done != nil {
		<-done
	}
	return nil
}

// ScanFile is the daemon-facing entrypoint. Errors from the worker
// surface as zero matches and nil; callers see the same "no match"
// outcome as they would for a clean scan. Distinguish real "worker
// degraded" from "nothing matched" via metrics exported from the
// supervisor, not from a returned error.
func (s *Supervisor) ScanFile(path string, maxBytes int) []yara.Match {
	if !s.running.Load() {
		return nil
	}
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		return nil
	}
	res, err := client.ScanFile(yaraipc.ScanFileArgs{Path: path, MaxBytes: maxBytes})
	if err != nil {
		s.logf("scan_file: %v", err)
		return nil
	}
	return toYaraMatches(res.Matches)
}

// ScanBytes is the daemon-facing entrypoint for already-in-memory data.
func (s *Supervisor) ScanBytes(data []byte) []yara.Match {
	if !s.running.Load() {
		return nil
	}
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		return nil
	}
	res, err := client.ScanBytes(yaraipc.ScanBytesArgs{Data: data})
	if err != nil {
		s.logf("scan_bytes: %v", err)
		return nil
	}
	return toYaraMatches(res.Matches)
}

// Reload asks the worker to recompile its rules directory.
func (s *Supervisor) Reload() error {
	if !s.running.Load() {
		return errors.New("yaraworker: supervisor not running")
	}
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		return errors.New("yaraworker: no client")
	}
	_, err := client.Reload(yaraipc.ReloadArgs{})
	return err
}

// RuleCount queries the worker. Zero on any error, matching the scanner
// semantics the daemon already expects.
func (s *Supervisor) RuleCount() int {
	if !s.running.Load() {
		return 0
	}
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		return 0
	}
	res, err := client.Ping()
	if err != nil {
		return 0
	}
	return res.RuleCount
}

// RestartCount is exposed for metrics + tests.
func (s *Supervisor) RestartCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restartCount
}

// ChildPID returns the current worker's pid, or 0 when no worker is
// running. For operator-facing log lines.
func (s *Supervisor) ChildPID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil || s.cmd.Process == nil {
		return 0
	}
	return s.cmd.Process.Pid
}

// RestartWorker signals the current worker to exit so the supervise
// loop respawns it against whatever state is now on disk (new rules
// directory, updated binary, etc.). Callers should prefer Reload for
// normal rule updates; RestartWorker is the escalation path for the
// rare case where an in-process recompile cannot or must not be
// trusted. The call returns immediately; the restart is asynchronous
// and observable via the OnRestart callback.
//
// No-op when the supervisor is stopped or has no running child.
func (s *Supervisor) RestartWorker() error {
	if s.stopped {
		return errors.New("yaraworker: supervisor is stopped")
	}
	s.mu.Lock()
	cmd := s.cmd
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return errors.New("yaraworker: no running worker")
	}
	return cmd.Process.Signal(syscall.SIGTERM)
}

// supervise watches the current child and restarts it on exit until
// ctx is cancelled.
func (s *Supervisor) supervise() {
	defer close(s.done)

	backoff := s.cfg.MinRestartInterval
	for {
		exitCode, sig := s.waitForChild()
		if s.ctx.Err() != nil {
			return
		}

		runDuration := time.Since(s.started)
		s.mu.Lock()
		s.restartCount++
		s.lastExitCode = exitCode
		s.lastExitSignal = sig
		s.mu.Unlock()

		if s.cfg.OnRestart != nil {
			s.cfg.OnRestart(exitCode, sig, runDuration)
		}

		if runDuration >= s.cfg.StableDuration {
			backoff = s.cfg.MinRestartInterval
		}

		s.logf("worker exited code=%d signal=%v ran=%s, restarting in %s",
			exitCode, sig, runDuration.Round(time.Millisecond), backoff)

		select {
		case <-time.After(backoff):
		case <-s.ctx.Done():
			return
		}

		if err := s.spawnAndWaitReady(); err != nil {
			s.logf("restart failed: %v", err)
			backoff *= 2
			if backoff > s.cfg.MaxRestartInterval {
				backoff = s.cfg.MaxRestartInterval
			}
			continue
		}
		backoff *= 2
		if backoff > s.cfg.MaxRestartInterval {
			backoff = s.cfg.MaxRestartInterval
		}
	}
}

// waitForChild blocks until the current worker exits, then returns its
// exit code and signal. -1/0 for either field means "unknown" or "not
// applicable".
func (s *Supervisor) waitForChild() (int, syscall.Signal) {
	s.mu.Lock()
	cmd := s.cmd
	s.mu.Unlock()
	if cmd == nil {
		return -1, 0
	}
	err := cmd.Wait()
	if err == nil {
		return 0, 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if status, ok := ee.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return -1, status.Signal()
			}
			return status.ExitStatus(), 0
		}
		return ee.ExitCode(), 0
	}
	return -1, 0
}

func (s *Supervisor) spawnAndWaitReady() error {
	s.mu.Lock()
	if s.client != nil {
		_ = s.client.Close()
		s.client = nil
	}
	s.mu.Unlock()

	// Unlink stale socket here too, even though the worker also does
	// it: the worker may fail before reaching its own unlink, leaving
	// a stale file that blocks dial attempts during a failed start.
	if err := os.Remove(s.cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("yaraworker: removing stale socket: %w", err)
	}

	args := []string{"yara-worker",
		"--socket", s.cfg.SocketPath,
		"--rules-dir", s.cfg.RulesDir,
	}
	args = append(args, s.cfg.ExtraArgs...)

	// #nosec G204 -- BinaryPath is supervisor-operator-configured (see
	// cmd/csm/main.go binaryPath), not attacker-controlled.
	cmd := exec.Command(s.cfg.BinaryPath, args...)
	if s.cfg.Env != nil {
		cmd.Env = s.cfg.Env
	}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("yaraworker: start worker: %w", err)
	}

	s.mu.Lock()
	s.cmd = cmd
	s.started = time.Now()
	client := yaraipc.NewClient(s.cfg.SocketPath, s.cfg.ClientTimeout)
	s.client = client
	s.mu.Unlock()

	if err := s.waitForReady(client); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		s.mu.Lock()
		s.cmd = nil
		_ = s.client.Close()
		s.client = nil
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *Supervisor) waitForReady(client *yaraipc.Client) error {
	deadline := time.Now().Add(s.cfg.StartTimeout)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(s.cfg.SocketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			if _, err := client.Ping(); err == nil {
				return nil
			}
		}
		select {
		case <-time.After(25 * time.Millisecond):
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
	return fmt.Errorf("yaraworker: worker did not become ready within %s", s.cfg.StartTimeout)
}

func (s *Supervisor) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

func toYaraMatches(in []yaraipc.Match) []yara.Match {
	if len(in) == 0 {
		return nil
	}
	out := make([]yara.Match, len(in))
	for i := range in {
		out[i] = yara.Match{RuleName: in[i].RuleName}
	}
	return out
}

// defaultSocketPath mirrors the roadmap-agreed location. Exposed for
// the daemon to reach when wiring up config defaults.
func DefaultSocketPath() string {
	return filepath.Join("/var", "run", "csm", "yara-worker.sock")
}
