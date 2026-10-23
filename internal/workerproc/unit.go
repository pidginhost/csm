package workerproc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/systemdrun"
)

// UnitConfig describes workers run as locked-down transient systemd units.
type UnitConfig struct {
	// Prefix names the units: Prefix + "-" + a generation number.
	Prefix  string
	Command string
	Args    []string
	// MemoryLimit caps memory and swap together, in bytes.
	MemoryLimit uint64
	// FileSizeLimit is LimitFSIZE. It bounds the worker's memfds too, so it
	// must exceed the largest reply a worker writes.
	FileSizeLimit uint64
	RuntimeMax    time.Duration
	// StartTimeout bounds unit start, hello and the memory cap together.
	StartTimeout time.Duration
	Protocol     int
	// Limits applies to the hello reply.
	Limits Limits
	Log    func(string, ...any)

	hooks *unitHooks // tests only; nil means the real system
}

// unitHooks are the system calls the launcher makes, replaced in tests.
type unitHooks struct {
	systemdRun           string
	mainPID              func(ctx context.Context, p *unitProcess) (int, error)
	killUnit             func(ctx context.Context, p *unitProcess) error
	procRoot, cgroupRoot string
	pollInterval         time.Duration
}

// unitKillTimeout bounds one systemctl kill.
const unitKillTimeout = 5 * time.Second

// unitGeneration numbers units. Seeded with the start time so a restarted
// daemon does not reuse the name of a unit still being torn down.
var unitGeneration = func() *atomic.Int64 {
	var g atomic.Int64
	g.Store(time.Now().UnixNano())
	return &g
}()

// lockdownProperties are the unit properties every worker runs under: no
// network, no host files, no privileges, bounded memory, tasks and files.
func lockdownProperties(cfg UnitConfig) []string {
	memory := strconv.FormatUint(cfg.MemoryLimit, 10)
	return []string{
		"DynamicUser=yes",
		"CapabilityBoundingSet=",
		"NoNewPrivileges=yes",
		"PrivateNetwork=yes",
		"RestrictAddressFamilies=AF_UNIX",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"ProtectKernelTunables=yes",
		"ProtectKernelModules=yes",
		"ProtectControlGroups=yes",
		"RestrictNamespaces=yes",
		"RestrictRealtime=yes",
		"LockPersonality=yes",
		"MemoryDenyWriteExecute=yes",
		"UMask=0077",
		"SystemCallFilter=@system-service",
		"SystemCallErrorNumber=EPERM",
		"MemoryAccounting=yes",
		"MemoryLimit=" + memory,
		"MemoryMax=" + memory,
		"MemorySwapMax=0",
		"TasksMax=64",
		"LimitNOFILE=256",
		"LimitCORE=0",
		"LimitFSIZE=" + strconv.FormatUint(cfg.FileSizeLimit, 10),
		// Matches csm.service, so a worker never outweighs the daemon.
		"CPUWeight=50",
	}
}

// UnitLauncher starts each worker as its own transient unit through
// `systemd-run --pipe`, whose stdin and stdout are the worker's socket. A
// worker is handed out only after it answered hello and its main PID is
// known; there is no fallback to running the command directly.
func UnitLauncher(cfg UnitConfig) Launcher {
	h := unitHooks{}
	if cfg.hooks != nil {
		h = *cfg.hooks
	}
	if h.mainPID == nil {
		h.mainPID = systemctlMainPID
	}
	if h.killUnit == nil {
		h.killUnit = systemctlKill
	}
	if h.procRoot == "" {
		h.procRoot = "/proc"
	}
	if h.cgroupRoot == "" {
		h.cgroupRoot = "/sys/fs/cgroup"
	}
	if h.pollInterval <= 0 {
		h.pollInterval = 500 * time.Millisecond
	}
	return func(ctx context.Context) (Process, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, err := startUnit(ctx, cfg, &h)
		if err != nil {
			return nil, fmt.Errorf("workerproc: isolation unavailable: %w", err)
		}
		return p, nil
	}
}

func startUnit(ctx context.Context, cfg UnitConfig, h *unitHooks) (*unitProcess, error) {
	path := h.systemdRun
	if path == "" {
		var err error
		if path, err = exec.LookPath("systemd-run"); err != nil {
			return nil, err
		}
	}
	conn, childFile, err := workerSocket()
	if err != nil {
		return nil, err
	}

	unit := cfg.Prefix + "-" + strconv.FormatInt(unitGeneration.Add(1), 10)
	name, args := systemdrun.Argv(path, systemdrun.Options{
		Pipe:       true,
		RuntimeMax: cfg.RuntimeMax,
		Unit:       unit,
		Properties: lockdownProperties(cfg),
	}, cfg.Command, cfg.Args...)
	// Not CommandContext: ending the request must not kill the worker.
	cmd := exec.Command(name, args...) // #nosec G204 -- systemd-run with fixed flags and the daemon's own binary.
	cmd.Stdin = childFile
	cmd.Stdout = childFile
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	// Closed at once, not deferred: while the daemon holds the child's end,
	// a systemd-run that exits early leaves the hello waiting for its
	// deadline instead of reading end of file.
	_ = childFile.Close()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("start systemd-run: %w", err)
	}
	p := &unitProcess{unit: unit, cmd: cmd, conn: conn, done: make(chan struct{}), killUnit: h.killUnit, log: cfg.Log}
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()

	startCtx, cancel := context.WithTimeout(ctx, cfg.StartTimeout)
	defer cancel()
	if err := p.start(startCtx, cfg, h); err != nil {
		_ = p.Kill()
		_ = conn.Close()
		select {
		case <-p.done:
		case <-time.After(reapTimeout):
			p.logf("unit %s did not stop", unit)
		}
		return nil, fmt.Errorf("unit %s: %w", unit, err)
	}
	return p, nil
}

// start finishes a launch: hello, then the main PID, which only systemd
// reports, never the worker.
func (p *unitProcess) start(ctx context.Context, cfg UnitConfig, h *unitHooks) error {
	if err := Handshake(ctx, p.conn, cfg.Limits, cfg.Protocol); err != nil {
		return err
	}
	pid, err := h.mainPID(ctx, p)
	if err != nil {
		return fmt.Errorf("main PID: %w", err)
	}
	if pid <= 0 {
		return errors.New("unit has no main process")
	}
	p.pid = pid
	return nil
}

// unitProcess is one worker unit. Done follows the systemd-run client, which
// exits when the unit ends.
type unitProcess struct {
	unit     string
	cmd      *exec.Cmd
	conn     *net.UnixConn
	done     chan struct{}
	pid      int
	killUnit func(ctx context.Context, p *unitProcess) error
	kill     sync.Once
	log      func(string, ...any)
}

func (p *unitProcess) Conn() *net.UnixConn   { return p.conn }
func (p *unitProcess) Done() <-chan struct{} { return p.done }
func (p *unitProcess) PID() int              { return p.pid }
func (p *unitProcess) Retire() bool          { return false }

// Kill asks systemd to SIGKILL the unit and returns at once: the supervisor
// calls it holding its lock, and a hung systemctl must not freeze it. The
// worker is killed by unit name, never by a PID it could have influenced.
func (p *unitProcess) Kill() error {
	p.kill.Do(func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), unitKillTimeout)
			defer cancel()
			if err := p.killUnit(ctx, p); err != nil {
				p.logf("kill unit %s: %v", p.unit, err)
			}
		}()
	})
	return nil
}

func (p *unitProcess) logf(format string, args ...any) {
	if p.log != nil {
		p.log(format, args...)
	}
}

func systemctlMainPID(ctx context.Context, p *unitProcess) (int, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "MainPID", "--value", p.unit+".service").Output() // #nosec G204 -- the unit name is ours.
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

func systemctlKill(ctx context.Context, p *unitProcess) error {
	out, err := exec.CommandContext(ctx, "systemctl", "kill", "--signal=SIGKILL", p.unit+".service").CombinedOutput() // #nosec G204 -- the unit name is ours.
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// StopUnits SIGKILLs every unit whose name starts with prefix, for leftovers
// of a daemon that died without stopping its workers.
func StopUnits(ctx context.Context, prefix string) error {
	out, err := exec.CommandContext(ctx, "systemctl", "kill", "--signal=SIGKILL", "--", prefix+"*.service").CombinedOutput() // #nosec G204 -- the prefix is a constant of the caller.
	if err != nil {
		return fmt.Errorf("workerproc: stop units %s*: %w: %s", prefix, err, strings.TrimSpace(string(out)))
	}
	return nil
}
