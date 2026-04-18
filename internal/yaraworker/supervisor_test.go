package yaraworker

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/yaraipc"
)

// Helper-process pattern: TestMain checks an env var and, if set, runs
// the mock worker in place of the test suite. This lets supervisor
// tests spawn the test binary itself as the worker process, avoiding
// the cost (and CI fragility) of building a separate helper binary.

func TestMain(m *testing.M) {
	if mode := os.Getenv("YARAWORKER_HELPER"); mode != "" {
		runHelper(mode)
		return
	}
	os.Exit(m.Run())
}

func runHelper(mode string) {
	sock := ""
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "--socket" && i+1 < len(os.Args) {
			sock = os.Args[i+1]
		}
	}
	if sock == "" {
		fmt.Fprintln(os.Stderr, "helper: --socket is required")
		os.Exit(2)
	}

	switch mode {
	case "normal":
		helperRunNormal(sock, 0)
	case "exit-on-start":
		code := 5
		if v := os.Getenv("YARAWORKER_EXIT_CODE"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				code = n
			}
		}
		os.Exit(code)
	case "sleep-forever":
		time.Sleep(time.Hour)
	case "crash-after-ping":
		helperRunNormal(sock, 139)
	default:
		fmt.Fprintf(os.Stderr, "helper: unknown mode %q\n", mode)
		os.Exit(2)
	}

	os.Exit(0)
}

// helperRunNormal binds the socket and serves a scriptedHandler. If
// exitAfterPing is non-zero, the handler's Ping() calls os.Exit on the
// second call, modelling a real cgo crash during a scan: the supervisor
// sees the process go away and must restart it.
func helperRunNormal(sock string, exitAfterPing int) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		os.Exit(3)
	}
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: listen:", err)
		os.Exit(4)
	}
	_ = os.Chmod(sock, 0o600)

	ruleCount := 1
	if v := os.Getenv("YARAWORKER_RULE_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			ruleCount = n
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-sigs
		cancel()
	}()

	h := &scriptedHandler{ruleCount: ruleCount, exitAfterPing: exitAfterPing}
	_ = yaraipc.Serve(ctx, ln, h, yaraipc.ServeOptions{})
}

type scriptedHandler struct {
	mu            sync.Mutex
	ruleCount     int
	pings         int
	exitAfterPing int
}

func (s *scriptedHandler) ScanFile(_ yaraipc.ScanFileArgs) (yaraipc.ScanResult, error) {
	return yaraipc.ScanResult{}, nil
}
func (s *scriptedHandler) ScanBytes(_ yaraipc.ScanBytesArgs) (yaraipc.ScanResult, error) {
	return yaraipc.ScanResult{}, nil
}
func (s *scriptedHandler) Reload(_ yaraipc.ReloadArgs) (yaraipc.ReloadResult, error) {
	return yaraipc.ReloadResult{RuleCount: s.ruleCount}, nil
}
func (s *scriptedHandler) Ping() (yaraipc.PingResult, error) {
	s.mu.Lock()
	s.pings++
	pings := s.pings
	code := s.exitAfterPing
	s.mu.Unlock()
	if code != 0 && pings >= 2 {
		os.Exit(code)
	}
	return yaraipc.PingResult{Alive: true, RuleCount: s.ruleCount}, nil
}

// helperEnv prepares an env slice that selects the helper mode. Extra
// key=value pairs tune helper behaviour.
func helperEnv(mode string, extra ...string) []string {
	env := append([]string{}, os.Environ()...)
	env = append(env, "YARAWORKER_HELPER="+mode)
	env = append(env, extra...)
	return env
}

func shortSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "y")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "w.sock")
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

func TestSupervisorStartsAndStops(t *testing.T) {
	sock := shortSockPath(t)
	cfg := SupervisorConfig{
		BinaryPath:         os.Args[0],
		SocketPath:         sock,
		RulesDir:           "",
		StartTimeout:       3 * time.Second,
		MinRestartInterval: 50 * time.Millisecond,
		MaxRestartInterval: 500 * time.Millisecond,
		StableDuration:     50 * time.Millisecond,
		ClientTimeout:      2 * time.Second,
		Env:                helperEnv("normal", "YARAWORKER_RULE_COUNT=7"),
	}
	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if n := sup.RuleCount(); n != 7 {
		t.Errorf("rule_count: got %d want 7", n)
	}

	if err := sup.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if err := sup.Stop(); err != nil {
		t.Errorf("Stop (idempotent): %v", err)
	}
}

func TestSupervisorRestartsOnCrash(t *testing.T) {
	sock := shortSockPath(t)
	var restarts atomic.Int32
	cfg := SupervisorConfig{
		BinaryPath:         os.Args[0],
		SocketPath:         sock,
		RulesDir:           "",
		StartTimeout:       3 * time.Second,
		MinRestartInterval: 50 * time.Millisecond,
		MaxRestartInterval: 200 * time.Millisecond,
		StableDuration:     50 * time.Millisecond,
		ClientTimeout:      2 * time.Second,
		Env:                helperEnv("crash-after-ping"),
		OnRestart: func(_ int, _ syscall.Signal, _ time.Duration) {
			restarts.Add(1)
		},
	}
	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sup.Stop() }()

	// RuleCount does a Ping; the helper crashes on the second ping (the
	// first was Start's readiness probe).
	_ = sup.RuleCount()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if restarts.Load() >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("supervisor did not restart after crash (OnRestart called %d times)", restarts.Load())
}

func TestSupervisorStartTimeoutOnHang(t *testing.T) {
	sock := shortSockPath(t)
	cfg := SupervisorConfig{
		BinaryPath:   os.Args[0],
		SocketPath:   sock,
		RulesDir:     "",
		StartTimeout: 200 * time.Millisecond,
		Env:          helperEnv("sleep-forever"),
	}
	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if err := sup.Start(context.Background()); err == nil {
		_ = sup.Stop()
		t.Fatal("expected Start to error on worker that never binds")
	}
}

func TestSupervisorScanBeforeStartReturnsEmpty(t *testing.T) {
	cfg := SupervisorConfig{BinaryPath: "/usr/bin/true", SocketPath: "/tmp/unused.sock"}
	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if got := sup.ScanFile("/tmp/x", 8192); got != nil {
		t.Errorf("ScanFile before Start: got %+v, want nil", got)
	}
	if got := sup.ScanBytes([]byte("x")); got != nil {
		t.Errorf("ScanBytes before Start: got %+v, want nil", got)
	}
	if n := sup.RuleCount(); n != 0 {
		t.Errorf("RuleCount before Start: got %d, want 0", n)
	}
}

func TestNewSupervisorRejectsEmptyBinaryPath(t *testing.T) {
	if _, err := NewSupervisor(SupervisorConfig{SocketPath: "/tmp/x.sock"}); err == nil {
		t.Error("expected error for empty BinaryPath")
	}
}

func TestNewSupervisorRejectsEmptySocketPath(t *testing.T) {
	if _, err := NewSupervisor(SupervisorConfig{BinaryPath: "/usr/bin/true"}); err == nil {
		t.Error("expected error for empty SocketPath")
	}
}
