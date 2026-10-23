//go:build linux && kernelintegration

package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	unitHelperOps["probe"] = probeOp
	unitHelperOps["alloc"] = allocOp
	unitHelperOps["fsize"] = fsizeOp
}

type probeResult struct {
	UID                              int
	INET, INET6, Home, Shadow, Spool string
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func probeOp(json.RawMessage) Frame {
	r := probeResult{UID: os.Getuid()}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	r.INET = errText(err)
	fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	r.INET6 = errText(err)
	_, err = os.ReadDir("/home")
	r.Home = errText(err)
	f, err := os.Open("/etc/shadow")
	if err == nil {
		_ = f.Close()
	}
	r.Shadow = errText(err)
	_, err = os.ReadDir("/var/spool/exim/input")
	r.Spool = errText(err)
	out, _ := json.Marshal(r)
	return Frame{Payload: out}
}

// allocOp allocates the payload's MiB and touches every page.
func allocOp(payload json.RawMessage) Frame {
	var mib int
	if err := json.Unmarshal(payload, &mib); err != nil {
		return Frame{Error: err.Error()}
	}
	b := make([]byte, mib<<20)
	for i := 0; i < len(b); i += 4096 {
		b[i] = 1
	}
	runtime.KeepAlive(b)
	return Frame{Payload: json.RawMessage(`{}`)}
}

// fsizeOp writes 2 MiB into a memfd and reports the write error.
func fsizeOp(json.RawMessage) Frame {
	fd, err := unix.MemfdCreate("fsize", unix.MFD_CLOEXEC)
	if err != nil {
		return Frame{Error: err.Error()}
	}
	f := os.NewFile(uintptr(fd), "fsize")
	defer f.Close()
	_, err = f.Write(make([]byte, 2<<20))
	out, _ := json.Marshal(map[string]string{"error": errText(err)})
	return Frame{Payload: out}
}

// kernelUnitConfig runs a copy of this test binary as a real transient unit.
// The copy lives under /var/lib: PrivateTmp hides /tmp from the unit, and the
// dynamic user must be able to traverse to it.
func kernelUnitConfig(t *testing.T, memory, fsize uint64) UnitConfig {
	t.Helper()
	if os.Getuid() != 0 {
		t.Fatal("kernel unit tests need root under systemd")
	}
	dir, err := os.MkdirTemp("/var/lib", "csm-workerproc-ktest-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if chmodErr := os.Chmod(dir, 0o755); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	bin := filepath.Join(dir, "workerproc.test")
	src, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(bin, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = StopUnits(ctx, "csm-parse-worker-ktest-")
	})
	return UnitConfig{
		Prefix:        "csm-parse-worker-ktest",
		Command:       bin,
		Args:          []string{unitHelperArg, "1"},
		MemoryLimit:   memory,
		FileSizeLimit: fsize,
		RuntimeMax:    10 * time.Minute,
		StartTimeout:  10 * time.Second,
		Protocol:      1,
		Limits:        Limits{MaxFrameBytes: 1 << 20, MaxFDs: 1},
		Log:           func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	}
}

func kernelSupervisor(t *testing.T, cfg UnitConfig) *Supervisor {
	t.Helper()
	s, err := New(Config{Name: "unit worker", Launch: UnitLauncher(cfg), Timeout: 30 * time.Second, Limits: cfg.Limits})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

func callInto(t *testing.T, s *Supervisor, op string, payload string, out any) error {
	t.Helper()
	_, _, err := s.Call(context.Background(), Frame{Op: op, Payload: json.RawMessage(payload)}, nil, func(reply Frame, _ []*os.File) (bool, error) {
		if out == nil {
			return false, nil
		}
		return false, json.Unmarshal(reply.Payload, out)
	})
	return err
}

func TestKernelUnitLauncherLockdown(t *testing.T) {
	cfg := kernelUnitConfig(t, 128<<20, 1<<20)
	if _, err := os.Stat("/var/spool/exim/input"); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll("/var/spool/exim/input", 0o750); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove("/var/spool/exim/input") })
	}
	s := kernelSupervisor(t, cfg)
	var r probeResult
	if err := callInto(t, s, "probe", `{}`, &r); err != nil {
		t.Fatal(err)
	}
	if r.UID == 0 {
		t.Fatal("worker runs as root")
	}
	if !strings.Contains(r.INET, "address family not supported") || r.INET6 == "" {
		t.Fatalf("network sockets: inet %q inet6 %q", r.INET, r.INET6)
	}
	if r.Home == "" || r.Shadow == "" || r.Spool == "" {
		t.Fatalf("file access: %+v", r)
	}
	var w struct{ Error string }
	if err := callInto(t, s, "fsize", `{}`, &w); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.Error, "file too large") {
		t.Fatalf("memfd write past LimitFSIZE: %q", w.Error)
	}
	if err := callInto(t, s, "probe", `{}`, &r); err != nil {
		t.Fatalf("worker did not survive EFBIG: %v", err)
	}
}

func TestKernelStopUnitsKillsLeftovers(t *testing.T) {
	cfg := kernelUnitConfig(t, 128<<20, 1<<20)
	p, err := UnitLauncher(cfg)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Conn().Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := StopUnits(ctx, "csm-parse-worker-ktest-"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("unit still running after StopUnits")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		out, err := exec.Command("systemctl", "list-units", "--all", "--plain", "--no-legend", "csm-parse-worker-ktest*").Output()
		if err == nil && strings.TrimSpace(string(out)) == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("units left: %s %v", out, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
