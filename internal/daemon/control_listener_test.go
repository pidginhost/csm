package daemon

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/state"
)

// redirectControlSocket swaps the package-level socket path to a
// per-test location and restores the production default on cleanup.
// Uses os.MkdirTemp("/tmp", ...) rather than t.TempDir() because
// macOS caps sun_path at 104 bytes and /var/folders/... overflows
// (same workaround as internal/yaraipc/roundtrip_test.go).
func redirectControlSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "csmctl")
	if err != nil {
		t.Fatalf("mkdir temp socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	prev := controlSocketPath
	controlSocketPath = filepath.Join(dir, "c.sock")
	t.Cleanup(func() { controlSocketPath = prev })
	return controlSocketPath
}

// newDaemonForListener is the minimal Daemon needed by dispatch() via
// the Unix-socket code path. Mirrors newListenerForTest but is reused by
// the listener-level tests that exercise NewControlListener/Run/Stop.
func newDaemonForListener(t *testing.T) *Daemon {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	d := &Daemon{
		cfg:       &config.Config{},
		store:     st,
		alertCh:   make(chan alert.Finding, 8),
		version:   "test",
		startTime: time.Now().Add(-30 * time.Second),
	}
	config.SetActive(d.cfg)
	t.Cleanup(func() { config.SetActive(nil) })
	return d
}

// roundtrip dials the socket, sends one line-framed request, reads one
// line of response, and returns the decoded envelope.
func roundtrip(t *testing.T, sock string, req control.Request) control.Response {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial %s: %v", sock, err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	line, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	line = append(line, '\n')
	if _, wErr := conn.Write(line); wErr != nil {
		t.Fatalf("write: %v", wErr)
	}

	rd := bufio.NewReader(conn)
	data, err := rd.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp control.Response
	if uErr := json.Unmarshal(data, &resp); uErr != nil {
		t.Fatalf("decode response %q: %v", data, uErr)
	}
	return resp
}

// --- NewControlListener -----------------------------------------------

func TestNewControlListenerBindsAndChmods(t *testing.T) {
	sock := redirectControlSocket(t)
	d := newDaemonForListener(t)

	cl, err := NewControlListener(d)
	if err != nil {
		t.Fatalf("NewControlListener: %v", err)
	}
	defer cl.Stop()

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("socket missing after NewControlListener: %v", err)
	}
	// The socket must be chmod 0600; anything more permissive would
	// let a non-root user on the same host drive the daemon.
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("socket perm: got %o, want 0600", mode)
	}
}

// A crashed daemon leaves the socket file on disk. The next
// NewControlListener must remove it before binding, not fail with
// EADDRINUSE.
func TestNewControlListenerClearsStaleSocket(t *testing.T) {
	sock := redirectControlSocket(t)
	// Seed a stale file at the socket path.
	if err := os.WriteFile(sock, []byte("stale"), 0600); err != nil {
		t.Fatalf("seed stale socket: %v", err)
	}
	d := newDaemonForListener(t)

	cl, err := NewControlListener(d)
	if err != nil {
		t.Fatalf("NewControlListener with stale socket: %v", err)
	}
	defer cl.Stop()

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("socket missing: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Errorf("expected a Unix socket at %s, got mode %v", sock, info.Mode())
	}
}

// --- Run + handleConnection end-to-end --------------------------------

func TestControlListenerRunHandlesStatusRequest(t *testing.T) {
	redirectControlSocket(t)
	d := newDaemonForListener(t)
	cl, err := NewControlListener(d)
	if err != nil {
		t.Fatalf("NewControlListener: %v", err)
	}
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		cl.Run(stopCh)
		close(done)
	}()
	defer func() {
		close(stopCh)
		cl.Stop()
		<-done
	}()

	resp := roundtrip(t, controlSocketPath, control.Request{Cmd: control.CmdStatus})
	if !resp.OK {
		t.Fatalf("status roundtrip failed: %q", resp.Error)
	}
	var status control.StatusResult
	if err := json.Unmarshal(resp.Result, &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.Version != "test" {
		t.Errorf("version: got %q", status.Version)
	}
}

func TestControlListenerRunRejectsUnknownCommand(t *testing.T) {
	redirectControlSocket(t)
	d := newDaemonForListener(t)
	cl, err := NewControlListener(d)
	if err != nil {
		t.Fatalf("NewControlListener: %v", err)
	}
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		cl.Run(stopCh)
		close(done)
	}()
	defer func() {
		close(stopCh)
		cl.Stop()
		<-done
	}()

	resp := roundtrip(t, controlSocketPath, control.Request{Cmd: "does.not.exist"})
	if resp.OK {
		t.Fatal("unknown command must surface OK=false")
	}
	if !strings.Contains(resp.Error, "unknown command") {
		t.Errorf("error text: %q", resp.Error)
	}
}

// Malformed JSON (no trailing newline, truncated) must produce a
// parseable error response — the bufio scanner delivers a full line
// when the socket is closed, and dispatch's JSON error path kicks in.
func TestControlListenerRunHandlesMalformedLine(t *testing.T) {
	sock := redirectControlSocket(t)
	d := newDaemonForListener(t)
	cl, err := NewControlListener(d)
	if err != nil {
		t.Fatalf("NewControlListener: %v", err)
	}
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		cl.Run(stopCh)
		close(done)
	}()
	defer func() {
		close(stopCh)
		cl.Stop()
		<-done
	}()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, wErr := conn.Write([]byte("{not json\n")); wErr != nil {
		t.Fatalf("write: %v", wErr)
	}
	rd := bufio.NewReader(conn)
	data, err := rd.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp control.Response
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("decode response %q: %v", data, err)
	}
	if resp.OK {
		t.Fatal("malformed request must surface OK=false")
	}
	if !strings.Contains(resp.Error, "bad request") {
		t.Errorf("error text: %q", resp.Error)
	}
}

// --- Stop -------------------------------------------------------------

func TestControlListenerStopIsIdempotent(t *testing.T) {
	redirectControlSocket(t)
	d := newDaemonForListener(t)
	cl, err := NewControlListener(d)
	if err != nil {
		t.Fatalf("NewControlListener: %v", err)
	}
	cl.Stop()
	// Second Stop must not panic; both listener.Close and os.Remove
	// are wrapped so idempotency is an explicit contract.
	cl.Stop()
}

// After Stop, the accept loop must return immediately on the next
// accept error (listener closed) rather than busy-looping. Verified
// by Run returning within a bounded time after Stop.
func TestControlListenerRunExitsAfterStop(t *testing.T) {
	redirectControlSocket(t)
	d := newDaemonForListener(t)
	cl, err := NewControlListener(d)
	if err != nil {
		t.Fatalf("NewControlListener: %v", err)
	}
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		cl.Run(stopCh)
		close(done)
	}()
	close(stopCh)
	cl.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return within 1s of Stop")
	}
}
