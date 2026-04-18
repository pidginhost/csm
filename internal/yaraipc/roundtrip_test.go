package yaraipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHandler records what the server-side saw and returns whatever the
// test prepared.
type fakeHandler struct {
	mu sync.Mutex

	scanFileArgs  []ScanFileArgs
	scanBytesArgs []ScanBytesArgs
	reloadArgs    []ReloadArgs
	pingCount     int

	scanFileRes  ScanResult
	scanBytesRes ScanResult
	reloadRes    ReloadResult
	pingRes      PingResult

	scanFileErr  error
	scanBytesErr error
	reloadErr    error
	pingErr      error
}

func (f *fakeHandler) ScanFile(a ScanFileArgs) (ScanResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scanFileArgs = append(f.scanFileArgs, a)
	return f.scanFileRes, f.scanFileErr
}

func (f *fakeHandler) ScanBytes(a ScanBytesArgs) (ScanResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scanBytesArgs = append(f.scanBytesArgs, a)
	return f.scanBytesRes, f.scanBytesErr
}

func (f *fakeHandler) Reload(a ReloadArgs) (ReloadResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloadArgs = append(f.reloadArgs, a)
	return f.reloadRes, f.reloadErr
}

func (f *fakeHandler) Ping() (PingResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pingCount++
	return f.pingRes, f.pingErr
}

// startServer brings up a real Unix-socket listener under t.TempDir so
// connection lifecycle (dial, EOF, reconnect) is exercised as it will be
// in production.
// startServer brings up a real Unix-socket listener so the dial/EOF/
// reconnect path is exercised the same way as in production. The socket
// lives under /tmp via a short os.MkdirTemp because macOS caps
// sun_path at 104 bytes and t.TempDir() paths (/var/folders/...) push
// right up against that limit once the test name is appended.
func startServer(t *testing.T, h Handler) (socketPath string, shutdown func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "y")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath = filepath.Join(dir, "w.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, ln, h, ServeOptions{})
	}()

	return socketPath, func() {
		cancel()
		_ = ln.Close()
		<-done
	}
}

func TestClientServerScanFile(t *testing.T) {
	h := &fakeHandler{
		scanFileRes: ScanResult{Matches: []Match{{RuleName: "webshell_generic"}}},
	}
	socketPath, stop := startServer(t, h)
	defer stop()

	c := NewClient(socketPath, 2*time.Second)
	defer func() { _ = c.Close() }()

	res, err := c.ScanFile(ScanFileArgs{Path: "/tmp/suspect.php", MaxBytes: 4096})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(res.Matches) != 1 || res.Matches[0].RuleName != "webshell_generic" {
		t.Errorf("matches: got %+v", res.Matches)
	}
	if len(h.scanFileArgs) != 1 {
		t.Fatalf("handler saw %d requests, want 1", len(h.scanFileArgs))
	}
	if h.scanFileArgs[0].Path != "/tmp/suspect.php" {
		t.Errorf("path: got %q want /tmp/suspect.php", h.scanFileArgs[0].Path)
	}
	if h.scanFileArgs[0].MaxBytes != 4096 {
		t.Errorf("max_bytes: got %d want 4096", h.scanFileArgs[0].MaxBytes)
	}
}

func TestClientServerScanBytes(t *testing.T) {
	h := &fakeHandler{}
	socketPath, stop := startServer(t, h)
	defer stop()

	c := NewClient(socketPath, 2*time.Second)
	defer func() { _ = c.Close() }()

	// Synthetic webshell-ish payload; we only care that it round-trips
	// byte-for-byte, not that any rule matches it.
	payload := []byte("<?php " + "ev" + "al($_POST['x']); ?>")
	if _, err := c.ScanBytes(ScanBytesArgs{Data: payload}); err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if len(h.scanBytesArgs) != 1 {
		t.Fatalf("handler saw %d requests, want 1", len(h.scanBytesArgs))
	}
	if string(h.scanBytesArgs[0].Data) != string(payload) {
		t.Errorf("payload mismatch")
	}
}

func TestClientServerReload(t *testing.T) {
	h := &fakeHandler{reloadRes: ReloadResult{RuleCount: 42}}
	socketPath, stop := startServer(t, h)
	defer stop()

	c := NewClient(socketPath, 2*time.Second)
	defer func() { _ = c.Close() }()

	res, err := c.Reload(ReloadArgs{RulesDir: "/opt/csm/rules"})
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if res.RuleCount != 42 {
		t.Errorf("rule_count: got %d want 42", res.RuleCount)
	}
	if len(h.reloadArgs) != 1 || h.reloadArgs[0].RulesDir != "/opt/csm/rules" {
		t.Errorf("reload args: got %+v", h.reloadArgs)
	}
}

func TestClientServerPing(t *testing.T) {
	h := &fakeHandler{pingRes: PingResult{Alive: true, RuleCount: 128}}
	socketPath, stop := startServer(t, h)
	defer stop()

	c := NewClient(socketPath, 2*time.Second)
	defer func() { _ = c.Close() }()

	res, err := c.Ping()
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !res.Alive || res.RuleCount != 128 {
		t.Errorf("ping result: got %+v", res)
	}
}

func TestClientSurfaceHandlerError(t *testing.T) {
	h := &fakeHandler{scanFileErr: errors.New("rules not loaded")}
	socketPath, stop := startServer(t, h)
	defer stop()

	c := NewClient(socketPath, 2*time.Second)
	defer func() { _ = c.Close() }()

	_, err := c.ScanFile(ScanFileArgs{Path: "/tmp/x"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "rules not loaded") {
		t.Errorf("error should surface handler message: %v", err)
	}
}

func TestClientReconnectsAfterServerClose(t *testing.T) {
	h := &fakeHandler{pingRes: PingResult{Alive: true}}
	socketPath, stop := startServer(t, h)

	c := NewClient(socketPath, 2*time.Second)
	defer func() { _ = c.Close() }()

	if _, err := c.Ping(); err != nil {
		t.Fatalf("first ping: %v", err)
	}

	// Kill the server; the client's cached conn is now stale.
	stop()

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("re-listen: %v", err)
	}
	h2 := &fakeHandler{pingRes: PingResult{Alive: true, RuleCount: 7}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, ln, h2, ServeOptions{})
	}()
	defer func() {
		cancel()
		_ = ln.Close()
		<-done
	}()

	// The first post-restart call may see the stale conn and error on
	// write. The retry after drop-and-redial must succeed; this is the
	// contract the supervisor relies on.
	var reconnectErr error
	for attempt := 0; attempt < 2; attempt++ {
		res, err := c.Ping()
		if err == nil {
			if res.RuleCount != 7 {
				t.Fatalf("post-reconnect ping: got rule_count=%d want 7", res.RuleCount)
			}
			return
		}
		reconnectErr = err
	}
	t.Fatalf("client did not recover after server restart: %v", reconnectErr)
}

func TestServerRejectsUnknownOp(t *testing.T) {
	h := &fakeHandler{}
	socketPath, stop := startServer(t, h)
	defer stop()

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if werr := WriteFrame(conn, Frame{Op: "totally_made_up"}); werr != nil {
		t.Fatalf("WriteFrame: %v", werr)
	}
	resp, err := ReadFrame(conn)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if resp.Error == "" {
		t.Fatal("expected error on unknown op")
	}
	if !strings.Contains(resp.Error, "unknown op") {
		t.Errorf("error should mention unknown op: %q", resp.Error)
	}
}
