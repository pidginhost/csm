package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/control"
)

// shortSockPath returns a unix socket path short enough to satisfy
// both macOS (~104 bytes) and Linux (~108 bytes) limits. t.TempDir()
// under macOS expands to a long /var/folders/... path that blows past
// that cap, so we seed a deterministic /tmp path scoped to the test
// and clean it up via t.Cleanup.
var sockCounter uint64

func shortSockPath(t *testing.T) string {
	t.Helper()
	n := atomic.AddUint64(&sockCounter, 1)
	p := filepath.Join(os.TempDir(), fmt.Sprintf("csm-client-%d-%d.sock", os.Getpid(), n))
	// Best-effort pre-cleanup for test re-runs.
	_ = os.Remove(p)
	t.Cleanup(func() { _ = os.Remove(p) })
	return p
}

// fakeDaemon listens on a temporary unix socket and invokes handle for
// each incoming request. The scanner and writer are line-oriented to
// match the daemon's real control protocol. The returned cleanup
// function shuts the listener down, restores controlSocketPath, and
// blocks until the accept loop AND every dispatched connection handler
// has exited -- so a parallel test that reuses the socket path cannot
// race with goroutines still holding the listener fd.
//
// Tests use this to exercise the client's timeout and error paths
// without depending on the live daemon socket or requiring root.
func fakeDaemon(t *testing.T, handle func(control.Request) control.Response) func() {
	t.Helper()

	sockPath := shortSockPath(t)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listening on %s: %v", sockPath, err)
	}

	savedPath := controlSocketPath
	controlSocketPath = sockPath

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				scanner := bufio.NewScanner(c)
				scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
				if !scanner.Scan() {
					return
				}
				var req control.Request
				if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
					return
				}
				resp := handle(req)
				b, err := json.Marshal(resp)
				if err != nil {
					return
				}
				b = append(b, '\n')
				_, _ = c.Write(b)
			}(conn)
		}
	}()

	return func() {
		_ = l.Close()
		wg.Wait()
		controlSocketPath = savedPath
	}
}

func TestSendControl_ReturnsDaemonOKResult(t *testing.T) {
	cleanup := fakeDaemon(t, func(req control.Request) control.Response {
		if req.Cmd != "status" {
			t.Errorf("daemon received unexpected cmd %q", req.Cmd)
		}
		return control.Response{OK: true, Result: json.RawMessage(`{"version":"x"}`)}
	})
	defer cleanup()

	result, err := sendControl("status", nil)
	if err != nil {
		t.Fatalf("sendControl: %v", err)
	}
	if string(result) != `{"version":"x"}` {
		t.Errorf("unexpected Result payload: %s", result)
	}
}

func TestSendControl_ReturnsDaemonError(t *testing.T) {
	cleanup := fakeDaemon(t, func(control.Request) control.Response {
		return control.Response{OK: false, Error: "boom"}
	})
	defer cleanup()

	_, err := sendControl("status", nil)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected daemon error surfaced, got %v", err)
	}
}

func TestSendControl_DaemonNotListening(t *testing.T) {
	saved := controlSocketPath
	controlSocketPath = shortSockPath(t) // path exists only as a string; no listener
	defer func() { controlSocketPath = saved }()

	_, err := sendControl("status", nil)
	if !errors.Is(err, errDaemonNotRunning) {
		t.Errorf("expected errDaemonNotRunning when socket missing, got %v", err)
	}
}

// The tier-run timeout is the reason this split exists. Verify the two
// code paths are wired to different ceilings: a default-timeout call
// must bail once the short deadline passes, while a tier-run call with
// a longer deadline to the same slow daemon must still succeed. Using
// 150 ms / 5 s keeps the test fast yet unambiguous about which timeout
// governed.
//
// This also pins the regression the whole fix is about: a deep-tier
// scan that takes longer than the default short-op ceiling must still
// return its result through the long-run CLI path.

func TestSendControlWithTimeout_ShortCeilingTimesOutOnSlowDaemon(t *testing.T) {
	cleanup := fakeDaemon(t, func(control.Request) control.Response {
		// Simulate a daemon that is busy scanning and does not respond
		// within the short-op window.
		time.Sleep(300 * time.Millisecond)
		return control.Response{OK: true, Result: json.RawMessage(`"late"`)}
	})
	defer cleanup()

	start := time.Now()
	_, err := sendControlWithTimeout("tier-run", nil, 150*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "reading response") {
		t.Errorf("expected 'reading response' error (socket read deadline), got %q", err)
	}
	// Bounds the deadline-honouring window; this is the behaviour
	// csm-deep.service was exhibiting against the production 5-min
	// ceiling. The narrow upper bound (elapsed < 290 ms) guarantees
	// we returned on the SHORT deadline, not the daemon's 300 ms sleep.
	if elapsed < 140*time.Millisecond || elapsed > 290*time.Millisecond {
		t.Errorf("elapsed=%v, expected near the short deadline (150ms)", elapsed)
	}
}

func TestSendControlWithTimeout_LongCeilingWaitsForResult(t *testing.T) {
	cleanup := fakeDaemon(t, func(control.Request) control.Response {
		// Simulates a deep-tier scan that runs beyond the default
		// short-op timeout. 300 ms > the prior 150 ms failure window.
		time.Sleep(300 * time.Millisecond)
		return control.Response{OK: true, Result: json.RawMessage(`"done"`)}
	})
	defer cleanup()

	result, err := sendControlWithTimeout("tier-run", nil, 5*time.Second)
	if err != nil {
		t.Fatalf("long-ceiling call should succeed, got %v", err)
	}
	if string(result) != `"done"` {
		t.Errorf("unexpected result %q", result)
	}
}

// Pin the constants themselves so a future edit that accidentally
// equalises the two timeouts (reintroducing the csm-deep regression)
// fails CI instead of silently shipping.
func TestControlReadTimeouts_TierRunIsMuchLongerThanDefault(t *testing.T) {
	if controlReadTimeoutTierRun <= controlReadTimeout {
		t.Fatalf("tier-run timeout (%v) must exceed default timeout (%v); "+
			"the default is for fast RPCs (status, reload), the tier-run "+
			"ceiling is the backstop for multi-minute deep scans",
			controlReadTimeoutTierRun, controlReadTimeout)
	}
	// Sanity: the tier-run ceiling must be long enough to accommodate a
	// deep scan on a 500-WP-install server (observed ~15-30 min). If a
	// future edit halves this to 15 min the regression could start
	// bleeding back in on peak-load servers.
	const minTierCeiling = 30 * time.Minute
	if controlReadTimeoutTierRun < minTierCeiling {
		t.Errorf("tier-run ceiling %v is below %v; observed deep scans "+
			"on large cPanel hosts reach 15-30 min, need headroom above "+
			"that", controlReadTimeoutTierRun, minTierCeiling)
	}
}
