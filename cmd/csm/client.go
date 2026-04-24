package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/control"
)

// controlDialTimeout caps how long we'll wait for the socket to accept
// a connection. Small: the daemon is local and either answers fast or
// isn't there at all.
const controlDialTimeout = 2 * time.Second

// controlReadTimeout is the default response ceiling for CLI commands
// that return promptly (status, reload, history queries). Short-ish so
// an operator stuck against a wedged daemon sees the failure quickly.
const controlReadTimeout = 5 * time.Minute

// controlReadTimeoutTierRun is the response ceiling for `csm run-*`
// commands. These are synchronous RPCs that drive the daemon's tier
// scanner over every account on the host; on large cPanel servers
// (hundreds of WordPress installs running through the plugin-cache
// refresh) the scan legitimately takes tens of minutes. A ceiling
// shorter than that made the hourly `csm-deep` systemd timer exit 1
// with "reading response: i/o timeout" every run even though the
// daemon was still scanning normally. The ceiling is deliberately
// well above the worst observed elapsed time so that steady-state
// success reports its result line rather than a phantom failure; it
// is not intended as a "wait for a deadlocked daemon" pathway (an
// operator who sees run-deep idle for an hour will ^C regardless).
const controlReadTimeoutTierRun = 60 * time.Minute

// controlSocketPath is the Unix socket to dial. In production it
// defaults to the daemon's well-known path; tests replace it with a
// temporary path to exercise the protocol without needing root.
var controlSocketPath = control.DefaultSocketPath

// errDaemonNotRunning is returned when dialing the control socket
// fails in a way that means "the daemon isn't listening." Callers
// translate this into the operator-visible "daemon not running" exit.
var errDaemonNotRunning = errors.New("daemon not running")

// sendControl dispatches cmd+args to the daemon with the default
// short-op read ceiling. Use sendControlWithTimeout for long-running
// tier scans.
func sendControl(cmd string, args any) (json.RawMessage, error) {
	return sendControlWithTimeout(cmd, args, controlReadTimeout)
}

// sendControlWithTimeout serialises cmd+args, dials the daemon, writes
// one request line, reads one response line, and returns the raw
// Result. readTimeout caps how long we wait for the response line; the
// caller decodes Result into whatever type the command promises.
//
// A missing socket or connection refused maps to errDaemonNotRunning
// so the caller can distinguish "daemon down" from protocol errors.
// Everything else is surfaced unchanged.
func sendControlWithTimeout(cmd string, args any, readTimeout time.Duration) (json.RawMessage, error) {
	var argsRaw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return nil, fmt.Errorf("encoding args: %w", err)
		}
		argsRaw = b
	}

	conn, err := net.DialTimeout("unix", controlSocketPath, controlDialTimeout)
	if err != nil {
		// File-not-found and connection-refused both mean "no live
		// listener on the other end." Anything else (permission
		// denied, timeout) we leave as-is for the operator to read.
		if errors.Is(err, os.ErrNotExist) {
			return nil, errDaemonNotRunning
		}
		if opErr, ok := err.(*net.OpError); ok && opErr.Err != nil {
			msg := opErr.Err.Error()
			if msg == "connect: connection refused" || msg == "connect: no such file or directory" {
				return nil, errDaemonNotRunning
			}
		}
		return nil, fmt.Errorf("connecting to daemon: %w", err)
	}
	defer func() { _ = conn.Close() }()

	req := control.Request{Cmd: cmd, Args: argsRaw}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding request: %w", err)
	}
	reqBytes = append(reqBytes, '\n')

	_ = conn.SetWriteDeadline(time.Now().Add(controlDialTimeout))
	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("writing request: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	scanner := bufio.NewScanner(conn)
	// Mirror the daemon-side buffer cap so paginated history and
	// dry-run tier-run findings fit without truncation. The socket is
	// root-only 0600 so the original 1 MiB DoS guard no longer
	// applies — cap at 16 MiB so large finding lists round-trip.
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading response: %w", err)
		}
		return nil, fmt.Errorf("empty response from daemon")
	}

	var resp control.Response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("daemon: %s", resp.Error)
	}
	return resp.Result, nil
}

// requireDaemon translates sendControl errors into a clean operator
// message and exits non-zero. Use this from CLI handlers that have no
// legitimate fallback (tier runs, status, reloads).
func requireDaemon(cmd string, args any) json.RawMessage {
	return requireDaemonWithTimeout(cmd, args, controlReadTimeout)
}

// requireDaemonWithTimeout is requireDaemon with an explicit response
// ceiling. Used by tier-run paths that legitimately exceed the default.
func requireDaemonWithTimeout(cmd string, args any, readTimeout time.Duration) json.RawMessage {
	result, err := sendControlWithTimeout(cmd, args, readTimeout)
	if err != nil {
		if errors.Is(err, errDaemonNotRunning) {
			fmt.Fprintln(os.Stderr, "csm: daemon not running (start with: systemctl start csm)")
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "csm: %v\n", err)
		os.Exit(1)
	}
	return result
}
