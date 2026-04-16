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

// controlReadTimeout caps a single command's response wait. Tier runs
// on large cPanel servers can take tens of seconds, so this must be
// comfortably longer than the worst expected scan time.
const controlReadTimeout = 5 * time.Minute

// errDaemonNotRunning is returned when dialing the control socket
// fails in a way that means "the daemon isn't listening." Callers
// translate this into the operator-visible "daemon not running" exit.
var errDaemonNotRunning = errors.New("daemon not running")

// sendControl serialises cmd+args, dials the daemon, writes one
// request line, reads one response line, and returns the raw Result.
// The caller decodes Result into whatever type the command promises.
//
// A missing socket or connection refused maps to errDaemonNotRunning
// so the caller can distinguish "daemon down" from protocol errors.
// Everything else is surfaced unchanged.
func sendControl(cmd string, args any) (json.RawMessage, error) {
	var argsRaw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return nil, fmt.Errorf("encoding args: %w", err)
		}
		argsRaw = b
	}

	conn, err := net.DialTimeout("unix", control.DefaultSocketPath, controlDialTimeout)
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

	_ = conn.SetReadDeadline(time.Now().Add(controlReadTimeout))
	scanner := bufio.NewScanner(conn)
	// Mirror the daemon-side buffer cap so paginated history responses
	// fit without truncation.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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
	result, err := sendControl(cmd, args)
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
