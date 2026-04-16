package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
)

// controlSocketPath is the Unix socket the daemon binds for
// CLI-to-daemon IPC. Kept in sync with internal/control.DefaultSocketPath
// via a compile-time reference in NewControlListener.
const controlSocketPath = "/var/run/csm/control.sock"

// controlRequestTimeout caps how long a single client request can block
// the listener. Handlers that legitimately take longer (tier.run on a
// large server) run on the accepting goroutine, so the timeout applies
// to reading the request line and writing the response, not to the
// handler body itself.
const controlRequestTimeout = 2 * time.Second

// ControlListener serves the local command-line client over a Unix
// socket. One request and one response per connection, line-framed JSON.
// The daemon keeps exclusive ownership of the bbolt store; this listener
// is the only reason any CLI command needs to reach into daemon state.
type ControlListener struct {
	d        *Daemon
	listener net.Listener
}

// NewControlListener creates the socket, enforces 0600 perms, and
// returns a listener that the daemon wires into its goroutine pool.
func NewControlListener(d *Daemon) (*ControlListener, error) {
	socketDir := filepath.Dir(controlSocketPath)
	if err := os.MkdirAll(socketDir, 0750); err != nil {
		return nil, fmt.Errorf("creating socket dir: %w", err)
	}

	// Stale socket from a previous crash would make Listen fail with
	// EADDRINUSE. Remove before binding; the file is process-owned.
	_ = os.Remove(controlSocketPath)

	ln, err := net.Listen("unix", controlSocketPath)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", controlSocketPath, err)
	}

	// 0600 root-only: the CLI client also runs as root (fanotify,
	// nftables, cpanel APIs all require it), so no group is needed.
	if err := os.Chmod(controlSocketPath, 0600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}

	return &ControlListener{d: d, listener: ln}, nil
}

// Run accepts connections until stopCh closes. Each connection is
// handled on its own goroutine so a slow request never stalls the
// accept loop.
func (c *ControlListener) Run(stopCh <-chan struct{}) {
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
				csmlog.Warn("control listener accept error", "err", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		go c.handleConnection(conn)
	}
}

// Stop closes the listener and removes the socket file. Safe to call
// after Run has already returned.
func (c *ControlListener) Stop() {
	_ = c.listener.Close()
	_ = os.Remove(controlSocketPath)
}

// handleConnection reads one request, dispatches it, writes one
// response, and closes. The short timeout applies to I/O only; the
// handler itself can take as long as the underlying work requires.
func (c *ControlListener) handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Read deadline. Writes use a separate deadline set after the
	// handler returns so slow scans don't count against the reader.
	_ = conn.SetReadDeadline(time.Now().Add(controlRequestTimeout))

	scanner := bufio.NewScanner(conn)
	// Requests are single-line JSON but can carry larger Args payloads
	// once baseline/history paging enters the command set. 1 MiB is
	// well above any request we expect and well below any DoS concern
	// on a root-only socket.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	if !scanner.Scan() {
		return
	}
	line := scanner.Bytes()

	resp := c.dispatch(line)
	payload, err := json.Marshal(resp)
	if err != nil {
		// Marshalling a Response should not fail; if it does, fall back
		// to a minimal error response the client can still parse.
		payload = []byte(`{"ok":false,"error":"internal: response marshal failed"}`)
	}
	payload = append(payload, '\n')

	_ = conn.SetWriteDeadline(time.Now().Add(controlRequestTimeout))
	_, _ = conn.Write(payload)
}
