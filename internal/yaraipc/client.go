package yaraipc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/workerproc"
)

// ErrWorkerClosed means the worker hung up mid-request.
var ErrWorkerClosed = errors.New("yaraipc: worker connection closed")

// Dialer returns a fresh net.Conn to the worker. Decoupled from
// net.Dial so tests can substitute net.Pipe.
type Dialer func() (net.Conn, error)

// Client is a persistent-connection client. One in-flight request at a
// time: scanner callers do not need concurrency on a single socket and
// serialising simplifies failure semantics.
type Client struct {
	mu      sync.Mutex
	conn    net.Conn
	dialer  Dialer
	timeout time.Duration
}

// NewClient constructs a Client that dials socketPath on demand.
func NewClient(socketPath string, timeout time.Duration) *Client {
	return NewClientWithDialer(func() (net.Conn, error) {
		return net.DialTimeout("unix", socketPath, timeout)
	}, timeout)
}

// NewClientWithDialer is the test-friendly constructor.
func NewClientWithDialer(d Dialer, timeout time.Duration) *Client {
	return &Client{dialer: d, timeout: timeout}
}

// Close drops the underlying connection if any. The Client stays usable;
// the next call dials again.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropLocked()
}

func (c *Client) ensureConnLocked() (net.Conn, error) {
	if c.conn != nil {
		return c.conn, nil
	}
	conn, err := c.dialer()
	if err != nil {
		return nil, fmt.Errorf("yaraipc: dial: %w", err)
	}
	c.conn = conn
	return conn, nil
}

func (c *Client) dropLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// roundTrip sends req and returns the response frame. A closed socket is
// retried once because the server may intentionally close idle
// connections after their message budget is spent.
func (c *Client) roundTrip(req Frame) (Frame, error) {
	return c.roundTripFDs(req, nil)
}

// roundTripFDs is roundTrip with descriptors attached. A retry resends the
// same descriptors, which the caller still owns.
func (c *Client) roundTripFDs(req Frame, fds []*os.File) (Frame, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.roundTripLocked(req, fds)
	if err == nil || !isRetryableClosedConn(err) {
		return resp, err
	}
	return c.roundTripLocked(req, fds)
}

func (c *Client) roundTripLocked(req Frame, fds []*os.File) (Frame, error) {
	conn, err := c.ensureConnLocked()
	if err != nil {
		return Frame{}, err
	}
	if c.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}
	if werr := writeRequest(conn, req, fds); werr != nil {
		_ = c.dropLocked()
		return Frame{}, fmt.Errorf("yaraipc: write: %w", werr)
	}
	var resp Frame
	var rerr error
	if req.Op == OpScanFD {
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			return Frame{}, errors.New("yaraipc: descriptors need a Unix socket")
		}
		var wf workerproc.Frame
		wf, _, rerr = workerproc.ReceiveFrame(uc, workerproc.Limits{MaxFrameBytes: MaxFrameBytes})
		resp = Frame{Op: wf.Op, Payload: wf.Payload, Error: wf.Error}
	} else {
		resp, rerr = ReadFrame(conn)
	}
	if rerr != nil {
		_ = c.dropLocked()
		if errors.Is(rerr, io.EOF) {
			return Frame{}, ErrWorkerClosed
		}
		return Frame{}, fmt.Errorf("yaraipc: read: %w", rerr)
	}
	if resp.Error != "" {
		return Frame{}, fmt.Errorf("yaraipc: worker: %s", resp.Error)
	}
	return resp, nil
}

func writeRequest(conn net.Conn, req Frame, fds []*os.File) error {
	if len(fds) == 0 {
		return WriteFrame(conn, req)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("yaraipc: descriptors need a Unix socket")
	}
	return workerproc.SendFrame(uc, workerproc.Frame{Op: req.Op, Payload: req.Payload}, fds, MaxFrameBytes)
}

// ScanFD is the daemon-side shim for OpScanFD: the worker scans the first
// size bytes of f, read through the descriptor. The worker gets its own
// read-only open of f, so it cannot rewrite what the other engines scan.
func (c *Client) ScanFD(f *os.File, size int64) (ScanResult, error) {
	if size <= 0 || size > int64(int(^uint(0)>>1)) {
		return ScanResult{}, fmt.Errorf("yaraipc: invalid descriptor scan size: %d", size)
	}
	// #nosec G115 -- size was checked against the native int range above.
	req, err := EncodePayload(OpScanFD, ScanFDArgs{MaxBytes: int(size)})
	if err != nil {
		return ScanResult{}, err
	}
	ro, err := ReopenReadOnly(f)
	if err != nil {
		return ScanResult{}, fmt.Errorf("yaraipc: reopen part read-only: %w", err)
	}
	defer func() { _ = ro.Close() }()
	resp, err := c.roundTripFDs(req, []*os.File{ro})
	if err != nil {
		return ScanResult{}, err
	}
	return decodeScanFDResult(resp)
}

func decodeScanFDResult(resp Frame) (ScanResult, error) {
	if resp.Op != "" {
		return ScanResult{}, errors.New("yaraipc: invalid scan_fd reply")
	}
	matches, err := DecodeScanReply(resp.Payload)
	if err != nil {
		return ScanResult{}, err
	}
	return ScanResult{Matches: matches}, nil
}

func isRetryableClosedConn(err error) bool {
	return errors.Is(err, ErrWorkerClosed) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED)
}

// ScanBytes scans data the daemon already holds. The bytes travel as a
// sealed memfd over scan_fd, so no frame size limits them and the worker
// cannot change what it was given. Callers must treat any error as "could
// not scan", never as clean.
func (c *Client) ScanBytes(data []byte) (ScanResult, error) {
	if len(data) == 0 {
		return ScanResult{}, errors.New("yaraipc: empty byte scan")
	}
	req, err := EncodePayload(OpScanFD, ScanFDArgs{MaxBytes: len(data), EmptyRulesClean: true})
	if err != nil {
		return ScanResult{}, err
	}
	f, err := SealedMemfd("csm-yara-scan", data)
	if err != nil {
		return ScanResult{}, err
	}
	defer func() { _ = f.Close() }()
	resp, err := c.roundTripFDs(req, []*os.File{f})
	if err != nil {
		return ScanResult{}, err
	}
	return decodeScanFDResult(resp)
}

// Reload is the daemon-side shim for OpReload.
func (c *Client) Reload(args ReloadArgs) (ReloadResult, error) {
	req, err := EncodePayload(OpReload, args)
	if err != nil {
		return ReloadResult{}, err
	}
	resp, err := c.roundTrip(req)
	if err != nil {
		return ReloadResult{}, err
	}
	var res ReloadResult
	if len(resp.Payload) > 0 {
		if err := DecodePayload(resp, &res); err != nil {
			return ReloadResult{}, err
		}
	}
	return res, nil
}

// Ping is the daemon-side shim for OpPing.
func (c *Client) Ping() (PingResult, error) {
	req, err := EncodePayload(OpPing, nil)
	if err != nil {
		return PingResult{}, err
	}
	resp, err := c.roundTrip(req)
	if err != nil {
		return PingResult{}, err
	}
	var res PingResult
	if len(resp.Payload) > 0 {
		if err := DecodePayload(resp, &res); err != nil {
			return PingResult{}, err
		}
	}
	return res, nil
}
