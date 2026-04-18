package yaraipc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ErrWorkerClosed means the worker hung up mid-request. The daemon-side
// supervisor is expected to restart the worker; the client will dial
// again on the next call.
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

// roundTrip sends req and returns the response frame. On I/O error or
// EOF the connection is dropped so the next call reconnects.
func (c *Client) roundTrip(req Frame) (Frame, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := c.ensureConnLocked()
	if err != nil {
		return Frame{}, err
	}
	if c.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}
	if werr := WriteFrame(conn, req); werr != nil {
		_ = c.dropLocked()
		return Frame{}, fmt.Errorf("yaraipc: write: %w", werr)
	}
	resp, rerr := ReadFrame(conn)
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

// ScanFile is the daemon-side shim for OpScanFile.
func (c *Client) ScanFile(args ScanFileArgs) (ScanResult, error) {
	req, err := EncodePayload(OpScanFile, args)
	if err != nil {
		return ScanResult{}, err
	}
	resp, err := c.roundTrip(req)
	if err != nil {
		return ScanResult{}, err
	}
	var res ScanResult
	if len(resp.Payload) > 0 {
		if err := DecodePayload(resp, &res); err != nil {
			return ScanResult{}, err
		}
	}
	return res, nil
}

// ScanBytes is the daemon-side shim for OpScanBytes.
func (c *Client) ScanBytes(args ScanBytesArgs) (ScanResult, error) {
	req, err := EncodePayload(OpScanBytes, args)
	if err != nil {
		return ScanResult{}, err
	}
	resp, err := c.roundTrip(req)
	if err != nil {
		return ScanResult{}, err
	}
	var res ScanResult
	if len(resp.Payload) > 0 {
		if err := DecodePayload(resp, &res); err != nil {
			return ScanResult{}, err
		}
	}
	return res, nil
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
