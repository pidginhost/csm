package yaraipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Handler is the worker-side interface. The production implementation
// wraps internal/yara; tests supply fakes to drive the Serve loop.
type Handler interface {
	ScanFile(ScanFileArgs) (ScanResult, error)
	ScanBytes(ScanBytesArgs) (ScanResult, error)
	Reload(ReloadArgs) (ReloadResult, error)
	Ping() (PingResult, error)
}

// ServeOptions tunes Serve's behaviour. ErrorLog is called for per-frame
// decode or transport errors. Nil is fine; these errors are not fatal to
// the worker process.
type ServeOptions struct {
	ErrorLog func(error)
}

// Serve accepts connections on ln and dispatches frames to h until ctx
// is cancelled or ln returns an error. Per-connection goroutines are
// spawned; each handles its connection serially (single in-flight
// request), which matches the daemon-side client and keeps failure
// semantics simple.
//
// On ctx cancellation Serve closes the listener and any active
// connections. Without this, clients holding a cached conn would keep
// talking to a zombie handler instead of seeing EOF and reconnecting
// to whatever replaces the worker. In production that "zombie" is a
// crashed process (the kernel closes its sockets), but in-process
// tests and a graceful SIGTERM shutdown both need the explicit close.
func Serve(ctx context.Context, ln net.Listener, h Handler, opts ServeOptions) error {
	var (
		mu      sync.Mutex
		active  = map[net.Conn]struct{}{}
		closed  bool
		servers sync.WaitGroup
	)

	closeAll := func() {
		mu.Lock()
		if closed {
			mu.Unlock()
			return
		}
		closed = true
		conns := make([]net.Conn, 0, len(active))
		for c := range active {
			conns = append(conns, c)
		}
		mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		closeAll()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				servers.Wait()
				// Accept error after ctx cancellation is the expected
				// shutdown path (ln.Close from the watcher goroutine);
				// swallowing it here keeps Serve callers from needing to
				// distinguish "clean stop" from "real failure".
				return nil //nolint:nilerr
			}
			closeAll()
			servers.Wait()
			return fmt.Errorf("yaraipc: accept: %w", err)
		}
		mu.Lock()
		if closed {
			mu.Unlock()
			_ = conn.Close()
			continue
		}
		active[conn] = struct{}{}
		mu.Unlock()
		servers.Add(1)
		go func(c net.Conn) {
			defer servers.Done()
			serveConn(c, h, opts)
			mu.Lock()
			delete(active, c)
			mu.Unlock()
		}(conn)
	}
}

func serveConn(conn net.Conn, h Handler, opts ServeOptions) {
	defer func() { _ = conn.Close() }()
	for {
		req, err := ReadFrame(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			if opts.ErrorLog != nil {
				opts.ErrorLog(fmt.Errorf("read: %w", err))
			}
			return
		}
		resp := dispatch(req, h)
		if err := WriteFrame(conn, resp); err != nil {
			if opts.ErrorLog != nil {
				opts.ErrorLog(fmt.Errorf("write: %w", err))
			}
			return
		}
	}
}

func dispatch(req Frame, h Handler) Frame {
	switch req.Op {
	case OpScanFile:
		var args ScanFileArgs
		if err := DecodePayload(req, &args); err != nil {
			return Frame{Error: fmt.Sprintf("decode scan_file: %v", err)}
		}
		res, err := h.ScanFile(args)
		return responseFrame(res, err)
	case OpScanBytes:
		var args ScanBytesArgs
		if err := DecodePayload(req, &args); err != nil {
			return Frame{Error: fmt.Sprintf("decode scan_bytes: %v", err)}
		}
		res, err := h.ScanBytes(args)
		return responseFrame(res, err)
	case OpReload:
		// Reload payload is optional; an empty frame means reuse the
		// worker's startup RulesDir.
		var args ReloadArgs
		if len(req.Payload) > 0 {
			if err := DecodePayload(req, &args); err != nil {
				return Frame{Error: fmt.Sprintf("decode reload: %v", err)}
			}
		}
		res, err := h.Reload(args)
		return responseFrame(res, err)
	case OpPing:
		res, err := h.Ping()
		return responseFrame(res, err)
	default:
		return Frame{Error: fmt.Sprintf("yaraipc: unknown op %q", req.Op)}
	}
}

func responseFrame(result any, err error) Frame {
	if err != nil {
		return Frame{Error: err.Error()}
	}
	f, encErr := EncodePayload("", result)
	if encErr != nil {
		return Frame{Error: encErr.Error()}
	}
	return f
}
