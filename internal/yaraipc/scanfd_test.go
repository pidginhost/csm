package yaraipc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/workerproc"
)

// fdHandler records what scan_fd gave it, and whether it could write
// through the descriptor.
type fdHandler struct {
	fakeHandler
	mu       sync.Mutex
	data     []byte
	args     ScanFDArgs
	writable bool
}

func (h *fdHandler) ScanFD(f *os.File, args ScanFDArgs) (ScanResult, error) {
	b, err := io.ReadAll(io.NewSectionReader(f, 0, int64(args.MaxBytes)))
	_, writeErr := f.WriteAt([]byte("w"), 0)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.data, h.args, h.writable = b, args, writeErr == nil
	return ScanResult{Matches: []Match{{RuleName: "seen"}}}, err
}

func tempPayload(t *testing.T, data []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "part")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestServerScanFDScansDescriptor(t *testing.T) {
	h := &fdHandler{}
	socket, shutdown := startServer(t, h)
	defer shutdown()
	payload := bytes.Repeat([]byte("x"), 20<<20) // past MaxScanBytes
	c := NewClient(socket, 10*time.Second)
	defer func() { _ = c.Close() }()
	res, err := c.ScanFD(tempPayload(t, payload), int64(len(payload)))
	if err != nil || len(res.Matches) != 1 {
		t.Fatalf("ScanFD = %+v, %v", res, err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.data) != len(payload) || h.args.MaxBytes != len(payload) {
		t.Fatalf("handler read %d bytes, args %+v", len(h.data), h.args)
	}
}

func rawRequest(t *testing.T, socket string, f Frame, fds []*os.File) Frame {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	uc := conn.(*net.UnixConn)
	if sendErr := workerproc.SendFrame(uc, workerproc.Frame{Op: f.Op, Payload: f.Payload}, fds, MaxFrameBytes); sendErr != nil {
		t.Fatal(sendErr)
	}
	resp, err := ReadFrame(uc)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestServerRefusesDescriptorOnOtherOps(t *testing.T) {
	socket, shutdown := startServer(t, &fdHandler{})
	defer shutdown()
	f := tempPayload(t, []byte("x"))
	for _, op := range []string{OpPing, OpScanFile, OpScanBytes, OpReload, "unknown"} {
		resp := rawRequest(t, socket, Frame{Op: op}, []*os.File{f})
		if resp.Error == "" || !strings.Contains(resp.Error, "descriptor") {
			t.Fatalf("%s with a descriptor: %+v", op, resp)
		}
		assertOnlySourceOpen(t, f)
	}
}

func assertOnlySourceOpen(t *testing.T, f *os.File) {
	t.Helper()
	want, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		st, err := os.Stat(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && os.SameFile(want, st) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d descriptors remain open for the part, want only the source", count)
	}
}

func TestServerScanFDRequiresOneRegularFile(t *testing.T) {
	socket, shutdown := startServer(t, &fdHandler{})
	defer shutdown()
	req, err := EncodePayload(OpScanFD, ScanFDArgs{MaxBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	if resp := rawRequest(t, socket, req, nil); resp.Error == "" {
		t.Fatal("scan_fd without a descriptor accepted")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if resp := rawRequest(t, socket, req, []*os.File{r}); resp.Error == "" {
		t.Fatal("scan_fd with a pipe accepted")
	}
}

func TestServerScanFDUnsupportedHandler(t *testing.T) {
	socket, shutdown := startServer(t, &fakeHandler{})
	defer shutdown()
	req, err := EncodePayload(OpScanFD, ScanFDArgs{MaxBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	f := tempPayload(t, []byte("x"))
	if resp := rawRequest(t, socket, req, []*os.File{f}); resp.Error == "" {
		t.Fatal("handler without ScanFD answered scan_fd")
	}
	assertOnlySourceOpen(t, f)
}

// The worker scans what the other engines scan next: it must not be able to
// rewrite the part, even when the daemon holds it open for writing.
func TestClientScanFDSendsReadOnlyDescriptor(t *testing.T) {
	h := &fdHandler{}
	socket, shutdown := startServer(t, h)
	defer shutdown()
	path := filepath.Join(t.TempDir(), "part")
	if err := os.WriteFile(path, []byte("part"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	c := NewClient(socket, 10*time.Second)
	defer func() { _ = c.Close() }()
	if _, err = c.ScanFD(f, 4); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.writable || string(h.data) != "part" {
		t.Fatalf("worker writable=%v, read %q", h.writable, h.data)
	}
	if got, _ := os.ReadFile(path); string(got) != "part" { // #nosec G304 -- test temp file
		t.Fatalf("part rewritten to %q", got)
	}
}

// A peer may die after accepting the descriptor, or send a malformed result.
func scanFDPeer(t *testing.T, requests int, reply func(int, *net.UnixConn, []*os.File) error) *Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "yfd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := range requests {
			conn, acceptErr := ln.AcceptUnix()
			if acceptErr != nil {
				done <- acceptErr
				return
			}
			handleErr := func() error {
				defer func() { _ = conn.Close() }()
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return err
				}
				req, fds, err := workerproc.ReceiveFrame(conn, workerproc.Limits{MaxFrameBytes: MaxFrameBytes, MaxFDs: 1})
				defer func() {
					for _, f := range fds {
						_ = f.Close()
					}
				}()
				if err != nil {
					return err
				}
				if req.Op != OpScanFD || len(fds) != 1 {
					return fmt.Errorf("request %d: op %q, descriptors %d", i, req.Op, len(fds))
				}
				return reply(i, conn, fds)
			}()
			if handleErr != nil {
				done <- handleErr
				return
			}
		}
		done <- nil
	}()
	c := NewClient(path, 5*time.Second)
	t.Cleanup(func() {
		_ = c.Close()
		_ = ln.Close()
		if err := <-done; err != nil {
			t.Errorf("peer: %v", err)
		}
	})
	return c
}

func TestClientScanFDRejectsMalformedReply(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame Frame
		fds   bool
	}{
		{"missing", Frame{}, false},
		{"null", Frame{Payload: json.RawMessage(`null`)}, false},
		{"null-matches", Frame{Payload: json.RawMessage(`{"matches":null}`)}, false},
		{"empty", Frame{Payload: json.RawMessage(`{}`)}, false},
		{"ping", Frame{Payload: json.RawMessage(`{"alive":true}`)}, false},
		{"unknown", Frame{Payload: json.RawMessage(`{"matches":[],"partial":true}`)}, false},
		{"wrong-type", Frame{Payload: json.RawMessage(`{"matches":false}`)}, false},
		{"request", Frame{Op: OpScanFD, Payload: json.RawMessage(`{"matches":[]}`)}, false},
		{"descriptor", Frame{Payload: json.RawMessage(`{"matches":[]}`)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := scanFDPeer(t, 1, func(_ int, conn *net.UnixConn, fds []*os.File) error {
				if !tc.fds {
					fds = nil
				}
				return workerproc.SendFrame(conn, workerproc.Frame{Op: tc.frame.Op, Payload: tc.frame.Payload}, fds, MaxFrameBytes)
			})
			if res, err := c.ScanFD(tempPayload(t, []byte("part")), 4); err == nil {
				t.Fatalf("malformed reply scanned clean: %+v", res)
			}
		})
	}
}

func TestClientScanFDRejectsInvalidSource(t *testing.T) {
	c := NewClientWithDialer(func() (net.Conn, error) {
		t.Error("invalid descriptor scan reached the worker")
		return nil, errors.New("unexpected dial")
	}, time.Second)
	defer func() { _ = c.Close() }()
	f := tempPayload(t, []byte("part"))
	for _, size := range []int64{-1, 0} {
		if _, err := c.ScanFD(f, size); err == nil {
			t.Errorf("size %d accepted", size)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []*os.File{nil, f} {
		if _, err := c.ScanFD(f, 4); err == nil {
			t.Error("unreadable source accepted")
		}
	}
}

func TestClientScanFDRetryResendsDescriptor(t *testing.T) {
	f := tempPayload(t, []byte("part"))
	if _, err := f.Seek(2, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	c := scanFDPeer(t, 2, func(i int, conn *net.UnixConn, fds []*os.File) error {
		var r io.Reader = io.NewSectionReader(fds[0], 0, 4)
		if i == 0 {
			r = fds[0] // Even an offset-changing worker cannot affect the daemon.
		}
		data, err := io.ReadAll(r)
		if err != nil || string(data) != "part" {
			return fmt.Errorf("attempt %d: read %q, %v", i, data, err)
		}
		if i == 0 {
			return nil
		}
		return WriteFrame(conn, Frame{Payload: json.RawMessage(`{"matches":[{"rule":"hit"}]}`)})
	})
	res, err := c.ScanFD(f, 4)
	if err != nil || len(res.Matches) != 1 || res.Matches[0].RuleName != "hit" {
		t.Fatalf("retry = %+v, %v", res, err)
	}
	if offset, err := f.Seek(0, io.SeekCurrent); err != nil || offset != 2 {
		t.Fatalf("daemon offset = %d, %v", offset, err)
	}
}

func TestClientScanFDDoesNotChangeCallerFlags(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	flags := func() int {
		rc, err := r.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var flags int
		var flagErr error
		if err := rc.Control(func(fd uintptr) {
			flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		}); err != nil || flagErr != nil {
			t.Fatalf("flags: %v, %v", err, flagErr)
		}
		return flags
	}
	before := flags()
	socket, stop := startServer(t, &fdHandler{})
	defer stop()
	c := NewClient(socket, 5*time.Second)
	defer func() { _ = c.Close() }()
	if _, err := c.ScanFD(r, 4); err == nil {
		t.Fatal("pipe must be refused")
	}
	if after := flags(); after != before {
		t.Fatalf("caller flags changed: %#x -> %#x", before, after)
	}
}

type closingFDHandler struct {
	fakeHandler
	file   *os.File
	panics bool
}

func (h *closingFDHandler) ScanFD(f *os.File, _ ScanFDArgs) (ScanResult, error) {
	h.file = f
	if h.panics {
		panic("scan failed")
	}
	return ScanResult{}, nil
}

func TestServerScanFDClosesAfterDispatch(t *testing.T) {
	for _, panics := range []bool{false, true} {
		h := &closingFDHandler{panics: panics}
		socket, stop := startServer(t, h)
		c := NewClient(socket, 5*time.Second)
		_, err := c.ScanFD(tempPayload(t, []byte("part")), 4)
		_ = c.Close()
		stop()
		if (err != nil) != panics {
			t.Errorf("panic %v: error %v", panics, err)
		}
		if h.file == nil {
			t.Fatal("handler never received a descriptor")
		}
		if _, err := h.file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("received descriptor still open after dispatch: %v", err)
		}
	}
}
