//go:build linux

package yaraipc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// sealHandler records the seals on the descriptor scan_fd received.
type sealHandler struct {
	fdHandler
	seals int
}

func (h *sealHandler) ScanFD(f *os.File, args ScanFDArgs) (ScanResult, error) {
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		return ScanResult{}, err
	}
	h.mu.Lock()
	h.seals = seals
	h.mu.Unlock()
	return h.fdHandler.ScanFD(f, args)
}

// Byte scans reach the worker as a sealed memfd: the worker can read the
// bytes but cannot change what the daemon goes on to report.
func TestScanBytesSendsSealedDescriptor(t *testing.T) {
	h := &sealHandler{}
	socket, shutdown := startServer(t, h)
	defer shutdown()
	data := []byte("payload bytes")
	c := NewClient(socket, 10*time.Second)
	defer func() { _ = c.Close() }()
	res, err := c.ScanBytes(data)
	if err != nil || len(res.Matches) != 1 {
		t.Fatalf("ScanBytes = %+v, %v", res, err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !bytes.Equal(h.data, data) || h.writable {
		t.Fatalf("worker read %q, writable=%v", h.data, h.writable)
	}
	if h.args.MaxBytes != len(data) || !h.args.EmptyRulesClean {
		t.Fatalf("args = %+v", h.args)
	}
	for _, seal := range []int{unix.F_SEAL_WRITE, unix.F_SEAL_GROW, unix.F_SEAL_SHRINK, unix.F_SEAL_SEAL} {
		if h.seals&seal == 0 {
			t.Fatalf("seals = %#x, missing %#x", h.seals, seal)
		}
	}
}

func TestScanBytesHasNoFrameCeiling(t *testing.T) {
	h := &fdHandler{}
	socket, shutdown := startServer(t, h)
	defer shutdown()
	data := bytes.Repeat([]byte("A"), 20<<20) // past the old inline limit
	c := NewClient(socket, 10*time.Second)
	defer func() { _ = c.Close() }()
	if _, err := c.ScanBytes(data); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.data) != len(data) || h.writable {
		t.Fatalf("handler read %d bytes, writable=%v", len(h.data), h.writable)
	}
}

func TestScanBytesFailsWhenMemfdUnavailable(t *testing.T) {
	prev := memfdCreate
	memfdCreate = func(string, int) (int, error) { return -1, unix.EMFILE }
	t.Cleanup(func() { memfdCreate = prev })
	var dials atomic.Int32
	c := NewClientWithDialer(func() (net.Conn, error) {
		dials.Add(1)
		return nil, fmt.Errorf("unexpected dial")
	}, time.Second)
	res, err := c.ScanBytes([]byte("payload"))
	if err == nil || res.Matches != nil {
		t.Fatalf("ScanBytes = %+v, %v", res, err)
	}
	if dials.Load() != 0 {
		t.Fatal("a scan without its memfd reached the worker")
	}
}

func TestScanBytesRetryResendsDescriptor(t *testing.T) {
	data := []byte("payload bytes")
	c := scanFDPeer(t, 2, func(i int, conn *net.UnixConn, fds []*os.File) error {
		seen, err := io.ReadAll(io.NewSectionReader(fds[0], 0, 1<<20))
		if err != nil || !bytes.Equal(seen, data) {
			return fmt.Errorf("attempt %d: read %q, %v", i, seen, err)
		}
		if i == 0 {
			return nil // drop the connection without a reply
		}
		return WriteFrame(conn, Frame{Payload: json.RawMessage(`{"matches":[{"rule":"hit"}]}`)})
	})
	res, err := c.ScanBytes(data)
	if err != nil || len(res.Matches) != 1 || res.Matches[0].RuleName != "hit" {
		t.Fatalf("retry = %+v, %v", res, err)
	}
}

func TestScanBytesRejectsEmptyData(t *testing.T) {
	c := NewClientWithDialer(func() (net.Conn, error) {
		t.Error("empty scan reached the worker")
		return nil, fmt.Errorf("unexpected dial")
	}, time.Second)
	if _, err := c.ScanBytes(nil); err == nil {
		t.Fatal("empty data accepted")
	}
}
