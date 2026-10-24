package yaraipc

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
	resp := rawRequest(t, socket, Frame{Op: OpPing}, []*os.File{tempPayload(t, []byte("x"))})
	if resp.Error == "" || !strings.Contains(resp.Error, "descriptor") {
		t.Fatalf("ping with a descriptor: %+v", resp)
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
	if resp := rawRequest(t, socket, req, []*os.File{tempPayload(t, []byte("x"))}); resp.Error == "" {
		t.Fatal("handler without ScanFD answered scan_fd")
	}
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
