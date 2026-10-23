package workerproc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := Frame{Op: "analyze", Payload: []byte(`{"source":"PD9waHA="}`)}
	if err := WriteFrame(&buf, want, 8<<20); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadFrame(&buf, 8<<20)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Op != want.Op || string(got.Payload) != string(want.Payload) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

type chunkWriter struct {
	bytes.Buffer
	max int
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.Buffer.Write(p)
}

func TestWriteFrameCompletesShortWrites(t *testing.T) {
	var wire chunkWriter
	wire.max = 2
	want := Frame{Op: "ping"}
	if err := WriteFrame(&wire, want, 8<<20); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadFrame(&wire.Buffer, 8<<20)
	if err != nil {
		t.Fatalf("read frame written in short chunks: %v", err)
	}
	if got.Op != want.Op {
		t.Fatalf("op = %q, want %q", got.Op, want.Op)
	}
}

// TestReadFrameRejectsOversizeHeaderWithoutAllocating is the one that matters
// for a hostile peer: the length prefix is attacker-influenced, so a frame
// claiming 4 GiB must be refused from the header alone. Allocating first and
// discovering the truth afterwards is how a peer turns a 4-byte write into an
// out-of-memory kill.
func TestReadFrameRejectsOversizeHeaderWithoutAllocating(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], ^uint32(0))
	_, err := ReadFrame(bytes.NewReader(hdr[:]), 8<<20)
	if err == nil {
		t.Fatal("oversize length prefix accepted, want error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want it to name the cap", err)
	}
}

func TestWriteFrameRejectsOversizeBody(t *testing.T) {
	big := Frame{Op: "analyze", Payload: make([]byte, 8<<20+1)}
	for i := range big.Payload {
		big.Payload[i] = 'a'
	}
	if err := WriteFrame(io.Discard, big, 8<<20); err == nil {
		t.Fatal("oversize body accepted, want error")
	}
}

func TestReadFrameOnTruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{Op: "ping"}, 8<<20); err != nil {
		t.Fatalf("write: %v", err)
	}
	truncated := buf.Bytes()[:buf.Len()-1]
	if _, err := ReadFrame(bytes.NewReader(truncated), 8<<20); err == nil {
		t.Fatal("truncated frame accepted, want error")
	}
}

func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "socketpair")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	a, b := conn(fds[0]), conn(fds[1])
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestSocketFrameCarriesDescriptorsBothWays(t *testing.T) {
	a, b := socketPair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if sendErr := SendFrame(a, Frame{Op: "x", Payload: json.RawMessage(`{"n":1}`)}, []*os.File{w}, 1<<20); sendErr != nil {
		t.Fatal(sendErr)
	}
	f, fds, err := ReceiveFrame(b, Limits{MaxFrameBytes: 1 << 20, MaxFDs: 1})
	if err != nil {
		t.Fatal(err)
	}
	if f.Op != "x" || string(f.Payload) != `{"n":1}` || len(fds) != 1 {
		t.Fatalf("frame=%+v fds=%d", f, len(fds))
	}
	defer fds[0].Close()
	flags, err := unix.FcntlInt(fds[0].Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("received descriptor not close-on-exec: flags=%d err=%v", flags, err)
	}
	if _, err := fds[0].Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("descriptor is not the pipe: %q %v", buf, err)
	}
}

func TestReceiveFrameRejectsTooManyDescriptorsAndClosesThem(t *testing.T) {
	a, b := socketPair(t)
	before := openFDs(t)
	files := make([]*os.File, 3)
	for i := range files {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		files[i] = w
	}
	before += 6
	if err := SendFrame(a, Frame{Op: "x"}, files, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, fds, err := ReceiveFrame(b, Limits{MaxFrameBytes: 1 << 20, MaxFDs: 2}); err == nil || fds != nil {
		t.Fatalf("over-limit descriptors accepted: fds=%d err=%v", len(fds), err)
	}
	assertNoFDLeak(t, before)
}

func TestReceiveFrameClosesDescriptorsOnBadFrame(t *testing.T) {
	a, b := socketPair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	before := openFDs(t)
	// A header declaring more than the cap, with a descriptor attached.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 1<<30)
	if _, _, err := a.WriteMsgUnix(hdr[:], syscall.UnixRights(int(w.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if _, fds, err := ReceiveFrame(b, Limits{MaxFrameBytes: 1 << 20, MaxFDs: 1}); err == nil || fds != nil {
		t.Fatalf("bad frame accepted: fds=%d err=%v", len(fds), err)
	}
	assertNoFDLeak(t, before)
}

func TestSocketFrameLargeBodyWithDescriptors(t *testing.T) {
	a, b := socketPair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	big := Frame{Op: "big", Payload: json.RawMessage(`"` + strings.Repeat("a", 4<<20) + `"`)}
	errc := make(chan error, 1)
	go func() {
		if sendErr := SendFrame(a, big, []*os.File{w}, 8<<20); sendErr != nil {
			errc <- sendErr
			return
		}
		errc <- SendFrame(a, Frame{Op: "next"}, nil, 8<<20)
	}()
	lim := Limits{MaxFrameBytes: 8 << 20, MaxFDs: 1}
	f, fds, err := ReceiveFrame(b, lim)
	if err != nil || f.Op != "big" || len(f.Payload) != len(big.Payload) || len(fds) != 1 {
		t.Fatalf("large frame: op=%q len=%d fds=%d err=%v", f.Op, len(f.Payload), len(fds), err)
	}
	fds[0].Close()
	f, fds, err = ReceiveFrame(b, lim)
	if err != nil || f.Op != "next" || len(fds) != 0 {
		t.Fatalf("stream lost framing after a large frame: op=%q fds=%d err=%v", f.Op, len(fds), err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestSendFrameRefusesMoreThanKernelLimit(t *testing.T) {
	a, _ := socketPair(t)
	files := make([]*os.File, 254)
	for i := range files {
		files[i] = os.Stdin
	}
	if err := SendFrame(a, Frame{Op: "x"}, files, 1<<20); err == nil {
		t.Fatal("254 descriptors accepted")
	}
}

// A sender attaches descriptors to a frame's first byte. Descriptors that
// arrive later in the frame come from a peer splitting one frame across many
// sendmsg calls to pile up descriptors past the cap.
func TestReceiveFrameRejectsDescriptorsAfterFirstRead(t *testing.T) {
	a, b := socketPair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	before := openFDs(t)
	body := []byte(`{"op":"x"}`)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := a.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.WriteMsgUnix(body[:1], syscall.UnixRights(int(w.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write(body[1:]); err != nil {
		t.Fatal(err)
	}
	if _, fds, err := ReceiveFrame(b, Limits{MaxFrameBytes: 1 << 20, MaxFDs: 1}); err == nil || fds != nil {
		t.Fatalf("mid-frame descriptor accepted: fds=%d err=%v", len(fds), err)
	}
	assertNoFDLeak(t, before)
}
