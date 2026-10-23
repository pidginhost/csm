package workerproc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

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
	big := Frame{Op: "analyze", Payload: json.RawMessage(`"` + strings.Repeat("a", 8<<20) + `"`)}
	if err := WriteFrame(io.Discard, big, 8<<20); err == nil || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("oversize body: got %v, want cap error", err)
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
	fds, err := socketpair()
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
	for _, c := range []*net.UnixConn{a, b} {
		if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
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

func TestReceiveFrameClosesDescriptorsOnIncompleteOrInvalidFrame(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{name: "partial header", wire: []byte{0, 0}},
		{name: "partial body", wire: withHeader([]byte(`{"op":"x"}`))[:6]},
		{name: "invalid JSON", wire: withHeader([]byte(`{`))},
		{name: "empty body", wire: withHeader(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := socketPair(t)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			before := openFDs(t)
			if _, _, sendErr := a.WriteMsgUnix(tc.wire, syscall.UnixRights(int(w.Fd())), nil); sendErr != nil {
				t.Fatal(sendErr)
			}
			if closeErr := a.CloseWrite(); closeErr != nil {
				t.Fatal(closeErr)
			}
			_, files, err := ReceiveFrame(b, Limits{MaxFrameBytes: 100, MaxFDs: 1})
			defer closeFiles(files)
			if err == nil || files != nil {
				t.Errorf("bad frame accepted: files=%d err=%v", len(files), err)
			}
			assertNoFDLeak(t, before)
		})
	}
}

// A frame sent in pieces must not take the next frame's descriptors. A
// descriptor sent mid-frame is rejected instead; see
// TestReceiveFrameRejectsDescriptorsAfterFirstRead.
func TestReceiveFrameKeepsDescriptorsWithTheirFrame(t *testing.T) {
	a, b := socketPair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	wire := withHeader([]byte(`{"op":"first"}`))
	for _, part := range [][]byte{wire[:1], wire[1:4], wire[4:5], wire[5:]} {
		if writeErr := writeFull(a, part); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if sendErr := SendFrame(a, Frame{Op: "next"}, []*os.File{r}, 100); sendErr != nil {
		t.Fatal(sendErr)
	}
	lim := Limits{MaxFrameBytes: 100, MaxFDs: 1}
	f, files, err := ReceiveFrame(b, lim)
	defer closeFiles(files)
	if err != nil || f.Op != "first" || len(files) != 0 {
		t.Fatalf("first frame: op=%q descriptors=%d err=%v", f.Op, len(files), err)
	}
	if _, writeErr := w.Write([]byte("x")); writeErr != nil {
		t.Fatal(writeErr)
	}
	f, files, err = ReceiveFrame(b, lim)
	defer closeFiles(files)
	if err != nil || f.Op != "next" || len(files) != 1 {
		t.Fatalf("next frame: op=%q descriptors=%d err=%v", f.Op, len(files), err)
	}
	var got [1]byte
	if _, err := io.ReadFull(files[0], got[:]); err != nil || got[0] != 'x' {
		t.Fatalf("next frame did not receive the reader: data=%q err=%v", got, err)
	}
}

func TestSocketFrameLargeBodyWithDescriptors(t *testing.T) {
	a, b := socketPair(t)
	if err := a.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
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
		errc <- SendFrame(a, Frame{Op: "next"}, []*os.File{w}, 8<<20)
	}()
	lim := Limits{MaxFrameBytes: 8 << 20, MaxFDs: 1}
	f, fds, err := ReceiveFrame(b, lim)
	defer closeFiles(fds)
	if err != nil || f.Op != "big" || !bytes.Equal(f.Payload, big.Payload) || len(fds) != 1 {
		t.Fatalf("large frame: op=%q len=%d fds=%d err=%v", f.Op, len(f.Payload), len(fds), err)
	}
	f, fds, err = ReceiveFrame(b, lim)
	defer closeFiles(fds)
	if err != nil || f.Op != "next" || len(fds) != 1 {
		t.Fatalf("stream lost framing after a large frame: op=%q fds=%d err=%v", f.Op, len(fds), err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestReceiveFrameStopsOnDescriptorLimit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		limit    int
		counts   []int
		complete bool
	}{
		{name: "none allowed", limit: 0, counts: []int{1}},
		{name: "over limit without truncation", limit: 1, counts: []int{2}},
		{name: "truncated control", limit: 1, counts: []int{3}},
		{name: "across reads", limit: 2, counts: []int{2, 1}},
		{name: "at end of body", limit: 1, counts: []int{0, 2}, complete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := socketPair(t)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			before := openFDs(t)
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], 100)
			if tc.complete {
				binary.BigEndian.PutUint32(hdr[:], 2)
			}
			for i, count := range tc.counts {
				data := hdr[:]
				if i > 0 {
					data = []byte("{}")
				}
				fds := make([]int, count)
				for j := range fds {
					fds[j] = int(w.Fd())
				}
				var oob []byte
				if count > 0 {
					oob = syscall.UnixRights(fds...)
				}
				if _, _, sendErr := a.WriteMsgUnix(data, oob, nil); sendErr != nil {
					t.Fatal(sendErr)
				}
			}
			// Incomplete bodies must not delay descriptor rejection.
			if deadlineErr := b.SetReadDeadline(time.Now().Add(time.Second)); deadlineErr != nil {
				t.Fatal(deadlineErr)
			}
			_, files, err := ReceiveFrame(b, Limits{MaxFrameBytes: 100, MaxFDs: tc.limit})
			defer closeFiles(files)
			if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || !strings.Contains(err.Error(), "descriptor") || files != nil {
				t.Errorf("got files=%d error=%v, want immediate descriptor rejection", len(files), err)
			}
			assertNoFDLeak(t, before)
		})
	}
}

func TestRightsReaderKeepsDescriptorsBeforeControlParseError(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd, err := unix.Dup(int(w.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	// recvmsg owns the installed descriptor even if a later control is bad.
	oob := append(syscall.UnixRights(fd), make([]byte, syscall.CmsgLen(0))...)
	rr := &rightsReader{limit: 1, reads: 1}
	rr.collect(oob)
	if len(rr.files) != 1 {
		_ = unix.Close(fd)
		t.Fatalf("retained %d descriptors for cleanup, want 1", len(rr.files))
	}
	closeFiles(rr.files)
	if rr.err == nil {
		t.Error("malformed control accepted")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("descriptor still open after cleanup: %v", err)
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

func TestReceiveFrameRejectsDescriptorCapBeforeReadingBody(t *testing.T) {
	for _, count := range []int{2, 3} {
		a, b := socketPair(t)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		before := openFDs(t)
		fds := make([]int, count)
		for i := range fds {
			fds[i] = int(w.Fd())
		}
		// Send only the header. A rejected descriptor must not leave the
		// receiver waiting for more bytes from the same untrusted peer.
		if _, _, sendErr := a.WriteMsgUnix([]byte{0, 0, 0, 2}, syscall.UnixRights(fds...), nil); sendErr != nil {
			t.Fatal(sendErr)
		}
		if err := b.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		_, received, recvErr := ReceiveFrame(b, Limits{MaxFrameBytes: 1 << 20, MaxFDs: 1})
		if recvErr == nil || !strings.Contains(recvErr.Error(), "descriptors") || received != nil {
			t.Errorf("%d descriptors: fds=%d err=%v, want immediate descriptor error", count, len(received), recvErr)
		}
		assertNoFDLeak(t, before)
	}
}

// nonblocking reads O_NONBLOCK without calling Fd, which would itself switch
// the descriptor to blocking mode.
func nonblocking(t *testing.T, f *os.File) bool {
	t.Helper()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var flagErr error
	if err := rc.Control(func(fd uintptr) { flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil {
		t.Fatal(err)
	}
	if flagErr != nil {
		t.Fatal(flagErr)
	}
	return flags&unix.O_NONBLOCK != 0
}

// assertPipeStillPollable fails when f lost O_NONBLOCK or its deadlines.
func assertPipeStillPollable(t *testing.T, f *os.File) {
	t.Helper()
	if !nonblocking(t, f) {
		t.Fatal("caller pipe was switched to blocking mode")
	}
	if err := f.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("caller pipe lost deadlines: %v", err)
	}
}

func TestSendFrameKeepsCallerPipeNonBlocking(t *testing.T) {
	a, b := socketPair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if sendErr := SendFrame(a, Frame{Op: "x"}, []*os.File{r}, 1<<10); sendErr != nil {
		t.Fatal(sendErr)
	}
	_, got, err := ReceiveFrame(b, Limits{MaxFrameBytes: 1 << 10, MaxFDs: 1})
	if err != nil {
		t.Fatal(err)
	}
	closeFiles(got)
	assertPipeStillPollable(t, r)
}
