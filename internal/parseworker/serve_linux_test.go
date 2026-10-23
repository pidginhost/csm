package parseworker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/workerproc"
)

func connPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "pair")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	a, b := conn(fds[0]), conn(fds[1])
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	if err := a.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return a, b
}

// servePair runs Serve on the far end and returns the near end.
func servePair(t *testing.T) *net.UnixConn {
	t.Helper()
	a, b := connPair(t)
	go func() { _ = Serve(context.Background(), b) }()
	return a
}

func tempFile(t testing.TB, data []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "in.zip")
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

func listZipRequest(t *testing.T) workerproc.Frame {
	t.Helper()
	payload, err := json.Marshal(ListZipArgs{MaxDirBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return workerproc.Frame{Op: OpListZip, Payload: payload}
}

func roundTrip(t *testing.T, conn *net.UnixConn, req workerproc.Frame, fds []*os.File) (workerproc.Frame, []*os.File) {
	t.Helper()
	if err := workerproc.SendFrame(conn, req, fds, Limits.MaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	reply, got, err := workerproc.ReceiveFrame(conn, Limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, f := range got {
			_ = f.Close()
		}
	})
	return reply, got
}

func TestServeListZipReturnsListingMemfd(t *testing.T) {
	conn := servePair(t)
	zf := tempFile(t, zipBytes(t, "a/", "a/b.php", "c.txt"))
	reply, fds := roundTrip(t, conn, listZipRequest(t), []*os.File{zf})
	var res ListZipResult
	if reply.Error != "" || json.Unmarshal(reply.Payload, &res) != nil || res.Incomplete != "" {
		t.Fatalf("reply = %+v", reply)
	}
	if len(fds) != 1 {
		t.Fatalf("got %d descriptors", len(fds))
	}
	st, err := fds[0].Stat()
	if err != nil || !st.Mode().IsRegular() {
		t.Fatalf("listing descriptor: %v %v", st, err)
	}
	var names []string
	n, err := readEntries(io.NewSectionReader(fds[0], 0, st.Size()), func(name string, _ bool) error {
		names = append(names, name)
		return nil
	})
	if err != nil || n != res.Entries || res.Entries != 3 || names[1] != "a/b.php" {
		t.Fatalf("listing = %v (%d records, %v), result %+v", names, n, err, res)
	}
}

func TestServeListZipCorruptIsIncomplete(t *testing.T) {
	conn := servePair(t)
	junk := make([]byte, 4096)
	if _, err := rand.Read(junk); err != nil {
		t.Fatal(err)
	}
	reply, fds := roundTrip(t, conn, listZipRequest(t), []*os.File{tempFile(t, junk)})
	var res ListZipResult
	if reply.Error != "" || json.Unmarshal(reply.Payload, &res) != nil || res.Incomplete == "" || len(fds) != 0 {
		t.Fatalf("corrupt zip: reply %+v result %+v fds %d", reply, res, len(fds))
	}
}

func TestServeListZipRequiresOneDescriptor(t *testing.T) {
	a, b := connPair(t)
	served := make(chan error, 1)
	go func() { served <- Serve(context.Background(), b) }()
	zf := tempFile(t, zipBytes(t, "a.txt"))

	// No descriptor: an Error reply, and the loop goes on.
	if reply, fds := roundTrip(t, a, listZipRequest(t), nil); reply.Error == "" || len(fds) != 0 {
		t.Fatalf("no descriptor: reply %+v fds %d", reply, len(fds))
	}
	if reply, fds := roundTrip(t, a, listZipRequest(t), []*os.File{zf}); reply.Error != "" || len(fds) != 1 {
		t.Fatalf("loop did not continue: reply %+v fds %d", reply, len(fds))
	}
	// Two descriptors exceed the frame limit: the worker drops the
	// connection rather than guess where the next frame starts.
	if err := workerproc.SendFrame(a, listZipRequest(t), []*os.File{zf, zf}, Limits.MaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-served:
		if err == nil {
			t.Fatal("Serve accepted two descriptors")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept running after a frame with two descriptors")
	}
}
