package parseworker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/workerproc"
)

// TestParseWorkerHelper is not a real test: it is the worker the lister
// tests start. With no mode it runs Serve; a mode makes it lie.
func TestParseWorkerHelper(t *testing.T) {
	if os.Getenv("CSM_TEST_PARSE_WORKER") != "1" {
		return
	}
	conn, err := workerproc.ChildConn()
	if err != nil {
		os.Exit(2)
	}
	mode := os.Getenv("CSM_TEST_PARSE_WORKER_MODE")
	if mode == "" {
		err = Serve(context.Background(), conn)
	} else {
		err = workerproc.Serve(context.Background(), conn, Limits, lyingHandler(mode))
	}
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func memfdWith(data []byte) *os.File {
	return memfdWithSeals(data, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK)
}

func memfdWithSeals(data []byte, seals int) *os.File {
	fd, err := unix.MemfdCreate("lie", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		panic(err)
	}
	f := os.NewFile(uintptr(fd), "lie")
	if _, err := f.Write(data); err != nil {
		panic(err)
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		panic(err)
	}
	return f
}

func listingOf(names ...string) []byte {
	var buf bytes.Buffer
	for _, name := range names {
		_ = writeEntry(&buf, name, false)
	}
	return buf.Bytes()
}

// lyingHandler answers hello honestly and list_zip with the named lie.
func lyingHandler(mode string) workerproc.Handler {
	return func(_ context.Context, req workerproc.Frame, fds []*os.File) (workerproc.Frame, []*os.File) {
		if req.Op == workerproc.OpHello {
			return workerproc.HelloReply(ProtocolVersion), nil
		}
		ok := func(entries uint64, incomplete string) workerproc.Frame {
			return result(ListZipResult{Entries: entries, Incomplete: incomplete})
		}
		switch mode {
		case "null-reply", "missing-count", "null-count":
			payload := map[string]string{"null-reply": "null", "missing-count": "{}", "null-count": `{"entries":null}`}[mode]
			return workerproc.Frame{Payload: json.RawMessage(payload)}, []*os.File{memfdWith(nil)}
		case "incomplete-with-count":
			return ok(1, "partial"), nil
		case "long-incomplete":
			return ok(0, strings.Repeat("x", maxIncomplete+1)), nil
		case "unsealed":
			return ok(1, ""), []*os.File{memfdWithSeals(listingOf("a"), 0)}
		case "writable":
			return ok(1, ""), []*os.File{memfdWithSeals(listingOf("a"), unix.F_SEAL_GROW|unix.F_SEAL_SHRINK)}
		case "growable":
			return ok(1, ""), []*os.File{memfdWithSeals(listingOf("a"), unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK)}
		case "shrinkable":
			return ok(1, ""), []*os.File{memfdWithSeals(listingOf("a"), unix.F_SEAL_WRITE|unix.F_SEAL_GROW)}
		case "crash":
			os.Exit(3)
		case "two-fds":
			return ok(1, ""), []*os.File{memfdWith(listingOf("a")), memfdWith(listingOf("a"))}
		case "pipe-fd":
			r, w, _ := os.Pipe()
			_ = w.Close()
			return ok(0, ""), []*os.File{r}
		case "listing-larger-than-zip":
			st, _ := fds[0].Stat()
			names := make([]string, 0)
			for size := int64(0); size <= st.Size(); size += 3 + 8 {
				names = append(names, "filename")
			}
			return ok(uint64(len(names)), ""), []*os.File{memfdWith(listingOf(names...))}
		case "truncated-record":
			return ok(2, ""), []*os.File{memfdWith(append(listingOf("a"), 0, 0, 10, 'a'))}
		case "bad-flag":
			return ok(2, ""), []*os.File{memfdWith(append(listingOf("a"), 2, 0, 0))}
		case "count-mismatch":
			return ok(1, ""), []*os.File{memfdWith(listingOf("a", "b"))}
		case "incomplete-with-fd":
			return ok(0, "partial"), []*os.File{memfdWith(nil)}
		}
		return workerproc.Frame{Error: "unknown mode " + mode}, nil
	}
}

func testLister(t *testing.T, mode string) *Lister {
	t.Helper()
	exec := workerproc.ExecLauncher(os.Args[0], []string{"-test.run=^TestParseWorkerHelper$"},
		append(os.Environ(), "CSM_TEST_PARSE_WORKER=1", "CSM_TEST_PARSE_WORKER_MODE="+mode))
	l, err := NewLister(ListerConfig{Launch: func(ctx context.Context) (workerproc.Process, error) {
		p, err := exec(ctx)
		if err != nil {
			return nil, err
		}
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := workerproc.Handshake(hctx, p.Conn(), Limits, ProtocolVersion); err != nil {
			_ = p.Kill()
			<-p.Done()
			_ = p.Conn().Close()
			return nil, err
		}
		return p, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Stop() })
	return l
}

func collect(got *[]entry) func(string, bool) error {
	return func(name string, dir bool) error {
		*got = append(*got, entry{name, dir})
		return nil
	}
}

func listVia(t *testing.T, l *Lister, data []byte, visit func(string, bool) error) error {
	t.Helper()
	return l.ListZip(context.Background(), tempFile(t, data), int64(len(data)), 50<<20, visit)
}

func TestListZipDeliversEveryEntry(t *testing.T) {
	l := testLister(t, "")
	var got []entry
	if err := listVia(t, l, zipBytes(t, "a/", "a/b.php", "c/", "c/d.html", "e.txt"), collect(&got)); err != nil {
		t.Fatal(err)
	}
	want := []entry{{"a/", true}, {"a/b.php", false}, {"c/", true}, {"c/d.html", false}, {"e.txt", false}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("entries = %v", got)
	}
}

func TestListZipDeliversEntriesPastFiller(t *testing.T) {
	names := make([]string, 0, 30002)
	for i := range 30000 {
		names = append(names, fmt.Sprintf("filler/%05d.txt", i))
	}
	names = append(names, "office365/login.html", "office365/next.php")
	data := zipBytes(t, names...)
	l := testLister(t, "")
	var got []entry
	if err := listVia(t, l, data, collect(&got)); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(names) {
		t.Fatalf("got %d entries, want %d", len(got), len(names))
	}
	if last := got[len(got)-1]; last.name != "office365/next.php" {
		t.Fatalf("last entry = %v", last)
	}
	stop := errors.New("kit found")
	err := listVia(t, l, data, func(name string, _ bool) error {
		if name == "office365/next.php" {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || errors.Is(err, workerproc.ErrWorkerFailed) {
		t.Fatalf("visit sentinel = %v", err)
	}
	if st := l.Stats(); st.ConsecutiveFailures != 0 {
		t.Fatalf("visit stop counted as failure: %+v", st)
	}
}

func TestListZipCorruptIsIncompleteNotFailure(t *testing.T) {
	l := testLister(t, "")
	junk := make([]byte, 4096)
	if _, err := rand.Read(junk); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		err := listVia(t, l, junk, collect(new([]entry)))
		if !errors.Is(err, errIncomplete) || errors.Is(err, workerproc.ErrWorkerFailed) {
			t.Fatalf("corrupt zip = %v", err)
		}
	}
	if got := l.Stats().Spawns; got != 1 {
		t.Fatalf("spawns = %d", got)
	}
	if q := l.QueueStatuses(time.Now())["requests"]; q.DroppedTotal != 0 || q.InFlight != 0 || q.Depth != 0 {
		t.Fatalf("corrupt zips degraded request health: %+v", q)
	}
}

func TestListZipRejectsMalformedListing(t *testing.T) {
	for _, mode := range []string{
		"null-reply", "missing-count", "null-count", "incomplete-with-count", "long-incomplete",
		"unsealed", "writable", "growable", "shrinkable", "two-fds", "pipe-fd",
		"listing-larger-than-zip", "truncated-record", "bad-flag", "count-mismatch", "incomplete-with-fd",
	} {
		t.Run(mode, func(t *testing.T) {
			l := testLister(t, mode)
			data := zipBytes(t, "a.txt")
			for i := 1; i <= 2; i++ {
				visited := false
				err := listVia(t, l, data, func(string, bool) error { visited = true; return nil })
				if !errors.Is(err, workerproc.ErrWorkerFailed) || visited {
					t.Fatalf("call %d: err = %v visited = %v", i, err, visited)
				}
				if got := l.Stats().Spawns; got != i {
					t.Fatalf("call %d: spawns = %d, want a new worker per call", i, got)
				}
				if st := l.Stats(); st.Running || st.ConsecutiveFailures != i {
					t.Fatalf("call %d: rejected worker still usable: %+v", i, st)
				}
			}
		})
	}
}

func TestListZipWorkerCrash(t *testing.T) {
	l := testLister(t, "crash")
	if err := listVia(t, l, zipBytes(t, "a.txt"), collect(new([]entry))); !errors.Is(err, workerproc.ErrWorkerFailed) {
		t.Fatalf("crash = %v", err)
	}
}

func TestListZipQueuePublication(t *testing.T) {
	l := testLister(t, "")
	if _, ok := l.QueueStatuses(time.Now())["requests"]; !ok {
		t.Fatal("no requests row")
	}
	if err := listVia(t, l, zipBytes(t, "a.txt"), collect(new([]entry))); err != nil {
		t.Fatal(err)
	}
	q := l.QueueStatuses(time.Now())["requests"]
	if q.InFlight != 0 || q.Depth != 0 || q.DroppedTotal != 0 {
		t.Fatalf("requests row after one call: %+v", q)
	}
}
