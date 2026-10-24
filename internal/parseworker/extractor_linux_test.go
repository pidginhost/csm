package parseworker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/workerproc"
)

// TestExtractWorkerHelper is not a real test: it is the worker the
// extractor tests start. With no mode it runs Serve; a mode makes it lie.
func TestExtractWorkerHelper(t *testing.T) {
	if os.Getenv("CSM_TEST_EXTRACT_WORKER") != "1" {
		return
	}
	conn, err := workerproc.ChildConn()
	if err != nil {
		os.Exit(2)
	}
	mode := os.Getenv("CSM_TEST_EXTRACT_WORKER_MODE")
	if mode == "" {
		err = Serve(context.Background(), conn)
	} else {
		err = workerproc.Serve(context.Background(), conn, WorkerLimits, lyingExtractor(mode))
	}
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func sealedMemfd(data []byte, seal bool) *os.File {
	fd, err := unix.MemfdCreate("lie", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		panic(err)
	}
	f := os.NewFile(uintptr(fd), "lie")
	if _, err := f.Write(data); err != nil {
		panic(err)
	}
	if seal {
		if err := sealFile(f); err != nil {
			panic(err)
		}
	}
	return f
}

// lyingExtractor answers hello honestly and extract_message with the named lie.
func lyingExtractor(mode string) workerproc.Handler {
	return func(_ context.Context, req workerproc.Frame, _ []*os.File) (workerproc.Frame, []*os.File) {
		if req.Op == workerproc.OpHello {
			return workerproc.HelloReply(ProtocolVersion), nil
		}
		part := func(name string, size int64) ExtractPart {
			return ExtractPart{Filename: name, ContentType: "application/octet-stream", Size: size}
		}
		one := func(res ExtractResult, data []byte, seal bool) (workerproc.Frame, []*os.File) {
			return extractResult(res), []*os.File{sealedMemfd(data, seal)}
		}
		switch mode {
		case "hang":
			time.Sleep(time.Hour)
		case "crash":
			os.Exit(3)
		case "unsealed":
			return one(ExtractResult{Parts: []ExtractPart{part("a.bin", 4)}}, []byte("abcd"), false)
		case "size-mismatch":
			return one(ExtractResult{Parts: []ExtractPart{part("a.bin", 3)}}, []byte("abcd"), true)
		case "count-mismatch":
			return one(ExtractResult{Parts: []ExtractPart{part("a.bin", 4), part("b.bin", 4)}}, []byte("abcd"), true)
		case "over-attachment-cap":
			return one(ExtractResult{Parts: []ExtractPart{part("a.bin", 20)}}, make([]byte, 20), true)
		case "over-total-cap":
			return extractResult(ExtractResult{Parts: []ExtractPart{part("a.bin", 8), part("b.bin", 8)}}),
				[]*os.File{sealedMemfd(make([]byte, 8), true), sealedMemfd(make([]byte, 8), true)}
		case "unsanitized-name":
			return one(ExtractResult{Parts: []ExtractPart{part("dir/a.bin", 4)}}, []byte("abcd"), true)
		case "long-subject":
			return one(ExtractResult{Parts: []ExtractPart{part("a.bin", 4)}, Subject: strings.Repeat("s", 2000)}, []byte("abcd"), true)
		case "control-subject":
			return one(ExtractResult{Parts: []ExtractPart{part("a.bin", 4)}, Subject: "fine\nFORGED LOG LINE"}, []byte("abcd"), true)
		case "bad-direction":
			return one(ExtractResult{Parts: []ExtractPart{part("a.bin", 4)}, Direction: "sideways"}, []byte("abcd"), true)
		case "control-content-type":
			p := part("a.bin", 4)
			p.ContentType = "text/plain\x00evil"
			return one(ExtractResult{Parts: []ExtractPart{p}}, []byte("abcd"), true)
		case "empty-part":
			return one(ExtractResult{Parts: []ExtractPart{part("a.bin", 0)}}, nil, true)
		case "too-many-encrypted":
			return extractResult(ExtractResult{EncryptedEntries: make([]EncryptedEntry, MaxEncryptedEntries+1)}), nil
		}
		return workerproc.Frame{Error: "unknown mode " + mode}, nil
	}
}

func extractorFor(t *testing.T, modes ...string) *Extractor {
	t.Helper()
	launch := func(slot int) workerproc.Launcher {
		mode := modes[slot]
		exec := workerproc.ExecLauncher(os.Args[0], []string{"-test.run=^TestExtractWorkerHelper$"},
			append(os.Environ(), "CSM_TEST_EXTRACT_WORKER=1", "CSM_TEST_EXTRACT_WORKER_MODE="+mode))
		return func(ctx context.Context) (workerproc.Process, error) {
			p, err := exec(ctx)
			if err != nil {
				return nil, err
			}
			hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := workerproc.Handshake(hctx, p.Conn(), WorkerLimits, ProtocolVersion); err != nil {
				_ = p.Kill()
				<-p.Done()
				_ = p.Conn().Close()
				return nil, err
			}
			return p, nil
		}
	}
	e, err := NewExtractor(ExtractorConfig{Size: len(modes), Launch: launch})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	return e
}

func testLimits() emime.Limits {
	return emime.Limits{MaxAttachmentSize: 10, MaxArchiveDepth: 1, MaxArchiveFiles: 50, MaxExtractionSize: 12}
}

func TestExtractDeliversParts(t *testing.T) {
	e := extractorFor(t, "")
	h, d := spoolPair(t, "two", []string{"user@example.com"}, mailPart{"a.pdf", []byte("first part")}, mailPart{"b.doc", []byte("second")})
	limits := testLimits()
	limits.MaxAttachmentSize, limits.MaxExtractionSize = 1<<20, 4<<20
	res, err := e.Extract(context.Background(), 0, h, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if len(res.Parts) != 2 || res.Partial || res.Subject != "two" {
		t.Fatalf("result %+v", res)
	}
	for i, want := range []string{"first part", "second"} {
		p := res.Parts[i]
		if p.TempPath != "" || string(readPart(t, p.File, p.Size)) != want {
			t.Fatalf("part %d = %+v", i, p)
		}
	}
}

func TestExtractRejectsMalformedReply(t *testing.T) {
	for _, mode := range []string{"unsealed", "size-mismatch", "count-mismatch", "over-attachment-cap", "over-total-cap",
		"unsanitized-name", "long-subject", "control-subject", "bad-direction", "control-content-type", "empty-part", "too-many-encrypted"} {
		t.Run(mode, func(t *testing.T) {
			e := extractorFor(t, mode)
			h, d := spoolPair(t, "x", []string{"user@example.com"}, mailPart{"a.bin", []byte("x")})
			for call := 1; call <= 2; call++ {
				res, err := e.Extract(context.Background(), 0, h, d, testLimits())
				if res != nil || !errors.Is(err, workerproc.ErrWorkerFailed) || workerproc.FailureReason(err) != workerproc.ReasonProtocol {
					t.Fatalf("call %d: result %v err %v reason %q", call, res, err, workerproc.FailureReason(err))
				}
				if got := e.pool.Stats()[0].Spawns; got != call {
					t.Fatalf("call %d: spawns %d, want a new worker per rejected reply", call, got)
				}
			}
		})
	}
}

func TestExtractWorkerHangTimesOut(t *testing.T) {
	real := extractTimeout
	extractTimeout = 200 * time.Millisecond
	t.Cleanup(func() { extractTimeout = real })
	e := extractorFor(t, "hang")
	h, d := spoolPair(t, "x", []string{"user@example.com"}, mailPart{"a.bin", []byte("x")})
	_, err := e.Extract(context.Background(), 0, h, d, testLimits())
	if workerproc.FailureReason(err) != workerproc.ReasonTimeout {
		t.Fatalf("hang = %v (%q)", err, workerproc.FailureReason(err))
	}
}

func TestExtractWorkerCrash(t *testing.T) {
	e := extractorFor(t, "crash")
	h, d := spoolPair(t, "x", []string{"user@example.com"}, mailPart{"a.bin", []byte("x")})
	if _, err := e.Extract(context.Background(), 0, h, d, testLimits()); workerproc.FailureReason(err) != workerproc.ReasonCrash {
		t.Fatalf("crash = %v (%q)", err, workerproc.FailureReason(err))
	}
}

func TestExtractQueuePublication(t *testing.T) {
	e := extractorFor(t, "")
	h, d := spoolPair(t, "x", []string{"user@example.com"}, mailPart{"a.bin", []byte("x")})
	res, err := e.Extract(context.Background(), 0, h, d, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	res.Close()
	q, ok := e.QueueStatuses(time.Now())["requests"]
	if !ok || q.InFlight != 0 || q.DroppedTotal != 0 || q.Capacity != 1 {
		t.Fatalf("requests row %+v (found %v)", q, ok)
	}
}

func TestExtractSlotsAreIndependent(t *testing.T) {
	real := extractTimeout
	extractTimeout = 2 * time.Second
	t.Cleanup(func() { extractTimeout = real })
	e := extractorFor(t, "hang", "")
	h, d := spoolPair(t, "x", []string{"user@example.com"}, mailPart{"a.bin", []byte("x")})
	go func() { _, _ = e.Extract(context.Background(), 0, h, d, testLimits()) }()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	res, err := e.Extract(context.Background(), 1, h, d, testLimits())
	if err != nil || time.Since(start) > time.Second {
		t.Fatalf("slot 1 waited %s: %v", time.Since(start), err)
	}
	res.Close()
}

func TestFileSizeLimit(t *testing.T) {
	if got := FileSizeLimit(25 << 20); got != 64<<20 {
		t.Fatalf("25 MiB -> %d", got)
	}
	if got := FileSizeLimit(100 << 20); got != 101<<20 {
		t.Fatalf("100 MiB -> %d", got)
	}
}

// FuzzExtractReply drives the daemon's reply check with arbitrary JSON and
// sealed memfds of arbitrary sizes: it never panics, and an accepted reply
// respects every cap.
func FuzzExtractReply(f *testing.F) {
	f.Add([]byte(`{"parts":[{"filename":"a.bin","content_type":"x","size":2}]}`), []byte{2})
	f.Add([]byte(`{"parts":null,"subject":"s"}`), []byte{})
	f.Add([]byte(`{"parts":[{"filename":"a","size":1},{"filename":"b","size":3}],"to":["u@example.com"]}`), []byte{1, 3})
	f.Fuzz(func(t *testing.T, payload, sizes []byte) {
		if len(sizes) > 8 {
			sizes = sizes[:8]
		}
		fds := make([]*os.File, 0, len(sizes))
		for _, n := range sizes {
			fds = append(fds, sealedMemfd(make([]byte, n), true))
		}
		defer func() {
			for _, fd := range fds {
				_ = fd.Close()
			}
		}()
		limits := emime.Limits{MaxAttachmentSize: 100, MaxExtractionSize: 300, MaxArchiveFiles: 50}
		var res ExtractResult
		if err := checkExtract(payload, fds, limits, &res); err != nil {
			return
		}
		var total int64
		for _, p := range res.Parts {
			total += p.Size
			if p.Size <= 0 || p.Size > limits.MaxAttachmentSize || len(p.Filename) > 255 {
				t.Fatalf("accepted part %+v", p)
			}
		}
		if total > limits.MaxExtractionSize || len(res.Parts) != len(fds) || len(res.Subject) > 998 || len(res.To) > 100 {
			t.Fatalf("accepted reply %+v", res)
		}
		_ = json.Valid(payload)
	})
}
