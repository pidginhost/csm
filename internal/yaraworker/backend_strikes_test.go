//go:build linux

package yaraworker

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/workerproc"
)

// Requests already waiting for the worker must see failures from the
// requests ahead of them, including when a reload replaces the strike list.
func TestQueuedScansRespectStrikes(t *testing.T) {
	for _, reload := range []bool{false, true} {
		name := "same rules"
		if reload {
			name = "reload while queued"
		}
		t.Run(name, func(t *testing.T) {
			entered, resume := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			h := newHelper("crash-on:boom")
			fx := &backendFixture{scan: h, scanFn: func(ctx context.Context) (workerproc.Process, error) {
				if h.launches.Load() == 0 {
					close(entered)
					select {
					case <-resume:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return h.launch(ctx)
			}}
			b := newBackend(t, fx)
			t.Cleanup(release)
			if err := b.Reload(); err != nil {
				t.Fatal(err)
			}
			const requests = 6
			done := make(chan error, requests)
			go func() { _, err := b.ScanBytesChecked([]byte("boom")); done <- err }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("first scan did not start")
			}
			for i := 1; i < requests; i++ {
				f := tempFile(t, "boom ignored suffix")
				go func(f *os.File) { _, err := b.ScanFDChecked(f, 4); done <- err }(f)
			}
			waitForQueuedScans(t, b, requests-1)
			wantFailures := workerproc.StrikeLimit
			if reload {
				if err := b.Reload(); err != nil {
					t.Fatal(err)
				}
				// The running request used the old rules. The queued requests
				// get the new rules and their own chance to scan.
				wantFailures++
			}
			release()
			failures, refused := 0, 0
			for range requests {
				select {
				case err := <-done:
					switch {
					case errors.Is(err, workerproc.ErrWorkerFailed):
						failures++
					case errors.Is(err, errStruckOut):
						refused++
					default:
						t.Errorf("scan = %v, want worker failure or struck content", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("queued scan did not finish")
				}
			}
			if failures != wantFailures || refused != requests-wantFailures {
				t.Errorf("failures=%d refused=%d, want %d and %d", failures, refused, wantFailures, requests-wantFailures)
			}
			if got := h.launches.Load(); int(got) != wantFailures {
				t.Errorf("started %d workers, want %d", got, wantFailures)
			}
			if _, err := b.ScanBytesChecked([]byte("boom")); !errors.Is(err, errStruckOut) {
				t.Errorf("scan after queued failures = %v, want struck content", err)
			}
			if names := ruleNames(t, b, "evil"); len(names) != 1 || names[0] != "evil" {
				t.Errorf("unrelated scan = %v, want evil", names)
			}
		})
	}
}

func waitForQueuedScans(t *testing.T, b *Backend, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		status := b.QueueStatuses(time.Now())["requests"]
		if status.Depth == want && status.InFlight == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue = %+v, want %d waiting and one running", status, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// A reload can land after admission but before the replacement worker
// loads its rules. Its failure belongs to the rules it actually loaded.
func TestScanFailureStrikesLoadedRules(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	fx := &backendFixture{
		scan: newHelper("crash-on:boom"),
		log: func(format string, _ ...any) {
			if strings.HasSuffix(format, "retired") {
				close(entered)
				<-resume
			}
		},
	}
	b := newBackend(t, fx)
	t.Cleanup(release)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := b.Warm(); err != nil {
		t.Fatal(err)
	}
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := b.ScanBytesChecked([]byte("boom")); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not retire")
	}
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-done; !errors.Is(err, workerproc.ErrWorkerFailed) {
		t.Fatalf("first scan = %v, want worker failure", err)
	}
	if _, err := b.ScanBytesChecked([]byte("boom")); !errors.Is(err, workerproc.ErrWorkerFailed) {
		t.Fatalf("second scan = %v, want worker failure", err)
	}
	if _, err := b.ScanBytesChecked([]byte("boom")); !errors.Is(err, errStruckOut) {
		t.Fatalf("third scan = %v, want struck content", err)
	}
}

func TestStrikesCoverOnlyScannedPrefix(t *testing.T) {
	fx := &backendFixture{scan: newHelper("crash-on:boom")}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"boom first suffix", "boom second suffix"} {
		if _, err := b.ScanFDChecked(tempFile(t, content), 4); !errors.Is(err, workerproc.ErrWorkerFailed) {
			t.Fatalf("scan = %v, want worker failure", err)
		}
	}
	if _, err := b.ScanBytesChecked([]byte("boom")); !errors.Is(err, errStruckOut) {
		t.Fatalf("prefix through byte API = %v, want struck content", err)
	}
	if _, err := b.ScanFDChecked(tempFile(t, "boom third suffix"), 4); !errors.Is(err, errStruckOut) {
		t.Fatalf("prefix through descriptor API = %v, want struck content", err)
	}
	if _, err := b.ScanBytesChecked([]byte("boom distinct")); !errors.Is(err, workerproc.ErrWorkerFailed) {
		t.Fatalf("distinct scanned content = %v, want its own worker attempt", err)
	}
}

func TestStartupFailuresDoNotStrikeContent(t *testing.T) {
	for _, failure := range []error{errors.New("unit unavailable"), syscall.EMFILE, syscall.ENFILE} {
		t.Run(failure.Error(), func(t *testing.T) {
			fx := &backendFixture{scanFn: func(context.Context) (workerproc.Process, error) {
				return nil, failure
			}}
			b := newBackend(t, fx)
			if err := b.Reload(); err != nil {
				t.Fatal(err)
			}
			for range workerproc.ConsecutiveFailureLimit + 1 {
				if _, err := b.ScanBytesChecked([]byte("evil")); err == nil || errors.Is(err, errStruckOut) {
					t.Fatalf("startup failure = %v, want unavailable worker", err)
				}
			}
			if got := b.strikes.Load().Len(); got != 0 {
				t.Fatalf("startup failures struck %d inputs", got)
			}
		})
	}
}

func TestHashingRequiresLiveStrikes(t *testing.T) {
	for _, state := range []string{"empty", "expired", "live"} {
		t.Run(state, func(t *testing.T) {
			fx := &backendFixture{}
			b := newBackend(t, fx)
			if err := b.Reload(); err != nil {
				t.Fatal(err)
			}
			strikes := workerproc.NewStrikes()
			if state == "expired" {
				strikes = workerproc.NewStrikesWith(workerproc.StrikeLimit, -time.Second)
			}
			if state != "empty" {
				strikes.Record("other content")
			}
			b.strikes.Store(strikes)
			// A short descriptor reveals who read it: hashing fails locally;
			// without hashing, the worker reports the invalid scan size.
			_, err := b.ScanFDChecked(tempFile(t, "x"), 2)
			if state == "live" {
				if err == nil || !strings.Contains(err.Error(), "hash content") || fx.scan.launches.Load() != 0 {
					t.Fatalf("live strike scan = %v, launches=%d", err, fx.scan.launches.Load())
				}
			} else if !errors.Is(err, workerproc.ErrWorkerFailed) || fx.scan.launches.Load() != 1 {
				t.Fatalf("%s strike scan = %v, launches=%d", state, err, fx.scan.launches.Load())
			}
		})
	}
}
