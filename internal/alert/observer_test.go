package alert

import (
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

type panicStringer struct{}

func (panicStringer) String() string {
	panic("stringer\nforged")
}

func TestRegisterFindingObserverCalledOnDispatch(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	var calls atomic.Int64
	cancel := RegisterFindingObserver(func(f Finding) {
		calls.Add(1)
	})
	defer cancel()

	cfg := &config.Config{Hostname: "test"}
	emitAudit(cfg, []Finding{{Check: "x", Message: "y"}, {Check: "z", Message: "w"}})

	if got := calls.Load(); got != 2 {
		t.Errorf("observer calls: want 2, got %d", got)
	}
}

func TestRegisterFindingObserverCancelStops(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	var calls atomic.Int64
	cancel := RegisterFindingObserver(func(f Finding) { calls.Add(1) })
	cancel()

	cfg := &config.Config{Hostname: "test"}
	emitAudit(cfg, []Finding{{Check: "x"}})

	if calls.Load() != 0 {
		t.Errorf("observer must not fire after cancel; got %d", calls.Load())
	}
}

func TestObserverPanicIsolated(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	var goodCalls atomic.Int64
	cancelBad := RegisterFindingObserver(func(f Finding) { panic("boom") })
	defer cancelBad()
	cancelGood := RegisterFindingObserver(func(f Finding) { goodCalls.Add(1) })
	defer cancelGood()

	cfg := &config.Config{Hostname: "test"}
	_ = captureObserverStderr(t, func() {
		emitAudit(cfg, []Finding{{Check: "x"}})
	})

	if goodCalls.Load() != 1 {
		t.Errorf("panicking observer must not stop fan-out; goodCalls=%d", goodCalls.Load())
	}
}

func TestObserverPanicLogEscapesRecoveredValue(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	cancelBad := RegisterFindingObserver(func(f Finding) { panic("boom\nforged") })
	defer cancelBad()

	stderr := captureObserverStderr(t, func() {
		cfg := &config.Config{Hostname: "test"}
		emitAudit(cfg, []Finding{{Check: "line\ncheck"}})
	})

	if !strings.Contains(stderr, "alert: finding observer id=") {
		t.Fatalf("stderr missing observer panic prefix: %q", stderr)
	}
	if !strings.Contains(stderr, `panic for check="line\ncheck": "boom\nforged"`) {
		t.Fatalf("stderr missing escaped check and panic value: %q", stderr)
	}
	if strings.Contains(stderr, "line\ncheck") || strings.Contains(stderr, "boom\nforged") {
		t.Fatalf("stderr contains raw newline from finding or panic value: %q", stderr)
	}
	if !strings.Contains(stderr, "internal/alert.notifyFindingObservers") {
		t.Fatalf("stderr missing observer stack: %q", stderr)
	}
}

func TestObserverPanicValueFormattingEscapedAndFanoutContinues(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	var goodCalls atomic.Int64
	cancelBad := RegisterFindingObserver(func(f Finding) { panic(panicStringer{}) })
	defer cancelBad()
	cancelGood := RegisterFindingObserver(func(f Finding) { goodCalls.Add(1) })
	defer cancelGood()

	stderr := captureObserverStderr(t, func() {
		cfg := &config.Config{Hostname: "test"}
		emitAudit(cfg, []Finding{{Check: "x"}})
	})

	if goodCalls.Load() != 1 {
		t.Fatalf("panic value formatting stopped fan-out; goodCalls=%d", goodCalls.Load())
	}
	if !strings.Contains(stderr, `"%!v(PANIC=String method: stringer\nforged)"`) {
		t.Fatalf("stderr missing escaped formatting panic marker: %q", stderr)
	}
	if strings.Contains(stderr, "stringer\nforged") {
		t.Fatalf("stderr contains raw newline from formatting panic: %q", stderr)
	}
}

func captureObserverStderr(t *testing.T, fn func()) string {
	t.Helper()

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	os.Stderr = w
	wClosed := false
	defer func() {
		os.Stderr = origStderr
		if !wClosed {
			_ = w.Close()
		}
	}()

	fn()

	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	wClosed = true
	os.Stderr = origStderr

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
