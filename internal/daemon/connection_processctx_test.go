package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Synthetic PIDs can belong to live processes in the test's PID namespace.
// Their real start times must not decide whether a fixture matches the cache.
func stubProcessStartTime(t *testing.T, pid int, startedAt time.Time) {
	t.Helper()
	previous := processCtxReadStartedAt
	processCtxReadStartedAt = func(got int) (time.Time, bool) {
		if got != pid {
			t.Errorf("unexpected pid %d, want %d", got, pid)
			return time.Time{}, false
		}
		return startedAt, !startedAt.IsZero()
	}
	t.Cleanup(func() { processCtxReadStartedAt = previous })
}

func TestProcessStartTimeStubRestoresReader(t *testing.T) {
	resetProcessCtxForTest()
	t.Cleanup(resetProcessCtxForTest)
	startedAt := time.Unix(1700000000, 0)
	processCtxReadStartedAt = func(int) (time.Time, bool) { return startedAt, true }
	t.Run("unknown start time", func(t *testing.T) {
		stubProcessStartTime(t, 4242, time.Time{})
		if got := processCtxStartedAt(4242); !got.IsZero() {
			t.Fatalf("StartedAt = %v, want unknown", got)
		}
	})
	if got := processCtxStartedAt(4242); !got.Equal(startedAt) {
		t.Fatalf("restored StartedAt = %v, want %v", got, startedAt)
	}
}

func TestAttachProcessCtxFromCacheHit(t *testing.T) {
	resetProcessCtxForTest()
	stubProcessStartTime(t, 4242, time.Time{})
	cache, enr := ProcessCtx()
	cache.PutFromExec(4242, 1, 1001, "ncat", "/usr/bin/ncat")
	before := enr.Stats().Enqueued

	f := alert.Finding{Check: "outbound_connection", Message: "test", Timestamp: time.Now()}
	ev := ConnectionEvent{UID: 1001, PID: 4242, Family: 2, DstPort: 587, DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat"}
	attachProcessCtxToFinding(cache, enr, &f, ev)

	if f.Process == nil {
		t.Fatal("expected Process attached")
	}
	if f.Process.PID != 4242 || f.Process.UID != 1001 || f.Process.Exe != "/usr/bin/ncat" {
		t.Errorf("Process: %+v", f.Process)
	}
	if enr.Stats().Enqueued <= before {
		t.Fatal("exec-only cache hit should enqueue async /proc enrichment")
	}
}

func TestAttachProcessCtxFromProcCacheHitDoesNotReenqueue(t *testing.T) {
	resetProcessCtxForTest()
	stubProcessStartTime(t, 4242, time.Time{})
	cache, enr := ProcessCtx()
	cache.PutFromProc(4242, 1, 1001, "alice", "alice", "ncat", "/usr/bin/ncat", []string{"ncat"})
	before := enr.Stats().Enqueued

	f := alert.Finding{Check: "outbound_connection", Message: "test", Timestamp: time.Now()}
	ev := ConnectionEvent{UID: 1001, PID: 4242, Family: 2, DstPort: 587, DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat"}
	attachProcessCtxToFinding(cache, enr, &f, ev)

	if f.Process == nil {
		t.Fatal("expected Process attached")
	}
	if got := enr.Stats().Enqueued; got != before {
		t.Fatalf("proc-populated cache hit should not enqueue; before=%d after=%d", before, got)
	}
}

func TestAttachProcessCtxRejectsSameUIDCommStartMismatch(t *testing.T) {
	resetProcessCtxForTest()
	cache, enr := ProcessCtx()
	oldStartedAt := time.Unix(1700000000, 0)
	newStartedAt := oldStartedAt.Add(time.Hour)
	cache.PutFromProcStartedAt(4242, 1, 1001, "alice", "alice", "ncat", "/usr/bin/ncat", []string{"ncat"}, oldStartedAt)
	stubProcessStartTime(t, 4242, newStartedAt)
	before := enr.Stats().Enqueued

	f := alert.Finding{Check: "outbound_connection", Message: "test", Timestamp: time.Now()}
	ev := ConnectionEvent{UID: 1001, PID: 4242, Family: 2, DstPort: 587, DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat"}
	attachProcessCtxToFinding(cache, enr, &f, ev)

	if f.Process != nil {
		t.Fatalf("expected start-time mismatch to reject cache hit, got %+v", f.Process)
	}
	if enr.Stats().Enqueued <= before {
		t.Fatal("start-time mismatch should enqueue refresh")
	}
}

func TestProcessctxRequestFromConnectionIncludesStartTime(t *testing.T) {
	resetProcessCtxForTest()
	startedAt := time.Unix(1700000000, 0)
	stubProcessStartTime(t, 4242, startedAt)

	req := processctxRequestFromConnection(ConnectionEvent{UID: 1001, PID: 4242, Comm: "ncat"})
	if !req.StartedAt.Equal(startedAt) {
		t.Fatalf("StartedAt = %v, want %v", req.StartedAt, startedAt)
	}
}

func TestAttachProcessCtxOverridesDirectSMTPTenantFromProcessAccount(t *testing.T) {
	resetProcessCtxForTest()
	stubProcessStartTime(t, 4242, time.Time{})
	cache, enr := ProcessCtx()
	cache.PutFromProc(4242, 1, 1001, "php-fpm", "alice", "ncat", "/usr/bin/ncat", []string{"ncat"})

	f := alert.Finding{Check: "direct_smtp_egress", TenantID: "php-fpm", Message: "test", Timestamp: time.Now()}
	ev := ConnectionEvent{UID: 1001, PID: 4242, Family: 2, DstPort: 587, DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat"}
	attachProcessCtxToFinding(cache, enr, &f, ev)

	if f.TenantID != "alice" {
		t.Fatalf("TenantID = %q, want process account alice", f.TenantID)
	}
}

func TestAttachProcessCtxRejectsStaleCacheHitAndEnqueuesRefresh(t *testing.T) {
	for _, tc := range []struct {
		name string
		uid  int
		comm string
	}{
		{"UID mismatch", 1002, "ncat"},
		{"command mismatch", 1001, "curl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetProcessCtxForTest()
			t.Cleanup(resetProcessCtxForTest)
			stubProcessStartTime(t, 4242, time.Time{})
			cache, enr := ProcessCtx()
			cache.PutFromExec(4242, 1, tc.uid, tc.comm, "/usr/bin/"+tc.comm)
			before := enr.Stats().Enqueued

			f := alert.Finding{Check: "outbound_connection", Message: "test", Timestamp: time.Now()}
			ev := ConnectionEvent{UID: 1001, PID: 4242, Family: 2, DstPort: 587, DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat"}
			attachProcessCtxToFinding(cache, enr, &f, ev)

			if f.Process != nil {
				t.Fatalf("expected stale Process nil; got %+v", f.Process)
			}
			if got := enr.Stats().Enqueued; got != before+1 {
				t.Fatalf("stale cache hit should enqueue one refresh; before=%d after=%d", before, got)
			}
		})
	}
}

func TestAttachProcessCtxOnCacheMissEnqueuesAndLeavesNil(t *testing.T) {
	resetProcessCtxForTest()
	stubProcessStartTime(t, 99999, time.Time{})
	cache, enr := ProcessCtx()
	before := enr.Stats().Enqueued

	f := alert.Finding{Check: "outbound_connection", Message: "test", Timestamp: time.Now()}
	ev := ConnectionEvent{UID: 1001, PID: 99999, Family: 2, DstPort: 587, DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat"}
	attachProcessCtxToFinding(cache, enr, &f, ev)

	if f.Process != nil {
		t.Errorf("expected Process nil on cache miss; got %+v", f.Process)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if enr.Stats().Enqueued > before {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("expected enrichment enqueue; before=%d after=%d", before, enr.Stats().Enqueued)
}

func TestAttachProcessCtxFindingStaysSerializableWhenNil(t *testing.T) {
	f := alert.Finding{Check: "outbound_connection", Message: "test", Timestamp: time.Now()}
	// Caller never sets Process: deserializing should not include the key.
	// Smoke check via String() to confirm no panic.
	_ = f.String()
}
