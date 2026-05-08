package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestAttachProcessCtxFromCacheHit(t *testing.T) {
	resetProcessCtxForTest()
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

func TestAttachProcessCtxOverridesDirectSMTPTenantFromProcessAccount(t *testing.T) {
	resetProcessCtxForTest()
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
	resetProcessCtxForTest()
	cache, enr := ProcessCtx()
	cache.PutFromExec(4242, 1, 1002, "curl", "/usr/bin/curl")
	before := enr.Stats().Enqueued

	f := alert.Finding{Check: "outbound_connection", Message: "test", Timestamp: time.Now()}
	ev := ConnectionEvent{UID: 1001, PID: 4242, Family: 2, DstPort: 587, DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat"}
	attachProcessCtxToFinding(cache, enr, &f, ev)

	if f.Process != nil {
		t.Fatalf("expected stale Process nil; got %+v", f.Process)
	}
	if enr.Stats().Enqueued <= before {
		t.Fatal("stale cache hit should enqueue refresh")
	}
}

func TestAttachProcessCtxOnCacheMissEnqueuesAndLeavesNil(t *testing.T) {
	resetProcessCtxForTest()
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
