package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestPopulateProcessCtxFromExecEventStoresEntry(t *testing.T) {
	resetProcessCtxForTest()
	cache, _ := ProcessCtx()
	ev := ExecEvent{UID: 1001, PID: 4242, PPID: 1, Comm: "php-fpm", ParentComm: "init", Filename: "/usr/sbin/php-fpm"}
	populateProcessCtxFromExec(cache, ev)
	pc := cache.Materialize(4242)
	if pc == nil {
		t.Fatal("expected materialized entry")
	}
	if pc.UID != 1001 || pc.PPID != 1 || pc.Comm != "php-fpm" {
		t.Errorf("entry: %+v", pc)
	}
	if pc.Exe != "/usr/sbin/php-fpm" {
		t.Errorf("Exe: want /usr/sbin/php-fpm, got %q", pc.Exe)
	}
	// Identity must be populated synchronously so a connection landing 1ms
	// later sees a fully-formed Process on cache hit, not just UID.
	if pc.User == "" {
		t.Errorf("User: want non-empty (resolver lookup), got empty; pc=%+v", pc)
	}
}

func TestPopulateProcessCtxFromExecEventWithZeroPIDIsNoop(t *testing.T) {
	resetProcessCtxForTest()
	cache, _ := ProcessCtx()
	populateProcessCtxFromExec(cache, ExecEvent{PID: 0, Comm: "x"})
	if cache.Len() != 0 {
		t.Errorf("expected empty cache, got %d", cache.Len())
	}
}

func TestAttachProcessCtxToExecFinding(t *testing.T) {
	resetProcessCtxForTest()
	cache, _ := ProcessCtx()
	ev := ExecEvent{UID: 1001, PID: 4242, PPID: 1, Comm: "php-fpm", Filename: "/usr/sbin/php-fpm"}
	populateProcessCtxFromExec(cache, ev)
	f := alert.Finding{Check: "suspicious_process_exec", Message: "test", Timestamp: time.Now()}
	attachProcessCtxToExecFinding(cache, &f, ev)
	if f.Process == nil {
		t.Fatal("expected Process attached")
	}
	if f.Process.PID != 4242 || f.Process.UID != 1001 {
		t.Fatalf("Process = %+v", f.Process)
	}
}
