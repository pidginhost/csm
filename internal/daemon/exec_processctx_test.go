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
	if pc.User != "" || pc.Account != "" || len(pc.Cmdline) != 0 {
		t.Errorf("exec hot path should store only event data before async enrichment; pc=%+v", pc)
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

func TestAttachProcessCtxToExecFindingRejectsMismatchedCache(t *testing.T) {
	resetProcessCtxForTest()
	cache, _ := ProcessCtx()
	cache.PutFromExec(4242, 1, 1002, "curl", "/usr/bin/curl")

	ev := ExecEvent{UID: 1001, PID: 4242, PPID: 1, Comm: "php-fpm", Filename: "/usr/sbin/php-fpm"}
	f := alert.Finding{Check: "suspicious_process_exec", Message: "test", Timestamp: time.Now()}
	attachProcessCtxToExecFinding(cache, &f, ev)
	if f.Process != nil {
		t.Fatalf("expected stale cache hit to be ignored, got %+v", f.Process)
	}
}

func TestProcessctxRequestFromExecMapsFields(t *testing.T) {
	ev := ExecEvent{UID: 1001, PID: 4242, Comm: "php-fpm"}
	req := processctxRequestFromExec(ev)
	if req.PID != 4242 || req.UID != 1001 || req.Comm != "php-fpm" {
		t.Fatalf("request: %+v", req)
	}
	if !req.UIDKnown {
		t.Errorf("UIDKnown: want true (BPF event always knows UID)")
	}
}
