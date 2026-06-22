package daemon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// newScanJobControlListener creates a ControlListener wired with a real
// ScanJobManager backed by a temporary bbolt store. The bbolt global is
// swapped in and restored via t.Cleanup so parallel tests do not interfere.
func newScanJobControlListener(t *testing.T) (*ControlListener, *store.DB) {
	t.Helper()
	c := newListenerForTest(t)

	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})

	mgr, err := NewScanJobManager(c.d.store, c.d.cfg)
	if err != nil {
		t.Fatalf("NewScanJobManager: %v", err)
	}
	t.Cleanup(func() { mgr.Stop() })
	c.scanJobs = mgr

	return c, db
}

// --- CmdScanEnqueue ---

func TestDispatchScanEnqueueReturnsJobID(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "account", Target: "missing_acct", RespectIgnores: true,
	})
	line, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	resp := c.dispatch(line)
	if !resp.OK {
		t.Fatalf("dispatch failed: %s", resp.Error)
	}
	var out control.ScanEnqueueResponse
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		t.Fatal(err)
	}
	if out.JobID == "" {
		t.Error("expected a non-empty job id")
	}
	if out.State != "queued" {
		t.Errorf("initial state: got %q, want %q", out.State, "queued")
	}
}

func TestDispatchScanEnqueueRejectsUnknownScope(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "server", Target: "someuser",
	})
	line, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	resp := c.dispatch(line)
	if resp.OK {
		t.Fatal("unknown scope must be rejected")
	}
	if !strings.Contains(resp.Error, "scope") {
		t.Errorf("expected scope error, got %q", resp.Error)
	}
}

func TestDispatchScanEnqueueAllScopeEmptyTarget(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "all", Target: "",
	})
	line, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	resp := c.dispatch(line)
	if !resp.OK {
		t.Fatalf("scope=all with empty target must be accepted: %s", resp.Error)
	}
	var out control.ScanEnqueueResponse
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		t.Fatal(err)
	}
	if out.JobID == "" {
		t.Error("expected a non-empty job id")
	}
}

func TestDispatchScanEnqueueAllScopeLiteralAllTarget(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "all", Target: "all",
	})
	line, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	resp := c.dispatch(line)
	if !resp.OK {
		t.Fatalf("scope=all with target=\"all\" must be accepted: %s", resp.Error)
	}
}

func TestDispatchScanEnqueueAllScopeRejectsQuarantine(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "all", Target: "", Quarantine: true,
	})
	line, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	resp := c.dispatch(line)
	if resp.OK {
		t.Fatal("scope=all with quarantine must be rejected (server-wide remediation)")
	}
}

func TestDispatchScanEnqueueAllScopeRejectsJunkTarget(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "all", Target: "../etc",
	})
	line, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	resp := c.dispatch(line)
	if resp.OK {
		t.Fatal("scope=all with junk target must be rejected")
	}
	if !strings.Contains(resp.Error, "target") {
		t.Errorf("expected target error, got %q", resp.Error)
	}
}

func TestDispatchScanEnqueueRejectsEmptyTarget(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "account", Target: "",
	})
	line, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	resp := c.dispatch(line)
	if resp.OK {
		t.Fatal("empty target must be rejected")
	}
	if !strings.Contains(resp.Error, "target") {
		t.Errorf("expected target error, got %q", resp.Error)
	}
}

func TestDispatchScanEnqueueRejectsPathLikeTarget(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "account", Target: "../etc",
	})
	line, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	resp := c.dispatch(line)
	if resp.OK {
		t.Fatal("path-like target must be rejected")
	}
	if !strings.Contains(resp.Error, "invalid account target") {
		t.Errorf("expected invalid target error, got %q", resp.Error)
	}
}

func TestDispatchScanEnqueueNilManager(t *testing.T) {
	c := newListenerForTest(t)
	// c.scanJobs is nil -- must produce a clean error, not a panic.
	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "account", Target: "user",
	})
	line, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	resp := c.dispatch(line)
	if resp.OK {
		t.Fatal("nil manager must produce OK=false")
	}
	if resp.Error == "" {
		t.Error("nil manager must produce a non-empty error message")
	}
}

// --- CmdScanStatus ---

func TestDispatchScanStatusListsJobs(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	// Enqueue one job so the list is non-empty.
	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "account", Target: "user1",
	})
	enqLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	if r := c.dispatch(enqLine); !r.OK {
		t.Fatalf("enqueue failed: %s", r.Error)
	}

	// CmdScanStatus with empty job_id must list all jobs.
	statusArgs, _ := json.Marshal(control.ScanStatusRequest{})
	statusLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanStatus, Args: statusArgs})
	resp := c.dispatch(statusLine)
	if !resp.OK {
		t.Fatalf("scan.status failed: %s", resp.Error)
	}
	var out control.ScanStatusResponse
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Jobs) == 0 {
		t.Error("expected at least one job in the list")
	}
	if out.Job != nil {
		t.Error("list response must not set Job")
	}
}

func TestDispatchScanStatusSingleJob(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	// Enqueue a job to get a concrete ID.
	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "account", Target: "user2",
	})
	enqLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	enqResp := c.dispatch(enqLine)
	if !enqResp.OK {
		t.Fatalf("enqueue failed: %s", enqResp.Error)
	}
	var enqOut control.ScanEnqueueResponse
	if err := json.Unmarshal(enqResp.Result, &enqOut); err != nil {
		t.Fatal(err)
	}

	// CmdScanStatus with a concrete job_id must return that job.
	statusArgs, _ := json.Marshal(control.ScanStatusRequest{JobID: enqOut.JobID})
	statusLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanStatus, Args: statusArgs})
	resp := c.dispatch(statusLine)
	if !resp.OK {
		t.Fatalf("scan.status by id failed: %s", resp.Error)
	}
	var out control.ScanStatusResponse
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		t.Fatal(err)
	}
	if out.Job == nil {
		t.Fatal("expected Job to be set for single-id request")
	}
	if out.Job.ID != enqOut.JobID {
		t.Errorf("job id: got %q, want %q", out.Job.ID, enqOut.JobID)
	}
	if out.Jobs != nil {
		t.Error("single-id response must not set Jobs")
	}
}

func TestDispatchScanStatusUnknownID(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	statusArgs, _ := json.Marshal(control.ScanStatusRequest{JobID: "sj-doesnotexist"})
	statusLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanStatus, Args: statusArgs})
	resp := c.dispatch(statusLine)
	if resp.OK {
		t.Fatal("unknown job id must produce OK=false")
	}
}

func TestDispatchScanStatusNilManager(t *testing.T) {
	c := newListenerForTest(t)
	line, _ := json.Marshal(control.Request{Cmd: control.CmdScanStatus})
	resp := c.dispatch(line)
	if resp.OK {
		t.Fatal("nil manager must produce OK=false")
	}
}

// --- CmdScanReport ---

func TestDispatchScanReportReturnsFindingsAndTotal(t *testing.T) {
	c, db := newScanJobControlListener(t)

	// Enqueue a job to get a concrete ID.
	args, _ := json.Marshal(control.ScanEnqueueRequest{
		Scope: "account", Target: "user3",
	})
	enqLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: args})
	enqResp := c.dispatch(enqLine)
	if !enqResp.OK {
		t.Fatalf("enqueue failed: %s", enqResp.Error)
	}
	var enqOut control.ScanEnqueueResponse
	if err := json.Unmarshal(enqResp.Result, &enqOut); err != nil {
		t.Fatal(err)
	}

	// Seed one finding directly into the store.
	f := alert.Finding{Severity: alert.Warning, Check: "test_check", Message: "test finding"}
	if err := db.AppendScanJobFinding(enqOut.JobID, 0, f); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	reportArgs, _ := json.Marshal(control.ScanReportRequest{JobID: enqOut.JobID})
	reportLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanReport, Args: reportArgs})
	resp := c.dispatch(reportLine)
	if !resp.OK {
		t.Fatalf("scan.report failed: %s", resp.Error)
	}
	var out control.ScanReportResponse
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 1 {
		t.Errorf("total: got %d, want 1", out.Total)
	}
	if len(out.Findings) != 1 {
		t.Errorf("findings: got %d, want 1", len(out.Findings))
	}
	if out.Job.ID != enqOut.JobID {
		t.Errorf("job id: got %q, want %q", out.Job.ID, enqOut.JobID)
	}
}

func TestDispatchScanReportRequiresJobID(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	reportArgs, _ := json.Marshal(control.ScanReportRequest{JobID: ""})
	reportLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanReport, Args: reportArgs})
	resp := c.dispatch(reportLine)
	if resp.OK {
		t.Fatal("empty job_id must be rejected")
	}
}

func TestDispatchScanReportUnknownID(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	reportArgs, _ := json.Marshal(control.ScanReportRequest{JobID: "sj-nope"})
	reportLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanReport, Args: reportArgs})
	resp := c.dispatch(reportLine)
	if resp.OK {
		t.Fatal("unknown job id must produce OK=false")
	}
}

func TestDispatchScanReportNilManager(t *testing.T) {
	c := newListenerForTest(t)
	reportArgs, _ := json.Marshal(control.ScanReportRequest{JobID: "sj-x"})
	reportLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanReport, Args: reportArgs})
	resp := c.dispatch(reportLine)
	if resp.OK {
		t.Fatal("nil manager must produce OK=false")
	}
}

// --- CmdScanCancel ---

func TestDispatchScanCancelUnknownID(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	cancelArgs, _ := json.Marshal(control.ScanCancelRequest{JobID: "sj-doesnotexist"})
	cancelLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanCancel, Args: cancelArgs})
	resp := c.dispatch(cancelLine)
	if resp.OK {
		t.Fatal("canceling an unknown id must produce OK=false")
	}
}

func TestHandleScanCancelWrapsManagerError(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	cancelArgs, _ := json.Marshal(control.ScanCancelRequest{JobID: "sj-doesnotexist"})
	_, err := c.handleScanCancel(cancelArgs)
	if err == nil {
		t.Fatal("expected cancel error")
	}
	if !strings.Contains(err.Error(), "cancel:") {
		t.Fatalf("cancel error was not wrapped: %v", err)
	}
}

func TestDispatchScanCancelQueued(t *testing.T) {
	c, _ := newScanJobControlListener(t)

	// Block the worker so the second job stays queued.
	blockCh := make(chan struct{})
	c.scanJobs.runAccountScan = func(ctx context.Context, cfg *config.Config, st *state.Store, target string, opts checks.AccountScanOptions) []alert.Finding {
		select {
		case <-blockCh:
		case <-ctx.Done():
		}
		return nil
	}

	enqArgs1, _ := json.Marshal(control.ScanEnqueueRequest{Scope: "account", Target: "blocker"})
	enqLine1, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: enqArgs1})
	if r := c.dispatch(enqLine1); !r.OK {
		t.Fatalf("enqueue blocker: %s", r.Error)
	}

	enqArgs2, _ := json.Marshal(control.ScanEnqueueRequest{Scope: "account", Target: "queued"})
	enqLine2, _ := json.Marshal(control.Request{Cmd: control.CmdScanEnqueue, Args: enqArgs2})
	enqResp2 := c.dispatch(enqLine2)
	if !enqResp2.OK {
		t.Fatalf("enqueue queued job: %s", enqResp2.Error)
	}
	var enqOut2 control.ScanEnqueueResponse
	if err := json.Unmarshal(enqResp2.Result, &enqOut2); err != nil {
		t.Fatal(err)
	}

	cancelArgs, _ := json.Marshal(control.ScanCancelRequest{JobID: enqOut2.JobID})
	cancelLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanCancel, Args: cancelArgs})
	resp := c.dispatch(cancelLine)
	if !resp.OK {
		t.Fatalf("cancel queued job failed: %s", resp.Error)
	}
	var out control.ScanCancelResponse
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		t.Fatal(err)
	}
	if out.JobID != enqOut2.JobID {
		t.Errorf("job id: got %q, want %q", out.JobID, enqOut2.JobID)
	}
	// Unblock the worker so cleanup doesn't hang.
	close(blockCh)
}

func TestDispatchScanCancelNilManager(t *testing.T) {
	c := newListenerForTest(t)
	cancelArgs, _ := json.Marshal(control.ScanCancelRequest{JobID: "sj-x"})
	cancelLine, _ := json.Marshal(control.Request{Cmd: control.CmdScanCancel, Args: cancelArgs})
	resp := c.dispatch(cancelLine)
	if resp.OK {
		t.Fatal("nil manager must produce OK=false")
	}
}
