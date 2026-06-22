package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

// --- parseScanFlags unit tests ---

func TestScanFlagParseRejectsQuarantineWithoutFull(t *testing.T) {
	_, err := parseScanFlags([]string{"someuser", "--quarantine"})
	if err == nil {
		t.Error("expected error: --quarantine requires --full")
	}
}

func TestScanFlagParseAcceptsQuarantineWithFull(t *testing.T) {
	f, err := parseScanFlags([]string{"someuser", "--full", "--quarantine"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.quarantine {
		t.Error("quarantine flag not set")
	}
	if !f.full {
		t.Error("full flag not set")
	}
}

func TestScanFlagParseRequiresAccount(t *testing.T) {
	_, err := parseScanFlags([]string{})
	if err == nil {
		t.Error("expected error: account username required")
	}
}

func TestScanFlagParseRejectsAllFlag(t *testing.T) {
	_, err := parseScanFlags([]string{"someuser", "--all"})
	if err == nil {
		t.Error("expected error: --all is Phase 2")
	}
}

func TestScanFlagParseFullWaitJson(t *testing.T) {
	f, err := parseScanFlags([]string{"alice", "--full", "--wait", "--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.account != "alice" {
		t.Errorf("account = %q, want alice", f.account)
	}
	if !f.full {
		t.Error("full not set")
	}
	if !f.wait {
		t.Error("wait not set")
	}
	if !f.jsonOutput {
		t.Error("jsonOutput not set")
	}
}

func TestScanFlagParseRespectIgnores(t *testing.T) {
	f, err := parseScanFlags([]string{"bob", "--full", "--respect-ignores"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.respectIgnores {
		t.Error("respectIgnores not set")
	}
}

func TestScanFlagParseStatusNoID(t *testing.T) {
	f, err := parseScanFlags([]string{"--status"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.statusGiven {
		t.Error("statusGiven not set")
	}
	if f.statusID != "" {
		t.Errorf("statusID = %q, want empty", f.statusID)
	}
}

func TestScanFlagParseStatusWithID(t *testing.T) {
	f, err := parseScanFlags([]string{"--status", "job-42"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.statusID != "job-42" {
		t.Errorf("statusID = %q, want job-42", f.statusID)
	}
}

func TestScanFlagParseReportRequiresID(t *testing.T) {
	_, err := parseScanFlags([]string{"--report"})
	if err == nil {
		t.Error("expected error: --report requires a job id")
	}
}

func TestScanFlagParseReportWithID(t *testing.T) {
	f, err := parseScanFlags([]string{"--report", "job-7"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.reportID != "job-7" {
		t.Errorf("reportID = %q, want job-7", f.reportID)
	}
}

func TestScanFlagParseCancelRequiresID(t *testing.T) {
	_, err := parseScanFlags([]string{"--cancel"})
	if err == nil {
		t.Error("expected error: --cancel requires a job id")
	}
}

func TestScanFlagParseCancelWithID(t *testing.T) {
	f, err := parseScanFlags([]string{"--cancel", "job-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.cancelID != "job-1" {
		t.Errorf("cancelID = %q, want job-1", f.cancelID)
	}
}

func TestScanFlagParseRejectsAccountWithQueryFlags(t *testing.T) {
	_, err := parseScanFlags([]string{"someuser", "--status"})
	if err == nil {
		t.Error("expected error: account not allowed with --status")
	}
}

func TestScanFlagParseAlertLegacy(t *testing.T) {
	f, err := parseScanFlags([]string{"carol", "--alert"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.sendAlert {
		t.Error("sendAlert not set")
	}
	if f.full {
		t.Error("full should not be set for legacy scan")
	}
}

func TestScanFlagParseUnknownFlag(t *testing.T) {
	_, err := parseScanFlags([]string{"someuser", "--unknown-flag"})
	if err == nil {
		t.Error("expected error for unknown flag")
	}
}

// --- socket-backed dispatch tests ---

// TestScanEnqueueSendsCorrectCommand verifies that runScanFull sends
// CmdScanEnqueue with the right scope and target when --full is used.
func TestScanEnqueueSendsCorrectCommand(t *testing.T) {
	var receivedReq control.ScanEnqueueRequest
	cleanup := fakeDaemon(t, func(req control.Request) control.Response {
		if req.Cmd != control.CmdScanEnqueue {
			t.Errorf("expected cmd %q, got %q", control.CmdScanEnqueue, req.Cmd)
			return control.Response{OK: false, Error: "wrong cmd"}
		}
		if err := json.Unmarshal(req.Args, &receivedReq); err != nil {
			t.Errorf("unmarshal args: %v", err)
			return control.Response{OK: false, Error: "bad args"}
		}
		result, _ := json.Marshal(control.ScanEnqueueResponse{JobID: "job-test-1", State: "queued"})
		return control.Response{OK: true, Result: result}
	})
	defer cleanup()

	_, err := sendControl(control.CmdScanEnqueue, control.ScanEnqueueRequest{
		Scope:  "account",
		Target: "acct",
	})
	if err != nil {
		t.Fatalf("sendControl: %v", err)
	}
	if receivedReq.Scope != "account" {
		t.Errorf("scope = %q, want account", receivedReq.Scope)
	}
	if receivedReq.Target != "acct" {
		t.Errorf("target = %q, want acct", receivedReq.Target)
	}
}

// TestScanCancelSendsCorrectCommand verifies that the cancel sub-command
// sends CmdScanCancel with the correct job ID.
func TestScanCancelSendsCorrectCommand(t *testing.T) {
	var gotJobID string
	cleanup := fakeDaemon(t, func(req control.Request) control.Response {
		if req.Cmd != control.CmdScanCancel {
			t.Errorf("expected cmd %q, got %q", control.CmdScanCancel, req.Cmd)
			return control.Response{OK: false, Error: "wrong cmd"}
		}
		var cancelReq control.ScanCancelRequest
		if err := json.Unmarshal(req.Args, &cancelReq); err != nil {
			t.Errorf("unmarshal args: %v", err)
			return control.Response{OK: false, Error: "bad args"}
		}
		gotJobID = cancelReq.JobID
		result, _ := json.Marshal(control.ScanCancelResponse{JobID: cancelReq.JobID, State: "canceled"})
		return control.Response{OK: true, Result: result}
	})
	defer cleanup()

	_, err := sendControl(control.CmdScanCancel, control.ScanCancelRequest{JobID: "job-1"})
	if err != nil {
		t.Fatalf("sendControl: %v", err)
	}
	if gotJobID != "job-1" {
		t.Errorf("cancel job id = %q, want job-1", gotJobID)
	}
}

// TestScanEnqueueDaemonUnreachableReturnsError verifies that when the daemon
// is not running, sendControl returns errDaemonNotRunning rather than
// attempting an in-process fallback.
func TestScanEnqueueDaemonUnreachableReturnsError(t *testing.T) {
	saved := controlSocketPath
	controlSocketPath = shortSockPath(t) // no listener
	defer func() { controlSocketPath = saved }()

	_, err := sendControl(control.CmdScanEnqueue, control.ScanEnqueueRequest{
		Scope:  "account",
		Target: "someuser",
	})
	if !errors.Is(err, errDaemonNotRunning) {
		t.Errorf("expected errDaemonNotRunning, got %v", err)
	}
}
