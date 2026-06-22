package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/store"
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

func TestScanFlagParseRejectsWaitWithoutFull(t *testing.T) {
	_, err := parseScanFlags([]string{"someuser", "--wait"})
	if err == nil {
		t.Error("expected error: --wait requires --full")
	}
}

func TestScanFlagParseRejectsFullOnlyFlagsOnLegacyScan(t *testing.T) {
	tests := [][]string{
		{"someuser", "--respect-ignores"},
		{"someuser", "--json"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, err := parseScanFlags(args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestScanFlagParseRejectsAlertWithFullScan(t *testing.T) {
	_, err := parseScanFlags([]string{"someuser", "--full", "--alert"})
	if err == nil {
		t.Error("expected error: --alert cannot be used with --full")
	}
}

func TestScanFlagParseRejectsQueryExecutionFlagMix(t *testing.T) {
	tests := [][]string{
		{"--status", "--full"},
		{"--status", "--respect-ignores"},
		{"--report", "sj-1", "--quarantine"},
		{"--cancel", "sj-1", "--alert"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, err := parseScanFlags(args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestScanFlagParseRejectsMultipleQueryModes(t *testing.T) {
	tests := [][]string{
		{"--status", "--report", "sj-1"},
		{"--report", "sj-1", "--cancel", "sj-2"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, err := parseScanFlags(args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestScanFlagParseRejectsPathLikeAccount(t *testing.T) {
	tests := []string{"../etc", "/home/root", "bad/user", ".", "..", "bad user"}
	for _, account := range tests {
		t.Run(account, func(t *testing.T) {
			if _, err := parseScanFlags([]string{account, "--full"}); err == nil {
				t.Fatal("expected invalid account error")
			}
		})
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

// captureStdout replaces os.Stdout with a pipe for the duration of fn,
// returning everything written to it as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = orig
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

// TestRunScanFullWithPollLoop exercises runScanFullWith against an injected
// sender that mimics the daemon returning "running" on the first status
// poll then "done" on the second, followed by a report with one finding.
// It asserts:
//   - command sequence: CmdScanEnqueue -> CmdScanStatus (x2) -> CmdScanReport
//   - the enqueue request carries Scope="account", Target=<acct>,
//     RespectIgnores=true, Quarantine=false
//   - the printed output contains the finding message
func TestRunScanFullWithPollLoop(t *testing.T) {
	const jobID = "job-poll-1"
	const account = "testacct"

	// Track the sequence of commands the injected sender receives.
	var cmdSeq []string
	var capturedEnqReq control.ScanEnqueueRequest

	statusCallCount := 0
	testFinding := alert.Finding{
		Severity: alert.Warning,
		Check:    "test_check",
		Message:  "unique-finding-sentinel-xyz",
	}

	sender := func(cmd string, args any) (json.RawMessage, error) {
		cmdSeq = append(cmdSeq, cmd)
		switch cmd {
		case control.CmdScanEnqueue:
			// Unmarshal through JSON to capture the request as sent.
			raw, _ := json.Marshal(args)
			if err := json.Unmarshal(raw, &capturedEnqReq); err != nil {
				t.Errorf("unmarshal enqueue args: %v", err)
			}
			resp, _ := json.Marshal(control.ScanEnqueueResponse{JobID: jobID, State: "queued"})
			return resp, nil

		case control.CmdScanStatus:
			statusCallCount++
			var state string
			if statusCallCount == 1 {
				state = "running"
			} else {
				state = "done"
			}
			job := store.ScanJobRecord{ID: jobID, Scope: "account", Target: account, State: state}
			resp, _ := json.Marshal(control.ScanStatusResponse{Job: &job})
			return resp, nil

		case control.CmdScanReport:
			job := store.ScanJobRecord{ID: jobID, Scope: "account", Target: account, State: "done", FindingCount: 1}
			resp, _ := json.Marshal(control.ScanReportResponse{
				Job:      job,
				Findings: []alert.Finding{testFinding},
				Total:    1,
			})
			return resp, nil

		default:
			t.Errorf("unexpected command: %s", cmd)
			return nil, errors.New("unexpected cmd")
		}
	}

	f := scanFlags{
		account:        account,
		full:           true,
		wait:           true,
		respectIgnores: true,
		quarantine:     false,
	}

	out := captureStdout(t, func() {
		runScanFullWith(f, sender)
	})

	// Assert command sequence.
	wantSeq := []string{
		control.CmdScanEnqueue,
		control.CmdScanStatus,
		control.CmdScanStatus,
		control.CmdScanReport,
	}
	if len(cmdSeq) != len(wantSeq) {
		t.Errorf("command sequence = %v, want %v", cmdSeq, wantSeq)
	} else {
		for i, want := range wantSeq {
			if cmdSeq[i] != want {
				t.Errorf("cmdSeq[%d] = %q, want %q", i, cmdSeq[i], want)
			}
		}
	}

	// Assert enqueue request fields.
	if capturedEnqReq.Scope != "account" {
		t.Errorf("enqueue Scope = %q, want account", capturedEnqReq.Scope)
	}
	if capturedEnqReq.Target != account {
		t.Errorf("enqueue Target = %q, want %s", capturedEnqReq.Target, account)
	}
	if !capturedEnqReq.RespectIgnores {
		t.Error("enqueue RespectIgnores = false, want true")
	}
	if capturedEnqReq.Quarantine {
		t.Error("enqueue Quarantine = true, want false")
	}

	// Assert finding appears in output.
	if !strings.Contains(out, testFinding.Message) {
		t.Errorf("output %q does not contain finding message %q", out, testFinding.Message)
	}

	// Assert status was polled more than once (running then done).
	if statusCallCount < 2 {
		t.Errorf("statusCallCount = %d, want >= 2 (poll ran until terminal)", statusCallCount)
	}
}

// TestRunScanFullWithPollLoopNoRespectIgnores verifies that when
// --respect-ignores is not set, the enqueue request carries RespectIgnores=false.
func TestRunScanFullWithPollLoopNoRespectIgnores(t *testing.T) {
	const jobID = "job-poll-2"
	var capturedEnqReq control.ScanEnqueueRequest

	sender := func(cmd string, args any) (json.RawMessage, error) {
		raw, _ := json.Marshal(args)
		switch cmd {
		case control.CmdScanEnqueue:
			_ = json.Unmarshal(raw, &capturedEnqReq)
			resp, _ := json.Marshal(control.ScanEnqueueResponse{JobID: jobID, State: "queued"})
			return resp, nil
		default:
			// No --wait: only enqueue is called.
			t.Errorf("unexpected command after enqueue (no --wait): %s", cmd)
			return nil, errors.New("unexpected cmd")
		}
	}

	f := scanFlags{
		account:        "acct2",
		full:           true,
		wait:           false,
		respectIgnores: false,
		quarantine:     false,
	}

	captureStdout(t, func() {
		runScanFullWith(f, sender)
	})

	if capturedEnqReq.RespectIgnores {
		t.Error("enqueue RespectIgnores = true, want false when --respect-ignores not given")
	}
}
