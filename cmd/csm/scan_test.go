package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

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

func TestScanFlagParseAllRequiresFull(t *testing.T) {
	_, err := parseScanFlags([]string{"--all"})
	if err == nil {
		t.Error("expected error: --all requires --full")
	}
}

func TestScanFlagParseAllWithFullAccepted(t *testing.T) {
	f, err := parseScanFlags([]string{"--all", "--full"})
	if err != nil {
		t.Fatalf("--all --full must be accepted: %v", err)
	}
	if !f.all {
		t.Error("all flag not set")
	}
	if !f.full {
		t.Error("full flag not set")
	}
	if f.account != "" {
		t.Errorf("account = %q, want empty for --all", f.account)
	}
}

func TestScanFlagParseAllWithAccountErrors(t *testing.T) {
	_, err := parseScanFlags([]string{"someuser", "--all", "--full"})
	if err == nil {
		t.Error("expected error: cannot combine --all with an account username")
	}
}

func TestScanFlagParseAllWithQueryFlagErrors(t *testing.T) {
	tests := [][]string{
		{"--all", "--full", "--status"},
		{"--all", "--full", "--report", "sj-1"},
		{"--all", "--full", "--cancel", "sj-1"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, err := parseScanFlags(args); err == nil {
				t.Fatal("expected error combining --all with query flag")
			}
		})
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
		// Use a sub-millisecond interval so the test does not sleep 2 s.
		runScanFullWithInterval(f, sender, time.Microsecond)
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

// TestRunScanCancelWith exercises runScanCancelWith against an injected sender.
// It asserts:
//   - exactly one command is issued: CmdScanCancel
//   - the cancel request carries the correct JobID
//   - the printed output contains the job ID and the returned state
func TestRunScanCancelWith(t *testing.T) {
	const jobID = "job-cancel-1"
	const wantState = "canceling"

	var capturedCmd string
	var capturedReq control.ScanCancelRequest

	sender := func(cmd string, args any) (json.RawMessage, error) {
		capturedCmd = cmd
		raw, _ := json.Marshal(args)
		if err := json.Unmarshal(raw, &capturedReq); err != nil {
			t.Errorf("unmarshal cancel args: %v", err)
		}
		resp, _ := json.Marshal(control.ScanCancelResponse{JobID: jobID, State: wantState})
		return resp, nil
	}

	f := scanFlags{
		cancelID:   jobID,
		jsonOutput: false,
	}

	out := captureStdout(t, func() {
		runScanCancelWith(f, sender)
	})

	if capturedCmd != control.CmdScanCancel {
		t.Errorf("command = %q, want %q", capturedCmd, control.CmdScanCancel)
	}
	if capturedReq.JobID != jobID {
		t.Errorf("cancel request JobID = %q, want %q", capturedReq.JobID, jobID)
	}
	if !strings.Contains(out, jobID) {
		t.Errorf("output %q does not contain job ID %q", out, jobID)
	}
	if !strings.Contains(out, wantState) {
		t.Errorf("output %q does not contain state %q", out, wantState)
	}
}

// TestRunScanFullWithAllScope verifies that when f.all is set, runScanFullWith
// sends an enqueue request with Scope="all" and Target="".
func TestRunScanFullWithAllScope(t *testing.T) {
	const jobID = "job-all-1"
	var capturedEnqReq control.ScanEnqueueRequest

	sender := func(cmd string, args any) (json.RawMessage, error) {
		raw, _ := json.Marshal(args)
		switch cmd {
		case control.CmdScanEnqueue:
			_ = json.Unmarshal(raw, &capturedEnqReq)
			resp, _ := json.Marshal(control.ScanEnqueueResponse{JobID: jobID, State: "queued"})
			return resp, nil
		default:
			t.Errorf("unexpected command (no --wait): %s", cmd)
			return nil, errors.New("unexpected cmd")
		}
	}

	f := scanFlags{
		all:  true,
		full: true,
		wait: false,
	}

	captureStdout(t, func() {
		runScanFullWith(f, sender)
	})

	if capturedEnqReq.Scope != "all" {
		t.Errorf("enqueue Scope = %q, want all", capturedEnqReq.Scope)
	}
	if capturedEnqReq.Target != "" {
		t.Errorf("enqueue Target = %q, want empty", capturedEnqReq.Target)
	}
}

// TestPrintJobRecordAllScopeProgress verifies that printJobRecord prints
// per-account progress fields when Scope=="all" and progress fields are set.
func TestPrintJobRecordAllScopeProgress(t *testing.T) {
	j := store.ScanJobRecord{
		ID:             "job-all-2",
		Scope:          "all",
		Target:         "all",
		State:          "running",
		AccountsTotal:  5,
		AccountsDone:   2,
		CurrentAccount: "192-0-2-acct",
	}

	out := captureStdout(t, func() {
		printJobRecord(j)
	})

	if !strings.Contains(out, "2/5") {
		t.Errorf("output %q does not contain accounts progress 2/5", out)
	}
	if !strings.Contains(out, "192-0-2-acct") {
		t.Errorf("output %q does not contain current account", out)
	}
}

// TestPrintScanReportWithAllScopeGroupsByAccount verifies that
// printScanReportWith groups findings by TenantID when job scope is "all".
func TestPrintScanReportWithAllScopeGroupsByAccount(t *testing.T) {
	const jobID = "job-all-3"

	findings := []alert.Finding{
		{Severity: alert.Warning, Check: "check_a", Message: "finding-alpha", TenantID: "198-51-100-acct"},
		{Severity: alert.Warning, Check: "check_b", Message: "finding-beta", TenantID: "203-0-113-acct"},
		{Severity: alert.Critical, Check: "check_c", Message: "finding-gamma", TenantID: "198-51-100-acct"},
	}

	sender := func(cmd string, args any) (json.RawMessage, error) {
		job := store.ScanJobRecord{ID: jobID, Scope: "all", Target: "all", State: "done", FindingCount: 3}
		resp, _ := json.Marshal(control.ScanReportResponse{
			Job:      job,
			Findings: findings,
			Total:    3,
		})
		return resp, nil
	}

	out := captureStdout(t, func() {
		printScanReportWith(jobID, false, sender)
	})

	// Both account headers must appear.
	if !strings.Contains(out, "198-51-100-acct") {
		t.Errorf("output %q missing account header 198-51-100-acct", out)
	}
	if !strings.Contains(out, "203-0-113-acct") {
		t.Errorf("output %q missing account header 203-0-113-acct", out)
	}
	// All three finding messages must appear.
	for _, f := range findings {
		if !strings.Contains(out, f.Message) {
			t.Errorf("output %q missing finding %q", out, f.Message)
		}
	}
	// The account header for 198-51-100-acct must appear before 203-0-113-acct
	// findings (findings are grouped, not interleaved).
	idx1 := strings.Index(out, "198-51-100-acct")
	idx2 := strings.Index(out, "finding-beta")
	idx3 := strings.Index(out, "203-0-113-acct")
	if idx1 < 0 || idx2 < 0 || idx3 < 0 {
		t.Fatal("missing expected content in output")
	}
	// The 198-51-100-acct header should appear, followed by its findings,
	// then the 203-0-113-acct header, then finding-beta.
	if idx3 >= idx2 {
		t.Errorf("expected 203-0-113-acct header before finding-beta, got idx3=%d idx2=%d", idx3, idx2)
	}
}
