package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/store"
)

func incompleteScanFixture() (store.ScanJobRecord, []alert.Finding) {
	job := store.ScanJobRecord{ID: "job-incomplete", Scope: "account", Target: "alice", State: "done",
		Options: map[string]any{"quarantine": false}}
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "yara_match_scheduled", Message: "YARA rule match [x]: /home/alice/public_html/a.php"},
		{Severity: alert.High, Check: "yara_scan_incomplete", Message: "YARA deep scan could not cover 1 location(s)"},
	}
	return job, findings
}

// Two findings read as an almost clean account. A scan that stopped early
// says so before the findings, not only in one of them.
func TestReportFlagsIncompleteScan(t *testing.T) {
	job, findings := incompleteScanFixture()
	var buf bytes.Buffer
	if printScanReportTo(job.ID, false, &buf, makeScanReportSender(job, findings)) {
		t.Error("incomplete scan reported as complete")
	}
	out := buf.String()
	if warn := strings.Index(out, "INCOMPLETE"); warn < 0 || warn > strings.Index(out, "finding(s):") {
		t.Errorf("want the INCOMPLETE line before the findings; got:\n%s", out)
	}
	if printScanReportTo(job.ID, true, &bytes.Buffer{}, makeScanReportSender(job, findings)) {
		t.Error("JSON report of an incomplete scan reported as complete")
	}
	for _, check := range []string{"php_taint_scan_incomplete", "account_scan_truncated"} {
		gap := []alert.Finding{{Severity: alert.High, Check: check}}
		if printScanReportTo(job.ID, false, &bytes.Buffer{}, makeScanReportSender(job, gap)) {
			t.Errorf("%s did not mark the scan incomplete", check)
		}
	}
	if !printScanReportTo(job.ID, false, &bytes.Buffer{}, makeScanReportSender(job, findings[:1])) {
		t.Error("complete scan reported as incomplete")
	}
	job.State = "canceled"
	buf.Reset()
	if printScanReportTo(job.ID, false, &buf, makeScanReportSender(job, findings[:1])) {
		t.Error("canceled scan reported as complete")
	}
	// No gap finding explains a canceled job; the warning has to.
	if !strings.Contains(buf.String(), "INCOMPLETE: this scan was canceled") {
		t.Errorf("want the warning to name the canceled state; got:\n%s", buf.String())
	}
}

func TestReportFlagsFailedChecks(t *testing.T) {
	job, _ := incompleteScanFixture()
	for _, check := range []string{"check_timeout", "check_panic", "full_scan_file_too_large", "account_scan", "account_scan_error", "phishing_kit_archive_unscannable"} {
		for _, asJSON := range []bool{false, true} {
			var out bytes.Buffer
			findings := []alert.Finding{{Severity: alert.Warning, Check: check}}
			if printScanReportTo(job.ID, asJSON, &out, makeScanReportSender(job, findings)) {
				t.Errorf("%s, JSON=%v: failed check reported complete", check, asJSON)
			}
			if !asJSON && !strings.Contains(out.String(), "INCOMPLETE") {
				t.Errorf("%s: no incomplete warning", check)
			}
		}
	}
}

func TestReportFlagsTruncatedStoredFindings(t *testing.T) {
	job, _ := incompleteScanFixture()
	job.FindingsTruncated = true
	job.FindingCount = 2
	job.FindingsStored = 1
	findings := []alert.Finding{{Severity: alert.Critical, Check: "yara_match_scheduled"}}
	for _, asJSON := range []bool{false, true} {
		var out bytes.Buffer
		if printScanReportTo(job.ID, asJSON, &out, makeScanReportSender(job, findings)) {
			t.Errorf("JSON=%v: report with missing findings reported complete", asJSON)
		}
		if !asJSON && (!strings.Contains(out.String(), "INCOMPLETE") || !strings.Contains(out.String(), "findings were not stored")) {
			t.Errorf("truncated report warning missing: %s", out.String())
		}
	}
}

// A script must not take a scan that stopped early for a clean result.
func TestScanFullWaitExitsThreeWhenIncomplete(t *testing.T) {
	if os.Getenv("CSM_TEST_SCAN_INCOMPLETE") == "1" {
		job, findings := incompleteScanFixture()
		report := makeScanReportSender(job, findings)
		send := func(cmd string, args any) (json.RawMessage, error) {
			switch cmd {
			case control.CmdScanEnqueue:
				return json.Marshal(control.ScanEnqueueResponse{JobID: job.ID, State: "queued"})
			case control.CmdScanStatus:
				return json.Marshal(control.ScanStatusResponse{Job: &job})
			}
			return report(cmd, args)
		}
		runScanFullWithInterval(scanFlags{account: "alice", full: true, wait: true}, send, time.Microsecond)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestScanFullWaitExitsThreeWhenIncomplete$")
	cmd.Env = append(os.Environ(), "CSM_TEST_SCAN_INCOMPLETE=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 || !strings.Contains(string(out), "INCOMPLETE") {
		t.Fatalf("err = %v, want exit status 3 and an INCOMPLETE line; output:\n%s", err, out)
	}
}
