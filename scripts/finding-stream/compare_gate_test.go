package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// statusFile writes a csm status --json snapshot taken during run, whose
// owner expects entries.
func statusFile(t *testing.T, run uint64, entries ...string) string {
	t.Helper()
	quoted := make([]string, len(entries))
	for i, e := range entries {
		quoted[i] = `"` + e + `"`
	}
	p := filepath.Join(t.TempDir(), "status.json")
	body := fmt.Sprintf(`{"snapshot":{"started_at":"2026-09-08T09:00:00Z","admission":{"ledger":{"ingress":{"generation":%d,"open":true}},"owner":{"executing":false,"block_entries":[%s]}}}}`+"\n", run, strings.Join(quoted, ","))
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// gateRun builds one run's records: scan blocks of pam_bruteforce each
// matched by its admission step, incident blocks each matched by a
// coalesced incident summary, and summaries whose stamps span span from
// the start: the first counts the hour before it.
func gateRun(epoch uint64, scans, incidents int, span time.Duration) ([]alert.AuditEvent, []anonAction) {
	var findings []alert.AuditEvent
	var actions []anonAction
	for i := range scans + incidents {
		fid := fmt.Sprintf("fid-%032x", epoch<<16|uint64(i))
		findings = append(findings, alert.AuditEvent{V: 1, Timestamp: compareTS, FindingID: fid, Severity: "HIGH", Check: "pam_bruteforce"})
		at := time.Duration(i)*time.Minute + 5*time.Minute
		if i < scans {
			actions = append(actions, legacyBlock(fid, at, "scan"), admissionStep(fid, at+time.Second))
			continue
		}
		actions = append(actions, legacyBlock(fid, at, "incident"))
		r := summary(time.Hour, "pam_bruteforce", "coalesced", "", 1)
		r.Entry, r.Epoch = "incident", epoch
		actions = append(actions, r)
	}
	first, last := summary(0, "pam_bruteforce", "observe", "", 1), summary(span, "pam_bruteforce", "queued", "", 1)
	first.Epoch, last.Epoch = epoch, epoch
	return findings, append(actions, first, last)
}

func compareGate(t *testing.T, findings []alert.AuditEvent, actions []anonAction, status string) string {
	t.Helper()
	args := compareInputs(t, findings, actions)
	if status != "" {
		args = append(args, "--status", status)
	}
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// A run passes at 48 hours once every expected entry, and every scan check
// that blocked, has three blocks matched by what admission did.
func TestCompareGatePassesACoveredRunAt48Hours(t *testing.T) {
	findings, actions := gateRun(2, 3, 3, 48*time.Hour)
	report := compareGate(t, findings, actions, statusFile(t, 2, "scan", "incident"))
	for _, want := range []string{
		"run 2\n", "window: 2026-09-08T10:00:00Z to 2026-09-10T10:00:00Z, 48h0m0s: pass",
		"  incident: 3 legacy, 3 matched: pass\n", "  scan pam_bruteforce: 3 legacy, 3 matched: pass\n",
		"gate: pass\n", "verdict: pass (run 2)\n",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("missing %q:\n%s", want, report)
		}
	}
}

// Under 48 hours a covered run still fails. The window starts at the
// first summary's stamp: the hour that summary counts may have begun
// before the run, so it is not counted.
func TestCompareGateNeeds48Hours(t *testing.T) {
	findings, actions := gateRun(2, 3, 3, 47*time.Hour)
	report := compareGate(t, findings, actions, statusFile(t, 2, "scan", "incident"))
	for _, want := range []string{"window: 2026-09-08T10:00:00Z to 2026-09-10T09:00:00Z, 47h0m0s: FAIL (needs 48h0m0s)", "gate: FAIL: needs 48h0m0s\n", "verdict: FAIL: run 2 does not pass the gate\n"} {
		if !strings.Contains(report, want) {
			t.Fatalf("missing %q:\n%s", want, report)
		}
	}
}

// An entry short of its floor holds the gate until the run spans seven
// days; then the gate passes and lists it as unproven. An expected entry
// that never blocked is short too.
func TestCompareGateWaitsForShortEntriesUpToSevenDays(t *testing.T) {
	status := statusFile(t, 2, "scan", "incident", "central")
	findings, actions := gateRun(2, 3, 2, 7*24*time.Hour-time.Hour)
	report := compareGate(t, findings, actions, status)
	for _, want := range []string{"  incident: 2 legacy, 2 matched: short\n", "  central: 0 legacy, 0 matched: short\n", "gate: FAIL: coverage short until 168h0m0s\n"} {
		if !strings.Contains(report, want) {
			t.Fatalf("missing %q:\n%s", want, report)
		}
	}
	findings, actions = gateRun(2, 3, 2, 7*24*time.Hour)
	report = compareGate(t, findings, actions, status)
	if !strings.Contains(report, "gate: pass; unproven: central, incident\n") || !strings.Contains(report, "verdict: pass (run 2)\n") {
		t.Fatalf("seven days did not pass with the short entries unproven:\n%s", report)
	}
}

// A scan check needs its own three matched blocks, and an expected scan
// entry with no block at all is short.
func TestCompareGateCountsScanChecksApart(t *testing.T) {
	findings, actions := gateRun(2, 2, 0, 48*time.Hour)
	report := compareGate(t, findings, actions, statusFile(t, 2, "scan"))
	if !strings.Contains(report, "  scan pam_bruteforce: 2 legacy, 2 matched: short\n") || !strings.Contains(report, "gate: FAIL: coverage short until 168h0m0s\n") {
		t.Fatalf("a scan check short of three passed:\n%s", report)
	}
	findings, actions = gateRun(2, 0, 0, 48*time.Hour)
	report = compareGate(t, findings, actions, statusFile(t, 2, "scan"))
	if !strings.Contains(report, "  scan: 0 legacy, 0 matched: short\n") {
		t.Fatalf("an expected scan entry without blocks:\n%s", report)
	}
}

// Each run is reported alone, and only the run the status was taken in is
// judged: the status names the entries that run expects, not an earlier
// run's. Two runs of 30 hours do not make 48, an unexplained block in an
// earlier run does not fail the current one, and a passing earlier run
// does not pass a failing current one.
func TestCompareJudgesTheStatusRun(t *testing.T) {
	f1, a1 := gateRun(1, 3, 0, 30*time.Hour)
	f2, a2 := gateRun(2, 3, 0, 60*time.Hour)
	for i := range a2 {
		a2[i].Timestamp = a2[i].Timestamp.Add(31 * time.Hour)
	}
	bad := legacyBlock("fid-"+strings.Repeat("e", 32), 10*time.Hour, "scan")
	f1 = append(f1, alert.AuditEvent{V: 1, Timestamp: compareTS, FindingID: bad.FindingID, Severity: "HIGH", Check: "pam_bruteforce"})
	report := compareGate(t, append(f1, f2...), append(append(a1, bad), a2...), statusFile(t, 2, "scan"))
	runs := strings.Split(report, "\nrun ")
	if len(runs) != 3 || !strings.HasPrefix(runs[1], "1\n") || !strings.HasPrefix(runs[2], "2\n") {
		t.Fatalf("runs not reported apart:\n%s", report)
	}
	if !strings.Contains(runs[1], "unexplained: 1: FAIL") || !strings.Contains(runs[1], "gate: not judged: the status is of run 2") {
		t.Fatalf("run 1:\n%s", runs[1])
	}
	if !strings.Contains(runs[2], "unexplained: 0: pass") || !strings.Contains(runs[2], "gate: pass\n") || !strings.Contains(report, "verdict: pass (run 2)\n") {
		t.Fatalf("run 2:\n%s", runs[2])
	}
	f1, a1 = gateRun(1, 3, 0, 60*time.Hour)
	f2, a2 = gateRun(2, 3, 0, 60*time.Hour)
	for i := range a2 {
		a2[i].Timestamp = a2[i].Timestamp.Add(61 * time.Hour)
	}
	late := legacyBlock(bad.FindingID, 71*time.Hour, "scan")
	f1 = append(f1, alert.AuditEvent{V: 1, Timestamp: compareTS, FindingID: bad.FindingID, Severity: "HIGH", Check: "pam_bruteforce"})
	report = compareGate(t, append(f1, f2...), append(append(a1, late), a2...), statusFile(t, 2, "scan"))
	if runs = strings.Split(report, "\nrun "); len(runs) != 3 || !strings.Contains(runs[1], "60h0m0s: pass") || !strings.Contains(runs[1], "unexplained: 0: pass") {
		t.Fatalf("an earlier clean run:\n%s", report)
	}
	if !strings.Contains(runs[2], "gate: FAIL: unexplained, invalid or queue overflow decisions\n") || !strings.Contains(report, "verdict: FAIL: run 2 does not pass the gate\n") {
		t.Fatalf("a passing earlier run passed the current one:\n%s", report)
	}
	if report = compareGate(t, append(f1, f2...), append(append(a1, bad), a2...), statusFile(t, 3, "scan")); !strings.Contains(report, "verdict: FAIL: no summaries of run 3\n") {
		t.Fatalf("a status of a run without summaries:\n%s", report)
	}
	f1, a1 = gateRun(1, 3, 0, 30*time.Hour)
	f2, a2 = gateRun(2, 3, 0, 30*time.Hour)
	for i := range a2 {
		a2[i].Timestamp = a2[i].Timestamp.Add(31 * time.Hour)
	}
	if report = compareGate(t, append(f1, f2...), append(a1, a2...), statusFile(t, 2, "scan")); !strings.Contains(report, "verdict: FAIL: run 2 does not pass the gate\n") {
		t.Fatalf("two short runs passed together:\n%s", report)
	}
}

// Summaries recorded before they named their run may mix runs, so they
// never pass the gate; and without the host's status the gate cannot
// know which entries to expect.
func TestCompareGateRefusesUnmarkedRunsAndMissingStatus(t *testing.T) {
	findings, actions := gateRun(0, 3, 0, 7*24*time.Hour)
	report := compareGate(t, findings, actions, statusFile(t, 2, "scan"))
	if !strings.Contains(report, "run unmarked\n") || !strings.Contains(report, "gate: FAIL: summaries name no run\n") || !strings.Contains(report, "verdict: FAIL: no summaries of run 2\n") {
		t.Fatalf("an unmarked run:\n%s", report)
	}
	findings, actions = gateRun(2, 3, 0, 48*time.Hour)
	if report = compareGate(t, findings, actions, ""); !strings.Contains(report, "gate: FAIL: no status file\n") || !strings.Contains(report, "verdict: FAIL: no status file\n") {
		t.Fatalf("no status file:\n%s", report)
	}
}

// The status file must be one JSON document within the size bound that
// names the owner's run and its entries, from the closed list of entries
// that run automatic IP blocks; errors never repeat its path.
func TestCompareStatusFileIsChecked(t *testing.T) {
	findings, actions := gateRun(2, 3, 0, 48*time.Hour)
	dir := t.TempDir()
	const valid = `{"snapshot":{"admission":{"ledger":{"ingress":{"generation":2}},"owner":{"block_entries":["scan"]}}}}`
	for name, body := range map[string]string{
		"unknown entry":  `{"snapshot":{"admission":{"ledger":{"ingress":{"generation":2}},"owner":{"block_entries":["netblock"]}}}}`,
		"free text":      `{"snapshot":{"admission":{"ledger":{"ingress":{"generation":2}},"owner":{"block_entries":["customer.example"]}}}}`,
		"no owner":       `{"snapshot":{"admission":{"ledger":{"ingress":{"generation":2}}}}}`,
		"no run":         `{"snapshot":{"admission":{"owner":{"block_entries":["scan"]}}}}`,
		"run zero":       `{"snapshot":{"admission":{"ledger":{"ingress":{"generation":0}},"owner":{"block_entries":["scan"]}}}}`,
		"no admission":   `{"snapshot":{}}`,
		"malformed json": `{"snapshot":`,
		"trailing data":  valid + ` {}`,
		"oversize":       valid + strings.Repeat(" ", 64<<20),
	} {
		p := filepath.Join(dir, "customer.example.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err := run(append(compareInputs(t, findings, actions), "--status", p), &out)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "customer") {
			t.Errorf("%s: err %v, output %q", name, err, out.String())
		}
	}
	// The same document, ending in whitespace up to the bound, is read.
	p := filepath.Join(dir, "status.json")
	if err := os.WriteFile(p, []byte(valid+strings.Repeat(" ", 64<<20-len(valid))), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(append(compareInputs(t, findings, actions), "--status", p), &out); err != nil || !strings.Contains(out.String(), "verdict: pass (run 2)\n") {
		t.Fatalf("a valid status at the bound: err %v\n%s", err, out.String())
	}
}
