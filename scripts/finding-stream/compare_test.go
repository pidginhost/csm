package main

import (
	"bytes"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
)

var compareAddr = NewAnonymizer(testSalt()).mapAddr(netip.MustParseAddr("192.0.2.10"))
var compareOtherAddr = NewAnonymizer(testSalt()).mapAddr(netip.MustParseAddr("192.0.2.11"))

var compareTS = time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)

func legacyBlock(fid string, at time.Duration, reason string) anonAction {
	r := anonAction{V: 1, Format: 1, Timestamp: compareTS.Add(at), Op: "respond.block_ip", Action: "block", Actor: "daemon",
		FindingID: fid, anonTarget: anonTarget{Target: compareAddr, TargetKind: "ip"}, ReasonKind: reason, Result: "applied"}
	if reason == "asn_crawl" {
		r.Action, r.TargetKind, r.TargetPrefix = "block_subnet", "cidr", 24
	}
	return r
}

func admissionStep(fid string, at time.Duration) anonAction {
	return anonAction{V: 1, Format: 1, Timestamp: compareTS.Add(at), Op: "respond.block_ip", Action: "block_ip", Actor: "daemon",
		FindingID: fid, ActionID: "aid-" + strings.TrimPrefix(fid, "fid-"), ActionVersion: 3, anonTarget: anonTarget{Target: compareAddr, TargetKind: "ip"},
		ReasonKind: "admission_general", Result: "observe"}
}

func summary(hourEnd time.Duration, check, decision, refusal string, n uint64) anonAction {
	r := anonAction{V: 1, Format: 1, Timestamp: compareTS.Add(hourEnd), Op: "respond.block_ip", Action: "block_ip", Actor: "daemon",
		anonTarget: anonTarget{TargetKind: "empty"}, ReasonKind: "check", Check: check, Entry: "scan", Result: decision,
		Refusal: refusal, HasError: refusal != "", Count: n}
	if check == "http_asn_crawl" {
		r.Action, r.Entry = "block_subnet", "asn_crawl"
	}
	return r
}

func compareInputs(t *testing.T, findings []alert.AuditEvent, actions []anonAction) []string {
	t.Helper()
	dir := t.TempDir()
	fp, ap := filepath.Join(dir, "findings.jsonl"), filepath.Join(dir, "actions.jsonl")
	writeInput(t, fp, encodeLines(t, anySlice(findings)...))
	writeInput(t, ap, encodeLines(t, anySlice(actions)...))
	return []string{"compare", "--findings", fp, "--actions", ap}
}

// R11: every legacy automatic block in the preview window is matched by an
// admission step for its finding, by a coalesced admission or a designed
// refusal for its check in that hour or the next, or reported unexplained;
// Invalid and overflow refusals are totalled, and what the streams cannot
// show is named.
func TestCompareReportsTheR11Criteria(t *testing.T) {
	finding := func(fid, check string) alert.AuditEvent {
		return alert.AuditEvent{V: 1, Timestamp: compareTS, FindingID: fid, Severity: "CRITICAL", Check: check}
	}
	findings := []alert.AuditEvent{
		finding("fid-11111111111111111111111111111111", "pam_bruteforce"), finding("fid-22222222222222222222222222222222", "pam_bruteforce"), finding("fid-33333333333333333333333333333333", "http_asn_crawl"),
		finding("fid-44444444444444444444444444444444", "wp_login_bruteforce"), finding("fid-55555555555555555555555555555555", "pam_bruteforce"), finding("fid-66666666666666666666666666666666", "ftp_bruteforce"),
		finding("fid-77777777777777777777777777777777", "pam_bruteforce"),
	}
	operator := legacyBlock("fid-11111111111111111111111111111111", 15*time.Minute, "operator_cli")
	operator.Actor = "cli"
	early := legacyBlock("fid-22222222222222222222222222222222", -2*time.Hour, "scan")
	failed := legacyBlock("fid-11111111111111111111111111111111", 6*time.Minute, "scan")
	failed.Result = "failed"
	actions := []anonAction{
		legacyBlock("fid-11111111111111111111111111111111", 5*time.Minute, "scan"), admissionStep("fid-11111111111111111111111111111111", 5*time.Minute+time.Second),
		legacyBlock("fid-22222222222222222222222222222222", 20*time.Minute, "scan"),
		legacyBlock("fid-33333333333333333333333333333333", 30*time.Minute, "asn_crawl"),
		legacyBlock("fid-44444444444444444444444444444444", 40*time.Minute, "scan"),
		legacyBlock("fid-55555555555555555555555555555555", 3*time.Hour-time.Second, "incident"),
		legacyBlock("", 50*time.Minute, "central_intel"),
		legacyBlock("fid-66666666666666666666666666666666", 10*time.Minute, "scan"), admissionStep("fid-66666666666666666666666666666666", 3*time.Hour+30*time.Minute),
		legacyBlock("fid-77777777777777777777777777777777", 45*time.Minute, "scan"),
		operator, early, failed,
		summary(time.Hour, "pam_bruteforce", "coalesced", "", 1),
		summary(time.Hour, "http_asn_crawl", "refused", "attribution", 1),
		summary(time.Hour, "wp_login_bruteforce", "refused", "protected", 1),
		summary(time.Hour, "pam_bruteforce", "refused", "invalid", 2),
		summary(time.Hour, "pam_bruteforce", "refused", "queue_overflow", 1),
		func() anonAction {
			r := summary(4*time.Hour, "pam_bruteforce", "coalesced", "", 1)
			r.Entry = "incident"
			return r
		}(),
	}
	var out bytes.Buffer
	if err := run(compareInputs(t, findings, actions), &out); err != nil {
		t.Fatal(err)
	}
	want := `admission comparison
coverage: summary-hour span is nominal; counts are lower bounds; boundary hours may be partial; verify collector coverage, idle or missing hours and clean-stop completion
window: 2026-09-08T10:00:00Z to 2026-09-08T14:00:00Z, 4h0m0s: FAIL (needs 168h0m0s)
legacy automatic actions: 8
  matched by an admission step: 1
  matched by a coalesced admission: 2
  explained by a designed refusal: 1 (attribution 1)
  unexplained: 4: FAIL
    fid-66666666666666666666666666666666 ftp_bruteforce scan 2026-09-08T10:10:00Z
    fid-44444444444444444444444444444444 wp_login_bruteforce scan 2026-09-08T10:40:00Z
    fid-77777777777777777777777777777777 pam_bruteforce scan 2026-09-08T10:45:00Z
    no finding id central_intel 2026-09-08T10:50:00Z
invalid refusals: 2: FAIL
queue overflow refusals: 1: FAIL
read elsewhere: Critical deferrals and queue evictions (csm status, admission outcomes), handoff p99 (csm_admission_handoff_seconds), corruption/damage (csm status and doctor), collection and clean-stop coverage (collector inventory)
`
	if out.String() != want {
		t.Fatalf("report:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestComparePassesACleanWeek(t *testing.T) {
	findings := []alert.AuditEvent{{V: 1, Timestamp: compareTS, FindingID: "fid-11111111111111111111111111111111", Severity: "HIGH", Check: "pam_bruteforce"}}
	actions := []anonAction{
		legacyBlock("fid-11111111111111111111111111111111", 5*time.Minute, "scan"), admissionStep("fid-11111111111111111111111111111111", 5*time.Minute+time.Second),
		summary(time.Hour, "pam_bruteforce", "observe", "", 1), summary(7*24*time.Hour, "pam_bruteforce", "queued", "", 1),
	}
	var out bytes.Buffer
	if err := run(compareInputs(t, findings, actions), &out); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.Contains(line, "FAIL") {
			t.Errorf("clean week fails: %s", line)
		}
	}
	if !strings.Contains(out.String(), "168h0m0s: pass") {
		t.Fatalf("report:\n%s", out.String())
	}
}

func TestCompareRefusesBadInput(t *testing.T) {
	for name, args := range map[string][]string{
		"no actions":   {"compare", "--findings", "f.jsonl"},
		"no findings":  {"compare", "--actions", "a.jsonl"},
		"stray input":  {"compare", "--findings", "f.jsonl", "--actions", "a.jsonl", "x"},
		"unknown flag": {"compare", "--salt-file", "s"},
	} {
		if err := run(args, &bytes.Buffer{}); !errors.Is(err, errCompareUsage) {
			t.Errorf("%s: %v", name, err)
		}
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "actions.jsonl")
	writeInput(t, bad, []byte(`{"v":1,"op":"respond.block_ip","raw":"203.0.113.9"}`+"\n"))
	fp := filepath.Join(dir, "findings.jsonl")
	writeInput(t, fp, []byte{})
	var out bytes.Buffer
	if err := run([]string{"compare", "--findings", fp, "--actions", bad}, &out); err == nil || strings.Contains(err.Error(), "203.0.113.9") {
		t.Fatalf("raw row read as an anonymized one: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("a refused comparison printed %q", out.String())
	}
}

// Counts cannot explain another action family or entry, and one observed
// attempt cannot explain unrelated addresses or several legacy effects.
func TestCompareDoesNotBorrowUnrelatedDecisions(t *testing.T) {
	fid := "fid-" + strings.Repeat("1", 32)
	findings := []alert.AuditEvent{{V: 1, Timestamp: compareTS, FindingID: fid, Severity: "HIGH", Check: "pam_bruteforce"}}
	for name, change := range map[string]func(*anonAction){
		"other address": func(r *anonAction) { r.Target = compareOtherAddr },
		"other kind":    func(r *anonAction) { r.Action = "challenge" },
		"reserved only": func(r *anonAction) { r.Result = "reserved" },
	} {
		t.Run(name, func(t *testing.T) {
			step := admissionStep(fid, time.Minute)
			change(&step)
			actions := []anonAction{legacyBlock(fid, time.Minute, "scan"), step, summary(time.Hour, "pam_bruteforce", "queued", "", 1)}
			var out bytes.Buffer
			if err := run(compareInputs(t, findings, actions), &out); err != nil || !strings.Contains(out.String(), "unexplained: 1: FAIL") {
				t.Fatalf("borrowed decision: %v\n%s", err, out.String())
			}
		})
	}
	for name, change := range map[string]func(*anonAction){
		"other entry": func(r *anonAction) { r.Entry = "central" },
		"other kind":  func(r *anonAction) { r.Action = "challenge" },
	} {
		t.Run(name, func(t *testing.T) {
			r := summary(time.Hour, "pam_bruteforce", "coalesced", "", 1)
			change(&r)
			var out bytes.Buffer
			if err := run(compareInputs(t, findings, []anonAction{legacyBlock(fid, time.Minute, "scan"), r}), &out); err != nil || !strings.Contains(out.String(), "unexplained: 1: FAIL") {
				t.Fatalf("borrowed aggregate: %v\n%s", err, out.String())
			}
		})
	}
	var out bytes.Buffer
	actions := []anonAction{legacyBlock(fid, time.Minute, "scan"), legacyBlock(fid, 2*time.Minute, "scan"),
		admissionStep(fid, time.Minute), summary(time.Hour, "pam_bruteforce", "queued", "", 1)}
	if err := run(compareInputs(t, findings, actions), &out); err != nil || !strings.Contains(out.String(), "unexplained: 1: FAIL") {
		t.Fatalf("one preview matched twice: %v\n%s", err, out.String())
	}
}

func TestCompareLimitsDesignedRules(t *testing.T) {
	fid := "fid-" + strings.Repeat("1", 32)
	findings := []alert.AuditEvent{{V: 1, Timestamp: compareTS, FindingID: fid, Severity: "HIGH", Check: "pam_bruteforce"}}
	for _, reason := range []string{"policy", "attribution"} {
		var out bytes.Buffer
		if err := run(compareInputs(t, findings, []anonAction{legacyBlock(fid, time.Minute, "scan"),
			summary(time.Hour, "pam_bruteforce", "refused", reason, 1)}), &out); err != nil || !strings.Contains(out.String(), "unexplained: 1: FAIL") {
			t.Fatalf("unexpected refusal explained by %s: %v\n%s", reason, err, out.String())
		}
	}
	incident := legacyBlock(fid, time.Minute, "incident")
	missing := summary(time.Hour, "unknown", "refused", "policy", 1)
	missing.Entry = "incident"
	var incidentOut bytes.Buffer
	if err := run(compareInputs(t, findings, []anonAction{incident, incident, missing}), &incidentOut); err != nil ||
		!strings.Contains(incidentOut.String(), "explained by a designed refusal: 1 (policy 1)") || !strings.Contains(incidentOut.String(), "unexplained: 1: FAIL") {
		t.Fatalf("restored rootless temporary incident did not consume exactly one unknown count: %v\n%s", err, incidentOut.String())
	}
	served := missing
	served.Check = "pam_bruteforce"
	var servedOut bytes.Buffer
	if err := run(compareInputs(t, findings, []anonAction{incident, served}), &servedOut); err != nil || !strings.Contains(servedOut.String(), "unexplained: 1: FAIL") {
		t.Fatalf("a known-check policy refusal borrowed the rootless rule: %v\n%s", err, servedOut.String())
	}
	// A netblock has no retained root or finding link. Its exact entry and
	// kind may consume one fixed unknown-policy count, never more than one.
	r := summary(time.Hour, "unknown", "refused", "policy", 1)
	r.Entry, r.Action = "netblock", "block_subnet"
	legacy := legacyBlock("", time.Minute, "netblock")
	legacy.Action, legacy.TargetKind, legacy.TargetPrefix = "block_subnet", "cidr", 24
	var out bytes.Buffer
	if err := run(compareInputs(t, nil, []anonAction{legacy, legacy, r}), &out); err != nil ||
		!strings.Contains(out.String(), "explained by a designed refusal: 1 (policy 1)") || !strings.Contains(out.String(), "unexplained: 1: FAIL") {
		t.Fatalf("rootless policy count: %v\n%s", err, out.String())
	}
	permanent := incident
	permanent.Action = "permblock"
	var permanentOut bytes.Buffer
	if err := run(compareInputs(t, findings, []anonAction{permanent, missing}), &permanentOut); err != nil || !strings.Contains(permanentOut.String(), "explained by a designed refusal: 1 (policy 1)") {
		t.Fatalf("listed permanent incident refused: %v\n%s", err, permanentOut.String())
	}
}

func TestCompareRefusesIdentityShapedOutput(t *testing.T) {
	fid := "fid-" + strings.Repeat("1", 32)
	for name, change := range map[string]func(*anonAction){
		"raw finding id": func(r *anonAction) { r.FindingID = "customer.example" },
		"raw check":      func(r *anonAction) { r.Check = "customer_name"; r.Count = 1 },
		"raw address":    func(r *anonAction) { r.Target = "203.0.113.9" },
		"bad version":    func(r *anonAction) { r.Format = 0 },
		"unknown kind":   func(r *anonAction) { r.Action = "unexpected" },
	} {
		t.Run(name, func(t *testing.T) {
			r := legacyBlock(fid, time.Minute, "scan")
			change(&r)
			var out bytes.Buffer
			err := run(compareInputs(t, nil, []anonAction{r}), &out)
			if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "customer") || strings.Contains(err.Error(), "203.0.113.9") {
				t.Fatalf("invalid shape repeated input: %v %q", err, out.String())
			}
		})
	}
	for _, mutate := range []func(*alert.AuditEvent){
		func(f *alert.AuditEvent) { f.Check = "customer_name" },
		func(f *alert.AuditEvent) { f.FindingID = "customer.example" },
	} {
		f := alert.AuditEvent{V: 1, Timestamp: compareTS, FindingID: fid, Severity: "HIGH", Check: "pam_bruteforce"}
		mutate(&f)
		var out bytes.Buffer
		if err := run(compareInputs(t, []alert.AuditEvent{f}, nil), &out); err == nil || out.Len() != 0 {
			t.Fatalf("finding identity accepted: %v %q", err, out.String())
		}
	}
}

// This is a joined run with real writer row shapes. Anonymize must verify
// every row before compare can report the observed effect and summaries.
func TestCompareJoinedAdmissionRun(t *testing.T) {
	dir := t.TempDir()
	fp, ap := filepath.Join(dir, "raw-findings.jsonl"), filepath.Join(dir, "raw-actions.jsonl")
	fo, ao := filepath.Join(dir, "findings.jsonl.gz"), filepath.Join(dir, "actions.jsonl.gz")
	salt := filepath.Join(dir, "salt")
	writeTestSalt(t, salt)
	finding := alert.NewAuditEvent("host.example", alert.Finding{Check: "pam_bruteforce", Severity: alert.High, Timestamp: compareTS, Message: "Authentication failures"})
	legacy := actionlog.Record{V: 1, Timestamp: compareTS.Add(time.Minute), Op: "respond.block_ip", Action: "block", Actor: actionlog.Daemon,
		FindingID: finding.FindingID, Target: "192.0.2.10", Reason: "CSM auto-block: authentication failures", Result: actionlog.Applied}
	step := admissionRow("block_ip", "ip:192.0.2.10", "observe")
	step.Timestamp, step.FindingID = legacy.Timestamp.Add(time.Second), finding.FindingID
	reserved := step
	reserved.Result = "reserved"
	sum := summaryRow("observe", "")
	sum.Timestamp, sum.Reason, sum.ActorDetail, sum.Count = compareTS.Add(time.Hour), "pam_bruteforce", "scan", 1
	last := sum
	last.Timestamp, last.Result = compareTS.Add(7*24*time.Hour), "queued"
	remint := finding
	remint.Message = "Another report of the same observation"
	remint.FindingID = alert.FindingID(alert.Finding{Check: remint.Check, Severity: alert.High, Timestamp: remint.Timestamp, Message: remint.Message})
	secondLegacy := legacy
	secondLegacy.FindingID = remint.FindingID
	coalesced := sum
	coalesced.Result = "coalesced"
	writeInput(t, fp, encodeLines(t, finding, remint))
	writeInput(t, ap, encodeLines(t, legacy, secondLegacy, reserved, step, sum, coalesced, last))
	var anonOut bytes.Buffer
	if err := testRun().execute([]string{"anonymize", "--salt-file", salt, "--out", fo, "--actions", ap, "--actions-out", ao,
		"--manifest", filepath.Join(dir, "manifest.json"), fp}, &anonOut); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"compare", "--findings", fo, "--actions", ao}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"168h0m0s: pass", "legacy automatic actions: 2", "matched by an admission step: 1", "matched by a coalesced admission: 1", "unexplained: 0: pass", "invalid refusals: 0: pass"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q:\n%s", want, out.String())
		}
	}
}
func TestCompareMatchesSummaryBeforeTheLegacyHour(t *testing.T) {
	fid := "fid-" + strings.Repeat("a", 32)
	for _, decision := range []string{"coalesced", "refused"} {
		t.Run(decision, func(t *testing.T) {
			check := "pam_bruteforce"
			first := summary(time.Hour, check, decision, "", 1)
			last := summary(4*time.Hour, "pam_bruteforce", "queued", "", 1)
			legacy := legacyBlock(fid, time.Hour+time.Second, "scan")
			if decision == "refused" {
				first.Check, first.Refusal, first.Entry = "unknown", "policy", "incident"
				legacy.ReasonKind = "incident"
			}
			report, err := compareReport(map[string]string{fid: check}, []anonAction{first, legacy, last})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(report, "unexplained: 0: pass") {
				t.Fatalf("previous-hour handoff was missed:\n%s", report)
			}
			legacy.Timestamp = compareTS.Add(2*time.Hour + time.Second)
			report, err = compareReport(map[string]string{fid: check}, []anonAction{first, legacy, last})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(report, "unexplained: 1: FAIL") {
				t.Fatalf("a handoff two hours away matched:\n%s", report)
			}
		})
	}
}
