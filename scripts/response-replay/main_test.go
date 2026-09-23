package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/responsereplay"
)

const testRevision = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

func testRun() *replayRun {
	r := newRun()
	r.revision = func() toolRevision { return toolRevision{Revision: testRevision, GoVersion: "go1.27.1"} }
	return r
}

var fixtureT0 = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

func event(at time.Time, check string, sev alert.Severity, message, details string) alert.AuditEvent {
	return alert.AuditEvent{V: 1, Timestamp: at, FindingID: "alice-" + check, Severity: sev.String(), Check: check,
		Message: message, Details: details, Hostname: "alice-host.example.net", TenantID: "alice"}
}

func writeStream(t *testing.T, dir, name string, events ...alert.AuditEvent) string {
	t.Helper()
	var raw bytes.Buffer
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(append(line, '\n'))
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fixtureEvents is the plan's hand-calculated case: cap 2, one temporary
// slot, one hour scan leases. Three hard candidates at 12:00 give two scan
// blocks (the second evicts the first), one queued; a non-blockable row at
// 13:00 drains the queue after the first leases expired; a recorded
// challenge-timeout block at 13:01 with a 30 minute lease evicts it.
func fixtureEvents() []alert.AuditEvent {
	return []alert.AuditEvent{
		event(fixtureT0, "smtp_bruteforce", alert.Critical, "SMTP brute force from 203.0.113.1", ""),
		event(fixtureT0, "smtp_bruteforce", alert.Critical, "SMTP brute force from 203.0.113.2", ""),
		event(fixtureT0, "smtp_bruteforce", alert.Critical, "SMTP brute force from 203.0.113.3", ""),
		event(fixtureT0.Add(time.Hour), "unregistered_check", alert.Warning, "noise on alice", ""),
		event(fixtureT0.Add(61*time.Minute), "auto_block", alert.Critical, "AUTO-BLOCK: 203.0.113.4 blocked (expires in 30m0s)", "Reason: challenge timeout: no solve for alice"),
	}
}

func fixtureArgs(findings, out string, extra ...string) []string {
	args := []string{"--findings", findings, "--out", out, "--max-blocks-per-hour", "2", "--deny-temp-ip-limit", "1",
		"--block-expiry", "1h", "--seed", "1", "--hour-zone", "UTC"}
	return append(args, extra...)
}

func readReport(t *testing.T, path string) (map[string]any, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m, raw
}

func sub(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		m = m[k].(map[string]any)
	}
	return m
}

func TestReplayReportsTheHandCalculatedFixture(t *testing.T) {
	dir := t.TempDir()
	findings := writeStream(t, dir, "alice-stream.jsonl.gz", fixtureEvents()...)
	out := filepath.Join(dir, "reports", "bob-report.json")
	var stdout bytes.Buffer
	if err := testRun().execute(fixtureArgs(findings, out), &stdout); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report is not private: %v %v", info, err)
	}
	report, raw := readReport(t, out)
	hyp := sub(report, "hypothetical")
	for key, want := range map[string]float64{
		"scan_blocked": 3, "exempt_blocked": 1, "evicted": 2, "aged_out": 0, "overflowed": 0, "final_pending": 0,
		"never_served": 0, "new_candidates": 3, "first_queued": 1, "eligible": 3, "missing_ip": 0, "challenge_skipped": 0,
		"already_blocked": 0, "invalid_pending": 0, "ineligible_pending": 0, "pending_satisfied": 0,
		"pending_high_water": 1, "live_high_water": 1,
	} {
		if hyp[key] != want {
			t.Errorf("hypothetical %s = %v, want %v", key, hyp[key], want)
		}
	}
	if share := sub(report, "hypothetical", "delayed_share"); share["numerator"] != 1.0 || share["denominator"] != 3.0 {
		t.Errorf("delayed share = %v", share)
	}
	dist := sub(report, "distributions")
	want := map[string]map[string]any{
		"queue_delay_ns":        {"count": 1.0, "p50": float64(time.Hour), "p90": float64(time.Hour), "p99": float64(time.Hour), "max": float64(time.Hour)},
		"eviction_residence_ns": {"count": 2.0, "p50": 0.0, "p90": float64(time.Minute), "p99": float64(time.Minute), "max": float64(time.Minute)},
		"hourly_scan_blocks":    {"count": 2.0, "p50": 1.0, "p90": 2.0, "p99": 2.0, "max": 2.0},
		"hourly_all_blocks":     {"count": 2.0, "p50": 2.0, "p90": 2.0, "p99": 2.0, "max": 2.0},
	}
	for key, w := range want {
		if !reflect.DeepEqual(dist[key], any(w)) {
			t.Errorf("distribution %s = %v, want %v", key, dist[key], w)
		}
	}
	recorded := sub(report, "recorded")
	for key, want := range map[string]float64{"block_rows": 1, "nonscan_blocks": 1, "nonscan_unmodeled": 0, "other_blocks": 0, "unclassified_auto_block_rows": 0} {
		if recorded[key] != want {
			t.Errorf("recorded %s = %v, want %v", key, recorded[key], want)
		}
	}
	input := sub(report, "input")
	fileBytes, err := os.ReadFile(findings)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(fileBytes)
	if input["sha256"] != hex.EncodeToString(sum[:]) || input["rows"] != 5.0 || input["batches"] != 3.0 || input["unstamped"] != 0.0 ||
		input["first_ts"] != "2026-09-08T12:00:00Z" || input["last_ts"] != "2026-09-08T13:01:00Z" {
		t.Errorf("input = %v", input)
	}
	if cov := sub(report, "coverage"); cov["legacy_manifest_unavailable"] != true {
		t.Errorf("coverage = %v", cov)
	}
	policy := sub(report, "policy")
	for key, want := range map[string]any{"max_blocks_per_hour": 2.0, "max_blocks_per_hour_defaulted": false, "deny_temp_ip_limit": 1.0,
		"block_expiry_ns": float64(time.Hour), "block_expiry_defaulted": false, "pending_bound": 1000.0,
		"pending_max_age_ns": float64(2 * time.Hour), "hour_zone": "UTC", "challenge_enabled": true,
		"http_scanner_action": "challenge", "block_cpanel_logins": false} {
		if policy[key] != want {
			t.Errorf("policy %s = %v, want %v", key, policy[key], want)
		}
	}
	if src := sub(report, "source"); src["revision"] != testRevision || src["dirty"] != false {
		t.Errorf("source = %v", src)
	}
	assertNoInput(t, "report", string(raw))
	assertNoInput(t, "summary", stdout.String())
	for _, line := range []string{"report: written", "rows: 5", "scan blocks: 3", "exempt blocks: 1", "evictions: 2", "delayed: 1 of 3"} {
		if !strings.Contains(stdout.String(), line) {
			t.Errorf("summary lacks %q:\n%s", line, stdout.String())
		}
	}
	assertReportVocabulary(t, report)

	// The same numbers straight from the model with the command's own
	// classifier.
	o := options{challengeEnabled: true, scannerAction: "challenge"}
	rec, err := responsereplay.ReadFindings(findings)
	if err != nil {
		t.Fatal(err)
	}
	model, err := responsereplay.NewLegacy(responsereplay.LegacyConfig{MaxPerHour: 2, DenyTempLimit: 1, BlockTTL: time.Hour,
		PendingBound: 1000, PendingMaxAge: 2 * time.Hour, HourLocation: time.UTC, Seed: 1}, newClassifier(o), responsereplay.LegacyState{})
	if err != nil {
		t.Fatal(err)
	}
	var scan, exempt, evicted int
	for _, b := range responsereplay.Batches(rec.Findings) {
		step, err := model.Step(b)
		if err != nil {
			t.Fatal(err)
		}
		scan, exempt, evicted = scan+step.Blocked, exempt+step.ExemptBlocked, evicted+step.Evicted
	}
	if float64(scan) != hyp["scan_blocked"] || float64(exempt) != hyp["exempt_blocked"] || float64(evicted) != hyp["evicted"] {
		t.Fatalf("report disagrees with the model: %d %d %d", scan, exempt, evicted)
	}
}

// planted identities and names that must never reach a report or message.
var planted = []string{"alice", "bob-report", "203.0.113.", "example.net", "no solve"}

func assertNoInput(t *testing.T, where, text string) {
	t.Helper()
	for _, p := range planted {
		if strings.Contains(text, p) {
			t.Errorf("%s carries %q", where, p)
		}
	}
}

var (
	hexDigest   = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
	goVersion   = regexp.MustCompile(`^go[0-9.]+$`)
	fixedValues = map[string]bool{"legacy_scan_admission": true, "sorted_keys_math_rand_shuffle": true, "UTC": true, "challenge": true, "block": true}
)

// assertReportVocabulary walks every value: strings are fixed vocabulary,
// digests, versions or timestamps, never text taken from the recording.
func assertReportVocabulary(t *testing.T, v any) {
	t.Helper()
	switch v := v.(type) {
	case map[string]any:
		for key, val := range v {
			if !regexp.MustCompile(`^[a-z0-9_]+$`).MatchString(key) {
				t.Errorf("report key %q", key)
			}
			assertReportVocabulary(t, val)
		}
	case []any:
		for _, item := range v {
			assertReportVocabulary(t, item)
		}
	case string:
		if _, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return
		}
		if !fixedValues[v] && !reportVocabulary[v] && !hexDigest.MatchString(v) && !goVersion.MatchString(v) && !bundleValue(v) {
			t.Errorf("report carries free text %q", v)
		}
	}
}

func bundleValue(v string) bool {
	switch v {
	case "present", "absent", "not_recorded", "not_supplied", "unavailable", "not_applicable":
		return true
	}
	return false
}

func TestReplayRoutingFlags(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name  string
		event alert.AuditEvent
		extra []string
		want  float64
	}{
		{"challenge on routes", event(fixtureT0, "wp_login_bruteforce", alert.High, "WordPress login brute force from 203.0.113.9", ""), nil, 0},
		{"challenge off blocks", event(fixtureT0, "wp_login_bruteforce", alert.High, "WordPress login brute force from 203.0.113.9", ""), []string{"--challenge-enabled=false"}, 1},
		{"scanner default routes", event(fixtureT0, "http_scanner_profile", alert.High, "URL scanner profile from 203.0.113.9", ""), nil, 0},
		{"scanner block", event(fixtureT0, "http_scanner_profile", alert.High, "URL scanner profile from 203.0.113.9", ""), []string{"--http-scanner-action=block"}, 1},
		{"cpanel off", event(fixtureT0, "cpanel_multi_ip_login", alert.High, "cPanel login from 203.0.113.9", ""), nil, 0},
		{"cpanel on", event(fixtureT0, "cpanel_multi_ip_login", alert.High, "cPanel login from 203.0.113.9", ""), []string{"--block-cpanel-logins"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := writeStream(t, dir, strings.ReplaceAll(tc.name, " ", "-")+".jsonl.gz", tc.event)
			out := filepath.Join(t.TempDir(), "report.json")
			if err := testRun().execute(fixtureArgs(findings, out, tc.extra...), &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			report, _ := readReport(t, out)
			if got := sub(report, "hypothetical")["scan_blocked"]; got != tc.want {
				t.Fatalf("scan_blocked = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReplayObservationParsing(t *testing.T) {
	dir := t.TempDir()
	findings := writeStream(t, dir, "obs.jsonl.gz",
		event(fixtureT0, "auto_block", alert.Critical, "AUTO-BLOCK: 203.0.113.1 blocked (expires in banana)", "Reason: challenge timeout: x"),
		event(fixtureT0, "auto_block", alert.Critical, "AUTO-BLOCK: 203.0.113.2 blocked (expires in 0s)", "Reason: CSM incident: x"),
		event(fixtureT0, "auto_block", alert.Critical, "AUTO-BLOCK: 203.0.113.3 blocked (expires in 24h0m0s)", "Reason: SMTP brute force from 203.0.113.3"),
		event(fixtureT0, "auto_block", alert.Critical, "AUTO-BLOCK: 203.0.113.4 blocked (expires in 1h0m0s)", ""),
		event(fixtureT0, "auto_block", alert.Warning, "AUTO-BLOCK [dry-run]: 203.0.113.5 would be blocked (expires in 1h0m0s)", "Reason: challenge timeout: x"),
		event(fixtureT0, "auto_block", alert.Critical, "AUTO-BLOCK-SUBNET: 203.0.113.0/24 blocked", "Reason: x"),
		event(fixtureT0, "auto_block", alert.Critical, "AUTO-BLOCK: 203.0.113.6 blocked (expires in 30m0s)", "Reason: central-intel (locally corroborated) (warning: covered by Cloudflare)"),
	)
	out := filepath.Join(t.TempDir(), "report.json")
	if err := testRun().execute(fixtureArgs(findings, out), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	report, _ := readReport(t, out)
	recorded := sub(report, "recorded")
	for key, want := range map[string]float64{"block_rows": 5, "nonscan_blocks": 1, "nonscan_unmodeled": 2, "other_blocks": 2, "unclassified_auto_block_rows": 2} {
		if recorded[key] != want {
			t.Errorf("recorded %s = %v, want %v", key, recorded[key], want)
		}
	}
	if got := sub(report, "hypothetical")["exempt_blocked"]; got != 1.0 {
		t.Errorf("exempt_blocked = %v", got)
	}
	// Recorded blocks are observations, never scan demand.
	if got := sub(report, "hypothetical")["eligible"]; got != 0.0 {
		t.Errorf("auto_block rows counted as demand: %v", got)
	}
}

func TestReplayEmptyAndReorderedStreams(t *testing.T) {
	dir := t.TempDir()
	empty := writeStream(t, dir, "empty.jsonl.gz")
	out := filepath.Join(dir, "empty.json")
	if err := testRun().execute(fixtureArgs(empty, out), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	report, _ := readReport(t, out)
	if d := sub(report, "distributions", "queue_delay_ns"); !reflect.DeepEqual(d, map[string]any{"count": 0.0}) {
		t.Errorf("empty delay distribution = %v", d)
	}
	if in := sub(report, "input"); in["rows"] != 0.0 || in["first_ts"] != nil {
		t.Errorf("empty input = %v", in)
	}

	events := fixtureEvents()
	reversed := make([]alert.AuditEvent, len(events))
	for i := range events {
		reversed[len(events)-1-i] = events[i]
	}
	var results []map[string]any
	for i, evs := range [][]alert.AuditEvent{events, reversed} {
		findings := writeStream(t, dir, fmt.Sprintf("order-%d.jsonl.gz", i), evs...)
		out := filepath.Join(dir, fmt.Sprintf("order-%d.json", i))
		if err := testRun().execute(fixtureArgs(findings, out), &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		r, _ := readReport(t, out)
		results = append(results, r)
	}
	for _, key := range []string{"hypothetical", "distributions", "recorded"} {
		if !reflect.DeepEqual(results[0][key], results[1][key]) {
			t.Errorf("%s depends on row order", key)
		}
	}
}

func TestReplayIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	findings := writeStream(t, dir, "stream.jsonl.gz", fixtureEvents()...)
	var reports [][]byte
	for i := range 2 {
		out := filepath.Join(dir, fmt.Sprintf("r%d.json", i))
		if err := testRun().execute(fixtureArgs(findings, out), &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		_, raw := readReport(t, out)
		reports = append(reports, raw)
	}
	if !bytes.Equal(reports[0], reports[1]) {
		t.Fatal("identical runs wrote different reports")
	}
}

func bundleFor(t *testing.T, findings string, records int) string {
	t.Helper()
	raw, err := os.ReadFile(findings)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	m := responsereplay.BundleManifest{
		FormatVersion: 1, Tool: responsereplay.BundleTool{Revision: testRevision, GoVersion: "go1.27.1", ModuleVersion: "(devel)"},
		SaltFingerprint: "0123456789ab", AddressMap: "salted_not_topology_preserving",
		Inputs:        []responsereplay.BundleFile{{Kind: "findings", Ordinal: 1, SHA256: strings.Repeat("0", 64), Records: records}},
		Outputs:       []responsereplay.BundleFile{{Kind: "findings", Ordinal: 1, SHA256: hex.EncodeToString(sum[:]), Records: records}},
		DroppedFields: map[string]int{}, ActionResults: map[string]int{"applied": 4},
		Coverage: map[string]string{"findings": "present", "actions": "present", "firewall_audit": "not_supplied",
			"ledger": "unavailable", "review": "unavailable", "firewall_id_join": "not_applicable"},
		Join: responsereplay.BundleJoin{FindingRows: records, ActionRows: 4, ActionRowsMatched: 3},
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(findings), "manifest.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReplayCarriesTheJoinedManifest(t *testing.T) {
	dir := t.TempDir()
	findings := writeStream(t, dir, "stream.jsonl.gz", fixtureEvents()...)
	manifest := bundleFor(t, findings, 5)
	out := filepath.Join(dir, "report.json")
	if err := testRun().execute(fixtureArgs(findings, out, "--manifest", manifest), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	report, _ := readReport(t, out)
	m := sub(report, "manifest")
	if m["action_results"].(map[string]any)["applied"] != 4.0 || sub(report, "manifest", "join")["action_rows_matched"] != 3.0 ||
		sub(report, "manifest", "coverage")["actions"] != "present" || sub(report, "coverage")["legacy_manifest_unavailable"] != false {
		t.Fatalf("manifest not carried: %v", m)
	}
	// Recorded outcomes are carried apart; they are not replay demand.
	if sub(report, "hypothetical")["scan_blocked"] != 3.0 {
		t.Fatal("manifest outcomes changed the replay")
	}

	for name, records := range map[string]int{"records": 4} {
		mismatch := bundleFor(t, findings, records)
		if err := testRun().execute(fixtureArgs(findings, filepath.Join(dir, name+".json"), "--manifest", mismatch), &bytes.Buffer{}); !errors.Is(err, errManifestMismatch) {
			t.Errorf("%s mismatch: %v", name, err)
		}
	}
	other := writeStream(t, dir, "other.jsonl.gz", fixtureEvents()[:4]...)
	if err := testRun().execute(fixtureArgs(other, filepath.Join(dir, "digest.json"), "--manifest", bundleFor(t, findings, 4)), &bytes.Buffer{}); !errors.Is(err, errManifestMismatch) {
		t.Errorf("digest mismatch: %v", err)
	}
}

func TestReplayRefusals(t *testing.T) {
	dir := t.TempDir()
	findings := writeStream(t, dir, "alice-stream.jsonl.gz", fixtureEvents()...)
	manifest := bundleFor(t, findings, 5)
	badSeverity := writeStream(t, dir, "alice-severity.jsonl.gz", event(fixtureT0, "smtp_bruteforce", alert.Severity(42), "x", ""))
	notFile := filepath.Join(dir, "alice-file")
	if err := os.WriteFile(notFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "alice-dir")
	if err := os.Mkdir(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "alice-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "alice-out.json")
	required := func(drop string) []string {
		args := fixtureArgs(findings, out)
		for i := 0; i < len(args); i += 2 {
			if args[i] == drop {
				return append(append([]string{}, args[:i]...), args[i+2:]...)
			}
		}
		t.Fatalf("no flag %s", drop)
		return nil
	}
	for name, tc := range map[string]struct {
		args []string
		want error
	}{
		"no findings":      {required("--findings"), errUsage},
		"no out":           {required("--out"), errUsage},
		"no cap":           {required("--max-blocks-per-hour"), errUsage},
		"no deny limit":    {required("--deny-temp-ip-limit"), errUsage},
		"no seed":          {required("--seed"), errUsage},
		"no zone":          {required("--hour-zone"), errUsage},
		"unknown flag":     {append(fixtureArgs(findings, out), "--alice"), errUsage},
		"bad number":       {fixtureArgs(findings, out, "--seed", "alice"), errUsage},
		"negative deny":    {fixtureArgs(findings, out, "--deny-temp-ip-limit", "-1"), errPolicy},
		"bad zone":         {fixtureArgs(findings, out, "--hour-zone", "Alice/Nowhere"), errPolicy},
		"host zone":        {fixtureArgs(findings, out, "--hour-zone", "Local"), errPolicy},
		"bad expiry":       {fixtureArgs(findings, out, "--block-expiry", "alice"), errPolicy},
		"zero expiry":      {fixtureArgs(findings, out, "--block-expiry", "0s"), errPolicy},
		"bad action":       {fixtureArgs(findings, out, "--http-scanner-action", "alice"), errPolicy},
		"out is input":     {fixtureArgs(findings, findings), errOutputAlias},
		"out is manifest":  {fixtureArgs(findings, manifest, "--manifest", manifest), errOutputAlias},
		"out via link":     {fixtureArgs(findings, filepath.Join(link, filepath.Base(findings))), errOutputAlias},
		"out is directory": {fixtureArgs(findings, outDir), errUnsafeOutput},
		"unwritable out":   {fixtureArgs(findings, filepath.Join(notFile, "report.json")), errWrite},
		"bad severity":     {fixtureArgs(badSeverity, out), errSeverity},
		"missing input":    {fixtureArgs(filepath.Join(dir, "alice-missing.jsonl"), out), nil},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := testRun().execute(tc.args, &stdout)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || stdout.Len() != 0 {
				t.Fatalf("got %v, want %v; summary %q", err, tc.want, stdout.String())
			}
			assertNoInput(t, "error", err.Error())
			if strings.Contains(err.Error(), dir) {
				t.Fatalf("error carries a path: %v", err)
			}
			if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("a refused run wrote a report")
			}
		})
	}
	r := newRun()
	for _, rev := range []toolRevision{{}, {Revision: testRevision, Dirty: true}} {
		r.revision = func() toolRevision { return rev }
		if err := r.execute(fixtureArgs(findings, out), &bytes.Buffer{}); !errors.Is(err, errRevision) {
			t.Errorf("revision %+v: %v", rev, err)
		}
	}
}

func TestReplayRefusesTraversalAliases(t *testing.T) {
	for _, target := range []string{"findings", "manifest"} {
		for _, traversed := range []string{"input", "output"} {
			t.Run(target+"/"+traversed, func(t *testing.T) {
				dir := t.TempDir()
				parent := filepath.Join(dir, "private")
				child := filepath.Join(parent, "child")
				if err := os.MkdirAll(child, 0o700); err != nil {
					t.Fatal(err)
				}
				findings := writeStream(t, parent, "findings.jsonl.gz", fixtureEvents()...)
				manifest := bundleFor(t, findings, 5)
				protected := findings
				if target == "manifest" {
					protected = manifest
				}
				before, err := os.ReadFile(protected)
				if err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(dir, "link")
				if err = os.Symlink(child, link); err != nil {
					t.Fatal(err)
				}
				alias := link + "/../" + filepath.Base(protected)
				out := alias
				if traversed == "input" {
					out = protected
					if target == "manifest" {
						manifest = alias
					} else {
						findings = alias
					}
				}
				var stdout bytes.Buffer
				if err = testRun().execute(fixtureArgs(findings, out, "--manifest", manifest), &stdout); !errors.Is(err, errOutputAlias) || stdout.Len() != 0 {
					t.Errorf("alias not refused: %v; summary %q", err, stdout.String())
				}
				after, err := os.ReadFile(protected)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("protected input was replaced: %v", err)
				}
			})
		}
	}
}

func TestReplayCreatesReportThroughTraversal(t *testing.T) {
	dir := t.TempDir()
	findings := writeStream(t, dir, "findings.jsonl.gz", fixtureEvents()...)
	parent := filepath.Join(dir, "private")
	if err := os.MkdirAll(filepath.Join(parent, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(parent, "child"), link); err != nil {
		t.Fatal(err)
	}
	out := link + "/../reports/report.json"
	if err := testRun().execute(fixtureArgs(findings, out), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	readReport(t, filepath.Join(parent, "reports", "report.json"))
	if _, err := os.Stat(filepath.Join(dir, "reports")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created a directory outside the resolved destination: %v", err)
	}
}

func TestReplayObservationRequiresAnAddress(t *testing.T) {
	for _, target := range []string{"alice.example.net", "203.0.113.0/24", "203.0.113.1:443", "[2001:db8::1]"} {
		f := responsereplay.Finding{Check: "auto_block", Severity: "CRITICAL",
			Message: "AUTO-BLOCK: " + target + " blocked (expires in 1h0m0s)", Details: "Reason: challenge timeout: x"}
		if _, kind := classifyObservation(f); kind != observationUnclassified {
			t.Errorf("non-address %q counted as a live block: %v", target, kind)
		}
	}
}

func TestReplaySparseLongRecording(t *testing.T) {
	first := time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)
	last := time.Date(9999, 12, 31, 23, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	findings := writeStream(t, dir, "findings.jsonl.gz",
		event(first, "smtp_bruteforce", alert.Critical, "SMTP brute force from 203.0.113.1", ""),
		event(last, "smtp_bruteforce", alert.Critical, "SMTP brute force from 203.0.113.2", ""))
	out := filepath.Join(dir, "report.json")
	if err := testRun().execute(fixtureArgs(findings, out), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	r, _ := readReport(t, out)
	want := map[string]any{"count": float64((last.Unix()-first.Unix())/3600 + 1), "p50": 0.0, "p90": 0.0, "p99": 0.0, "max": 1.0}
	for _, kind := range []string{"hourly_scan_blocks", "hourly_all_blocks"} {
		if got := sub(r, "distributions", kind); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s = %v, want %v", kind, got, want)
		}
	}
}

func TestReplayResolvesDefaults(t *testing.T) {
	dir := t.TempDir()
	findings := writeStream(t, dir, "stream.jsonl.gz", fixtureEvents()...)
	out := filepath.Join(dir, "report.json")
	args := []string{"--findings", findings, "--out", out, "--max-blocks-per-hour", "0", "--deny-temp-ip-limit", "0", "--seed", "7", "--hour-zone", "Europe/Bucharest"}
	if err := testRun().execute(args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	report, _ := readReport(t, out)
	policy := sub(report, "policy")
	if policy["max_blocks_per_hour"] != 50.0 || policy["max_blocks_per_hour_defaulted"] != true || policy["block_expiry_ns"] != float64(24*time.Hour) ||
		policy["block_expiry_defaulted"] != true || policy["deny_temp_ip_limit"] != 0.0 || policy["hour_zone"] != "Europe/Bucharest" {
		t.Fatalf("policy = %v", policy)
	}
	if order := sub(report, "order"); order["seed"] != 7.0 || order["algorithm"] != "sorted_keys_math_rand_shuffle" {
		t.Fatalf("order = %v", order)
	}
}

// Work still queued when the recording ends was never served; it is
// reported apart from queue losses because the recording, not the queue,
// ended it.
func TestReplayCensorsPendingAtEnd(t *testing.T) {
	dir := t.TempDir()
	findings := writeStream(t, dir, "stream.jsonl.gz",
		event(fixtureT0, "smtp_bruteforce", alert.Critical, "SMTP brute force from 203.0.113.1", ""),
		event(fixtureT0, "smtp_bruteforce", alert.Critical, "SMTP brute force from 203.0.113.2", ""),
	)
	out := filepath.Join(dir, "report.json")
	args := []string{"--findings", findings, "--out", out, "--max-blocks-per-hour", "1", "--deny-temp-ip-limit", "0", "--seed", "1", "--hour-zone", "UTC"}
	if err := testRun().execute(args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	report, _ := readReport(t, out)
	hyp := sub(report, "hypothetical")
	if hyp["scan_blocked"] != 1.0 || hyp["final_pending"] != 1.0 || hyp["aged_out"] != 0.0 || hyp["overflowed"] != 0.0 || hyp["never_served"] != 1.0 {
		t.Fatalf("hypothetical = %v", hyp)
	}
}
