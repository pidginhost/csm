package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

var joinTS = time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)

const testRevision = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

func testRun() *anonymizeRun {
	r := newRun()
	r.revision = func() toolRevision {
		return toolRevision{Revision: testRevision, GoVersion: "go1.27.1", ModuleVersion: "(devel)"}
	}
	return r
}

func encodeLines(t *testing.T, rows ...any) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, row := range rows {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func writeInput(t *testing.T, path string, data []byte) {
	t.Helper()
	if strings.HasSuffix(path, ".gz") {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		if _, err := zw.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		data = b.Bytes()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTestSalt(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, testSalt(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func readGzipRows(t *testing.T, path string) ([]map[string]any, string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, m)
	}
	return rows, string(body)
}

func readManifest(t *testing.T, path string) (map[string]any, string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m, string(raw)
}

type joinFixture struct {
	dir                                    string
	salt                                   string
	findings, actions, firewall            string
	out, actionsOut, firewallOut, manifest string
	findingRows, actionRows, firewallRows  []byte
	findingsRaw                            []alert.AuditEvent
	actionsRaw                             []actionlog.Record
	firewallRaw                            []firewall.AuditEntry
}

// Input and output names carry identities of their own: none may appear in
// any output, the manifest, the summary or an error.
func newJoinFixture(t *testing.T) *joinFixture {
	t.Helper()
	dir := t.TempDir()
	f := &joinFixture{
		dir:         dir,
		salt:        filepath.Join(dir, "salt"),
		findings:    filepath.Join(dir, "in", "alice-findings.jsonl"),
		actions:     filepath.Join(dir, "in", "bob-actions.jsonl.gz"),
		firewall:    filepath.Join(dir, "in", "carol-firewall.jsonl"),
		out:         filepath.Join(dir, "out", "dave-findings.jsonl.gz"),
		actionsOut:  filepath.Join(dir, "out", "erin-actions.jsonl.gz"),
		firewallOut: filepath.Join(dir, "out", "frank-firewall.jsonl.gz"),
		manifest:    filepath.Join(dir, "out", "grace-manifest.json"),
	}
	// Out of time order on purpose: rows keep their input order.
	f.findingsRaw = []alert.AuditEvent{
		{V: 1, Timestamp: joinTS.Add(time.Minute), FindingID: "fedcba9876543210", Severity: "HIGH", Check: "wp_login_bruteforce",
			Message: "WordPress login brute force from 203.0.113.10 on alice", Hostname: "srv.example.com", TenantID: "alice"},
		{V: 1, Timestamp: joinTS, FindingID: "0123456789abcdef", Severity: "CRITICAL", Check: "smtp_bruteforce",
			Message: "SMTP brute force from 203.0.113.9", Hostname: "srv.example.com"},
	}
	f.actionsRaw = []actionlog.Record{
		{V: 1, Timestamp: joinTS.Add(2 * time.Minute), Hostname: "srv.example.com", Op: "respond.block_ip", Action: "block",
			Actor: actionlog.Daemon, ActorDetail: "expires in 24h0m0s", FindingID: "0123456789abcdef", Target: "203.0.113.9",
			Reason: "CSM auto-block: SMTP brute force from 203.0.113.9", Result: actionlog.Applied},
		{V: 1, Timestamp: joinTS.Add(3 * time.Minute), Hostname: "srv.example.com", Op: "respond.block_ip", Action: "block",
			Actor: actionlog.Daemon, FindingID: "1111222233334444", Target: "203.0.113.10",
			Reason: "CSM challenge-timeout: no solve from 203.0.113.10", Result: actionlog.Applied},
		{V: 1, Timestamp: joinTS.Add(time.Second), Hostname: "srv.example.com", Op: "respond.quarantine_file", Actor: actionlog.WebUI,
			Target: "/home/alice/public_html/x.php", Account: "alice", Reason: "Fixed via CSM Web UI",
			Before: &actionlog.FileState{Exists: true, Digest: strings.Repeat("ab", 32), Size: 5, Mode: "-rw-r--r--", UID: 7340033, GID: 7340033},
			After:  &actionlog.FileState{}, Result: actionlog.Applied},
	}
	f.firewallRaw = []firewall.AuditEntry{
		{Timestamp: joinTS.Add(2 * time.Minute), Action: "block", IP: "203.0.113.9", Reason: "CSM auto-block: SMTP brute force from 203.0.113.9",
			Source: firewall.SourceAutoResponse, Duration: "24h0m0s"},
		{Timestamp: joinTS.Add(4 * time.Minute), Action: "flush", Reason: "cleared 3 entries", Source: firewall.SourceSystem},
	}
	f.findingRows = encodeLines(t, anySlice(f.findingsRaw)...)
	f.actionRows = encodeLines(t, anySlice(f.actionsRaw)...)
	f.firewallRows = encodeLines(t, anySlice(f.firewallRaw)...)
	f.write(t)
	writeTestSalt(t, f.salt)
	return f
}

func anySlice[T any](rows []T) []any {
	out := make([]any, len(rows))
	for i := range rows {
		out[i] = rows[i]
	}
	return out
}

func (f *joinFixture) write(t *testing.T) {
	t.Helper()
	writeInput(t, f.findings, f.findingRows)
	writeInput(t, f.actions, f.actionRows)
	writeInput(t, f.firewall, f.firewallRows)
}

func (f *joinFixture) args(extra ...string) []string {
	args := []string{"anonymize", "--salt-file", f.salt, "--out", f.out,
		"--actions", f.actions, "--actions-out", f.actionsOut,
		"--firewall-audit", f.firewall, "--firewall-out", f.firewallOut, "--manifest", f.manifest}
	args = append(args, extra...)
	return append(args, f.findings)
}

func (f *joinFixture) outputs() []string {
	return []string{f.out, f.actionsOut, f.firewallOut, f.manifest}
}

// planted returns every identity and file name the fixture introduced.
func (f *joinFixture) planted() []string {
	return []string{
		"alice", "srv.example.com", "203.0.113.9", "203.0.113.10", "0123456789abcdef", "fedcba9876543210",
		"1111222233334444", "/home/", "public_html", strings.Repeat("ab", 32), "rw-r--r--", "7340033",
		"alice-findings", "bob-actions", "carol-firewall", "dave-findings", "erin-actions", "frank-firewall",
		"grace-manifest", f.dir,
	}
}

func assertNoPlanted(t *testing.T, where, text string, planted []string) {
	t.Helper()
	for _, p := range planted {
		if strings.Contains(text, p) {
			t.Errorf("%s carries %q", where, p)
		}
	}
}

func TestRunJoinsRecordedOutcomes(t *testing.T) {
	f := newJoinFixture(t)
	var stdout bytes.Buffer
	if err := testRun().execute(f.args(), &stdout); err != nil {
		t.Fatalf("run: %v", err)
	}
	a := NewAnonymizer(testSalt())
	for _, path := range f.outputs() {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("output is not private: %v %v", info, err)
		}
	}
	if info, err := os.Stat(filepath.Dir(f.out)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("output directory is not private: %v %v", info, err)
	}

	findings, findingBody := readGzipRows(t, f.out)
	if len(findings) != 2 || findings[0]["finding_id"] != a.ID(idFinding, "fedcba9876543210") || findings[1]["finding_id"] != a.ID(idFinding, "0123456789abcdef") {
		t.Fatalf("finding rows lost order or ids: %v", findings)
	}
	actions, actionBody := readGzipRows(t, f.actionsOut)
	want := []map[string]any{
		{"v": 1.0, "format_version": 1.0, "ts": "2026-09-08T10:02:00Z", "hostname": a.Host("srv.example.com"),
			"op": "respond.block_ip", "action": "block", "actor": "daemon", "duration_ns": float64(24 * time.Hour),
			"finding_id": a.ID(idFinding, "0123456789abcdef"), "target": a.IPv4("203.0.113.9"), "target_kind": "ip",
			"reason_kind": "scan", "result": "applied", "has_error": false},
		{"v": 1.0, "format_version": 1.0, "ts": "2026-09-08T10:03:00Z", "hostname": a.Host("srv.example.com"),
			"op": "respond.block_ip", "action": "block", "actor": "daemon",
			"finding_id": a.ID(idFinding, "1111222233334444"), "target": a.IPv4("203.0.113.10"), "target_kind": "ip",
			"reason_kind": "challenge_timeout", "result": "applied", "has_error": false},
		{"v": 1.0, "format_version": 1.0, "ts": "2026-09-08T10:00:01Z", "hostname": a.Host("srv.example.com"),
			"account": a.Account("alice"), "op": "respond.quarantine_file", "actor": "webui",
			"target": a.ID(idTarget, "/home/alice/public_html/x.php"), "target_kind": "path",
			"reason_kind": "operator_webui", "result": "applied", "has_error": false, "before_exists": true, "after_exists": false},
	}
	if !reflect.DeepEqual(actions, want) {
		t.Fatalf("action rows:\n got %v\nwant %v", actions, want)
	}
	if actions[0]["finding_id"] != findings[1]["finding_id"] {
		t.Fatal("the matching action and finding carry different pseudonyms")
	}
	firewallRows, firewallBody := readGzipRows(t, f.firewallOut)
	wantFirewall := []map[string]any{
		{"format_version": 1.0, "ts": "2026-09-08T10:02:00Z", "action": "block", "target": a.IPv4("203.0.113.9"),
			"target_kind": "ip", "reason_kind": "scan", "source": "auto_response", "duration_ns": float64(24 * time.Hour)},
		{"format_version": 1.0, "ts": "2026-09-08T10:04:00Z", "action": "flush", "target_kind": "empty",
			"reason_kind": "flush", "source": "system"},
	}
	if !reflect.DeepEqual(firewallRows, wantFirewall) {
		t.Fatalf("firewall rows:\n got %v\nwant %v", firewallRows, wantFirewall)
	}

	manifest, manifestBody := readManifest(t, f.manifest)
	assertManifestKeys(t, manifest)
	join := manifest["join"].(map[string]any)
	wantJoin := map[string]any{
		"finding_rows": 2.0, "unique_finding_ids": 2.0, "duplicate_finding_rows": 0.0, "finding_rows_without_id": 0.0, "finding_rows_unstamped": 0.0,
		"action_rows": 3.0, "action_rows_with_finding_id": 2.0, "action_rows_matched": 1.0,
		"action_rows_missing_finding": 1.0, "action_rows_without_finding_id": 1.0,
		"durable_rows": 0.0, "durable_keys": 0.0, "durable_identical_duplicates": 0.0, "durable_conflicting_keys": 0.0,
		"firewall_rows": 2.0,
	}
	if !reflect.DeepEqual(join, wantJoin) {
		t.Fatalf("join counts:\n got %v\nwant %v", join, wantJoin)
	}
	wantInputs := []any{
		map[string]any{"kind": "findings", "ordinal": 1.0, "sha256": fileDigest(t, f.findings), "records": 2.0,
			"min_ts": "2026-09-08T10:00:00Z", "max_ts": "2026-09-08T10:01:00Z"},
		map[string]any{"kind": "actions", "ordinal": 1.0, "sha256": fileDigest(t, f.actions), "records": 3.0,
			"min_ts": "2026-09-08T10:00:01Z", "max_ts": "2026-09-08T10:03:00Z"},
		map[string]any{"kind": "firewall_audit", "ordinal": 1.0, "sha256": fileDigest(t, f.firewall), "records": 2.0,
			"min_ts": "2026-09-08T10:02:00Z", "max_ts": "2026-09-08T10:04:00Z"},
	}
	if !reflect.DeepEqual(manifest["inputs"], wantInputs) {
		t.Fatalf("inputs:\n got %v\nwant %v", manifest["inputs"], wantInputs)
	}
	wantOutputs := []any{
		map[string]any{"kind": "findings", "ordinal": 1.0, "sha256": fileDigest(t, f.out), "records": 2.0,
			"min_ts": "2026-09-08T10:00:00Z", "max_ts": "2026-09-08T10:01:00Z"},
		map[string]any{"kind": "actions", "ordinal": 1.0, "sha256": fileDigest(t, f.actionsOut), "records": 3.0,
			"min_ts": "2026-09-08T10:00:01Z", "max_ts": "2026-09-08T10:03:00Z"},
		map[string]any{"kind": "firewall_audit", "ordinal": 1.0, "sha256": fileDigest(t, f.firewallOut), "records": 2.0,
			"min_ts": "2026-09-08T10:02:00Z", "max_ts": "2026-09-08T10:04:00Z"},
	}
	if !reflect.DeepEqual(manifest["outputs"], wantOutputs) {
		t.Fatalf("outputs:\n got %v\nwant %v", manifest["outputs"], wantOutputs)
	}
	wantDropped := map[string]any{}
	for _, key := range droppedFieldKeys {
		wantDropped[key] = 0.0
	}
	for key, n := range map[string]float64{
		"action.reason": 3, "action.before.sha256": 1, "action.before.size": 1, "action.before.mode": 1,
		"action.before.uid": 1, "action.before.gid": 1, "firewall.reason": 2,
	} {
		wantDropped[key] = n
	}
	if !reflect.DeepEqual(manifest["dropped_fields"], wantDropped) {
		t.Fatalf("dropped fields:\n got %v\nwant %v", manifest["dropped_fields"], wantDropped)
	}
	wantResults := map[string]any{"applied": 3.0, "dry_run": 0.0, "failed": 0.0, "refused": 0.0, "verified": 0.0, "unknown": 0.0}
	if !reflect.DeepEqual(manifest["action_results"], wantResults) {
		t.Fatalf("results: %v", manifest["action_results"])
	}
	wantCoverage := map[string]any{"findings": "present", "actions": "present", "firewall_audit": "present",
		"ledger": "unavailable", "review": "unavailable", "firewall_id_join": "unavailable"}
	if !reflect.DeepEqual(manifest["coverage"], wantCoverage) {
		t.Fatalf("coverage: %v", manifest["coverage"])
	}
	wantTool := map[string]any{"revision": testRevision, "dirty": false, "go_version": "go1.27.1", "module_version": "(devel)"}
	if !reflect.DeepEqual(manifest["tool"], wantTool) {
		t.Fatalf("tool: %v", manifest["tool"])
	}
	if manifest["format_version"] != 1.0 || manifest["address_map"] != "salted_not_topology_preserving" ||
		!strings.Contains(stdout.String(), "salt fingerprint: "+manifest["salt_fingerprint"].(string)) {
		t.Fatalf("manifest header: %v", manifest)
	}

	planted := f.planted()
	for where, text := range map[string]string{"findings output": findingBody, "actions output": actionBody,
		"firewall output": firewallBody, "manifest": manifestBody, "summary": stdout.String()} {
		assertNoPlanted(t, where, text, planted)
	}
	for _, want := range []string{"events: 2", "action rows: 3", "firewall rows: 2", "checks: 2 distinct", "manifest: written"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "smtp_bruteforce") {
		t.Errorf("summary prints input check names:\n%s", stdout.String())
	}
	assertNoStaging(t, filepath.Dir(f.out))
}

var manifestKeys = map[string][]string{
	"":               {"format_version", "tool", "salt_fingerprint", "address_map", "addresses", "inputs", "outputs", "input_manifest", "join", "dropped_fields", "action_results", "coverage"},
	"addresses":      {"ipv4_addresses", "ipv4_pseudonyms", "ipv6_addresses", "ipv6_pseudonyms"},
	"tool":           {"revision", "dirty", "go_version", "module_version"},
	"inputs":         {"kind", "ordinal", "sha256", "records", "min_ts", "max_ts"},
	"outputs":        {"kind", "ordinal", "sha256", "records", "min_ts", "max_ts"},
	"input_manifest": {"sha256", "records"},
}

// Every key a manifest can carry is fixed by this tool; none comes from input.
func assertManifestKeys(t *testing.T, m map[string]any) {
	t.Helper()
	check := func(where string, obj map[string]any) {
		for k := range obj {
			if !slices.Contains(manifestKeys[where], k) {
				t.Errorf("manifest %s has unexpected key %q", where, k)
			}
		}
	}
	check("", m)
	for k, v := range m {
		switch v := v.(type) {
		case map[string]any:
			switch k {
			case "tool", "input_manifest", "addresses":
				check(k, v)
			case "join":
				for jk := range v {
					if !slices.Contains(joinKeys(), jk) {
						t.Errorf("join has unexpected key %q", jk)
					}
				}
			case "dropped_fields":
				for dk := range v {
					if !slices.Contains(droppedFieldKeys, dk) {
						t.Errorf("dropped_fields has unexpected key %q", dk)
					}
				}
			case "action_results":
				for rk := range v {
					if !actionResults[rk] {
						t.Errorf("action_results has unexpected key %q", rk)
					}
				}
			case "coverage":
				for ck, cv := range v {
					if !slices.Contains([]string{"findings", "actions", "firewall_audit", "ledger", "review", "firewall_id_join"}, ck) ||
						!slices.Contains([]string{"present", "absent", "not_recorded", "not_supplied", "unavailable", "not_applicable"}, cv.(string)) {
						t.Errorf("coverage entry %q=%v", ck, cv)
					}
				}
			}
		case []any:
			for _, item := range v {
				check(k, item.(map[string]any))
			}
		}
	}
}

func joinKeys() []string {
	var keys []string
	for _, f := range reflect.VisibleFields(reflect.TypeFor[joinCounts]()) {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		keys = append(keys, name)
	}
	return keys
}

// assertNoStaging fails when a temporary or backup file is left in dir.
func assertNoStaging(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".finding-stream-") {
			t.Errorf("staging file left behind: %s", e.Name())
		}
	}
}

func TestRunCountsRepeatedObservations(t *testing.T) {
	f := newJoinFixture(t)
	dup := f.findingsRaw[1]
	noID := f.findingsRaw[0]
	noID.FindingID = ""
	f.findingsRaw = []alert.AuditEvent{f.findingsRaw[1], dup, noID}
	base := actionlog.Record{V: 1, Timestamp: joinTS, Op: "respond.block_ip", Action: "block", Actor: actionlog.Daemon,
		Target: "203.0.113.9", FindingID: "0123456789abcdef"}
	row := func(id string, version uint64, result actionlog.Result) actionlog.Record {
		r := base
		r.ActionID, r.ActionVersion, r.Result = id, version, result
		return r
	}
	f.actionsRaw = []actionlog.Record{
		row("DURABLEACTION0001", 1, "unknown"),
		row("DURABLEACTION0001", 1, "unknown"), // retransmission
		row("DURABLEACTION0001", 2, "verified"),
		row("DURABLEACTION0002", 1, "verified"),
		row("DURABLEACTION0002", 1, "failed"), // same identity, different evidence
	}
	f.findingRows = encodeLines(t, anySlice(f.findingsRaw)...)
	f.actionRows = encodeLines(t, anySlice(f.actionsRaw)...)
	f.write(t)
	if err := testRun().execute(f.args(), io.Discard); err != nil {
		t.Fatal(err)
	}
	manifest, _ := readManifest(t, f.manifest)
	join := manifest["join"].(map[string]any)
	for key, want := range map[string]float64{
		"finding_rows": 3, "unique_finding_ids": 1, "duplicate_finding_rows": 1, "finding_rows_without_id": 1,
		"action_rows": 5, "action_rows_with_finding_id": 5, "action_rows_matched": 5,
		"durable_rows": 5, "durable_keys": 3, "durable_identical_duplicates": 1, "durable_conflicting_keys": 1,
	} {
		if join[key] != want {
			t.Errorf("%s = %v, want %v", key, join[key], want)
		}
	}
	wantResults := map[string]any{"applied": 0.0, "dry_run": 0.0, "failed": 1.0, "refused": 0.0, "verified": 2.0, "unknown": 1.0}
	if !reflect.DeepEqual(manifest["action_results"], wantResults) {
		t.Fatalf("a retransmission counted as another outcome: %v", manifest["action_results"])
	}
	actions, _ := readGzipRows(t, f.actionsOut)
	findings, _ := readGzipRows(t, f.out)
	if len(actions) != 5 || len(findings) != 3 || actions[0]["action_id"] != actions[1]["action_id"] || actions[3]["action_id"] == actions[0]["action_id"] {
		t.Fatalf("rows not retained in order: %d actions, %d findings", len(actions), len(findings))
	}
}

func TestRunReportsMissingStreams(t *testing.T) {
	f := newJoinFixture(t)
	args := []string{"anonymize", "--salt-file", f.salt, "--out", f.out, "--manifest", f.manifest, f.findings}
	if err := testRun().execute(args, io.Discard); err != nil {
		t.Fatal(err)
	}
	manifest, _ := readManifest(t, f.manifest)
	want := map[string]any{"findings": "present", "actions": "not_supplied", "firewall_audit": "not_supplied",
		"ledger": "unavailable", "review": "unavailable", "firewall_id_join": "not_applicable"}
	if !reflect.DeepEqual(manifest["coverage"], want) {
		t.Fatalf("coverage: %v", manifest["coverage"])
	}

	inventory := filepath.Join(f.dir, "in", "inventory.json")
	writeInput(t, inventory, encodeLines(t, inputManifest{V: 1, Streams: []inputManifestEntry{
		{Kind: "findings", Availability: "present", SHA256: fileDigest(t, f.findings), Records: 2},
		{Kind: "actions", Availability: "not_recorded"},
		{Kind: "firewall_audit", Availability: "absent"},
		{Kind: "ledger", Availability: "not_recorded"},
	}}))
	args = []string{"anonymize", "--salt-file", f.salt, "--out", f.out, "--manifest", f.manifest, "--input-manifest", inventory, f.findings}
	if err := testRun().execute(args, io.Discard); err != nil {
		t.Fatal(err)
	}
	manifest, _ = readManifest(t, f.manifest)
	want = map[string]any{"findings": "present", "actions": "not_recorded", "firewall_audit": "absent",
		"ledger": "not_recorded", "review": "unavailable", "firewall_id_join": "not_applicable"}
	if !reflect.DeepEqual(manifest["coverage"], want) {
		t.Fatalf("coverage with inventory: %v", manifest["coverage"])
	}
	if im := manifest["input_manifest"].(map[string]any); im["sha256"] != fileDigest(t, inventory) || im["records"] != 4.0 {
		t.Fatalf("input manifest entry: %v", im)
	}
}

// snapshot records what every path holds, absent included, so a refusal can
// be shown to have changed nothing.
func snapshot(t *testing.T, paths ...string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			out[p] = nil
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		out[p] = raw
	}
	return out
}

func assertUnchanged(t *testing.T, before map[string][]byte) {
	t.Helper()
	for p, want := range before {
		got, err := os.ReadFile(p)
		switch {
		case want == nil && !errors.Is(err, os.ErrNotExist):
			t.Errorf("refusal created %s", filepath.Base(p))
		case want != nil && (err != nil || !bytes.Equal(got, want)):
			t.Errorf("refusal changed %s", filepath.Base(p))
		}
	}
}

func TestRunInputManifestMismatchRefuses(t *testing.T) {
	for name, entries := range map[string]func(f *joinFixture) []inputManifestEntry{
		"digest": func(f *joinFixture) []inputManifestEntry {
			return []inputManifestEntry{{Kind: "findings", Availability: "present", SHA256: strings.Repeat("0", 64), Records: 2}}
		},
		"records": func(f *joinFixture) []inputManifestEntry {
			return []inputManifestEntry{{Kind: "findings", Availability: "present", SHA256: fileDigest(t, f.findings), Records: 3}}
		},
		"unlisted input": func(f *joinFixture) []inputManifestEntry {
			return []inputManifestEntry{{Kind: "actions", Availability: "absent"}}
		},
		"extra present": func(f *joinFixture) []inputManifestEntry {
			return []inputManifestEntry{
				{Kind: "findings", Availability: "present", SHA256: fileDigest(t, f.findings), Records: 2},
				{Kind: "actions", Availability: "present", SHA256: fileDigest(t, f.actions), Records: 3},
			}
		},
		"ledger payload": func(f *joinFixture) []inputManifestEntry {
			return []inputManifestEntry{
				{Kind: "findings", Availability: "present", SHA256: fileDigest(t, f.findings), Records: 2},
				{Kind: "ledger", Availability: "present", SHA256: fileDigest(t, f.actions), Records: 3},
			}
		},
		"present and absent": func(f *joinFixture) []inputManifestEntry {
			return []inputManifestEntry{
				{Kind: "findings", Availability: "present", SHA256: fileDigest(t, f.findings), Records: 2},
				{Kind: "findings", Availability: "absent"},
			}
		},
		"unknown kind": func(f *joinFixture) []inputManifestEntry {
			return []inputManifestEntry{
				{Kind: "findings", Availability: "present", SHA256: fileDigest(t, f.findings), Records: 2},
				{Kind: "alice", Availability: "absent"},
			}
		},
		"absent with digest": func(f *joinFixture) []inputManifestEntry {
			return []inputManifestEntry{
				{Kind: "findings", Availability: "present", SHA256: fileDigest(t, f.findings), Records: 2},
				{Kind: "actions", Availability: "absent", SHA256: fileDigest(t, f.actions)},
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newJoinFixture(t)
			inventory := filepath.Join(f.dir, "in", "inventory.json")
			writeInput(t, inventory, encodeLines(t, inputManifest{V: 1, Streams: entries(f)}))
			before := snapshot(t, f.out, f.manifest)
			var stdout bytes.Buffer
			args := []string{"anonymize", "--salt-file", f.salt, "--out", f.out, "--manifest", f.manifest, "--input-manifest", inventory, f.findings}
			err := testRun().execute(args, &stdout)
			if !errors.Is(err, errInputManifest) || stdout.Len() != 0 {
				t.Fatalf("got %v, summary %q", err, stdout.String())
			}
			assertUnchanged(t, before)
		})
	}
}

func TestRunInputErrorsAreFixedCodes(t *testing.T) {
	longLine := `{"reason":"` + strings.Repeat("x", maxLineBytes) + `"}`
	for name, tc := range map[string]struct {
		stream string // which input gets the bad row
		row    string
		want   string
	}{
		"finding unknown field":  {"findings", `{"v":1,"ts":"2026-09-08T10:00:00Z","finding_id":"x","severity":"HIGH","check":"c","message":"m","hostname":"h","alice":1}`, "findings input 1 line 3: " + string(errUnknownField)},
		"finding without time":   {"findings", `{"v":1,"finding_id":"x","severity":"HIGH","check":"c","message":"m","hostname":"h"}`, "findings input 1 line 3: " + string(errRecordTime)},
		"finding version":        {"findings", `{"v":2,"ts":"2026-09-08T10:00:00Z","finding_id":"x","severity":"HIGH","check":"c","message":"m","hostname":"h"}`, "findings input 1 line 3: " + string(errRecordVersion)},
		"finding nested field":   {"findings", `{"v":1,"ts":"2026-09-08T10:00:00Z","finding_id":"x","severity":"HIGH","check":"c","message":"m","hostname":"h","process":{"pid":1,"ppid":0,"uid":0,"alice":1}}`, "findings input 1 line 3: " + string(errUnknownField)},
		"action vocabulary":      {"actions", `{"v":1,"ts":"2026-09-08T10:00:00Z","op":"respond.block_ip","action":"alice","actor":"daemon","target":"203.0.113.9","result":"applied"}`, "actions input 1 line 4: " + string(errUnknownAction)},
		"action unknown field":   {"actions", `{"v":1,"ts":"2026-09-08T10:00:00Z","op":"respond.block_ip","action":"block","actor":"daemon","target":"203.0.113.9","result":"applied","alice":"x"}`, "actions input 1 line 4: " + string(errUnknownField)},
		"action malformed":       {"actions", `{"v":1,`, "actions input 1 line 4: " + string(errSyntax)},
		"action trailing":        {"actions", `{"v":1,"ts":"2026-09-08T10:00:00Z","op":"respond.block_ip","action":"block","actor":"daemon","target":"203.0.113.9","result":"applied"} {}`, "actions input 1 line 4: " + string(errTrailing)},
		"firewall source":        {"firewall", `{"timestamp":"2026-09-08T10:00:00Z","action":"block","ip":"203.0.113.9","source":"alice"}`, "firewall_audit input 1 line 3: " + string(errUnknownSource)},
		"firewall address":       {"firewall", `{"timestamp":"2026-09-08T10:00:00Z","action":"block","ip":"alice.example.com"}`, "firewall_audit input 1 line 3: " + string(errTargetAddress)},
		"firewall oversize line": {"firewall", longLine, "firewall_audit input 1 line 3: " + string(errLineTooLong)},
	} {
		t.Run(name, func(t *testing.T) {
			f := newJoinFixture(t)
			switch tc.stream {
			case "findings":
				f.findingRows = append(f.findingRows, tc.row+"\n"...)
			case "actions":
				f.actionRows = append(f.actionRows, tc.row+"\n"...)
			case "firewall":
				f.firewallRows = append(f.firewallRows, tc.row+"\n"...)
			}
			f.write(t)
			if err := os.Remove(f.salt); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, append(f.outputs(), f.salt)...)
			var stdout bytes.Buffer
			err := testRun().execute(f.args(), &stdout)
			if err == nil || err.Error() != tc.want || stdout.Len() != 0 {
				t.Fatalf("got %v, want %q; summary %q", err, tc.want, stdout.String())
			}
			assertNoPlanted(t, "error", err.Error(), f.planted())
			assertUnchanged(t, before)
		})
	}
}

func TestRunInputFileErrorsAreFixedCodes(t *testing.T) {
	f := newJoinFixture(t)
	gz, err := os.ReadFile(f.actions)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"truncated gzip": {gz[:len(gz)-4], "actions input 1: " + string(errInputGzip)},
		"not gzip":       {[]byte("plain text"), "actions input 1: " + string(errInputGzip)},
		"bad checksum":   {append(append([]byte{}, gz[:len(gz)-8]...), 0, 0, 0, 0, gz[len(gz)-4], gz[len(gz)-3], gz[len(gz)-2], gz[len(gz)-1]), "actions input 1: " + string(errInputGzip)},
		"trailing bytes": {append(append([]byte{}, gz...), "junk"...), "actions input 1: " + string(errInputGzip)},
	} {
		t.Run(name, func(t *testing.T) {
			if writeErr := os.WriteFile(f.actions, tc.data, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			runErr := testRun().execute(f.args(), io.Discard)
			if runErr == nil || runErr.Error() != tc.want {
				t.Fatalf("got %v, want %q", runErr, tc.want)
			}
		})
	}
	missing := filepath.Join(f.dir, "in", "alice-missing.jsonl")
	err = testRun().execute([]string{"anonymize", "--salt-file", f.salt, "--out", f.out, missing}, io.Discard)
	if err == nil || err.Error() != "findings input 1: "+string(errInputOpen) {
		t.Fatalf("missing input: %v", err)
	}
}

func TestRunUsageErrorsCarryNoArguments(t *testing.T) {
	f := newJoinFixture(t)
	for name, tc := range map[string]struct {
		args []string
		want error
	}{
		"unknown flag":               {[]string{"anonymize", "--alice-marker", "x"}, errUsage},
		"no command":                 {[]string{"alice-marker"}, errUsage},
		"no output":                  {[]string{"anonymize", f.findings}, errUsage},
		"no input":                   {[]string{"anonymize", "--out", f.out}, errUsage},
		"actions without out":        {[]string{"anonymize", "--out", f.out, "--manifest", f.manifest, "--actions", f.actions, f.findings}, errUnpairedStream},
		"out without actions":        {[]string{"anonymize", "--out", f.out, "--manifest", f.manifest, "--actions-out", f.actionsOut, f.findings}, errUnpairedStream},
		"firewall without out":       {[]string{"anonymize", "--out", f.out, "--manifest", f.manifest, "--firewall-audit", f.firewall, f.findings}, errUnpairedStream},
		"out without firewall":       {[]string{"anonymize", "--out", f.out, "--manifest", f.manifest, "--firewall-out", f.firewallOut, f.findings}, errUnpairedStream},
		"join without manifest":      {[]string{"anonymize", "--out", f.out, "--actions", f.actions, "--actions-out", f.actionsOut, f.findings}, errManifestRequired},
		"inventory without manifest": {[]string{"anonymize", "--out", f.out, "--input-manifest", f.actions, f.findings}, errManifestRequired},
		"empty stream path":          {[]string{"anonymize", "--out", f.out, "--manifest", f.manifest, "--actions", "", "--actions-out", f.actionsOut, f.findings}, errUsage},
	} {
		t.Run(name, func(t *testing.T) {
			err := testRun().execute(tc.args, io.Discard)
			if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), f.dir) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	before := snapshot(t, f.outputs()...)
	r := testRun()
	r.revision = func() toolRevision { return toolRevision{Revision: testRevision, Dirty: true} }
	if err := r.execute(f.args(), io.Discard); !errors.Is(err, errRevision) {
		t.Fatalf("dirty tree published a manifest: %v", err)
	}
	r.revision = func() toolRevision { return toolRevision{} }
	if err := r.execute(f.args(), io.Discard); !errors.Is(err, errRevision) {
		t.Fatalf("unknown revision published a manifest: %v", err)
	}
	assertUnchanged(t, before)
}

// Every output is checked against every input, the salt, the inventory and
// every other output before anything is created, by lexical path, through
// symlinked directories and by inode.
func TestRunRefusesAliasedOrUnsafeOutputs(t *testing.T) {
	for name, tc := range map[string]struct {
		prepare func(t *testing.T, f *joinFixture) []string
		want    error
	}{
		"actions over findings out": {func(t *testing.T, f *joinFixture) []string {
			f.actionsOut = f.out
			return f.args()
		}, errOutputAlias},
		"manifest over firewall out": {func(t *testing.T, f *joinFixture) []string {
			f.manifest = f.firewallOut
			return f.args()
		}, errOutputAlias},
		"lexical variant of input": {func(t *testing.T, f *joinFixture) []string {
			f.firewallOut = filepath.Join(filepath.Dir(f.firewall), ".", "..", "in", filepath.Base(f.firewall))
			return f.args()
		}, errOutputAlias},
		"salt": {func(t *testing.T, f *joinFixture) []string {
			f.manifest = f.salt
			return f.args()
		}, errOutputAlias},
		"inventory": {func(t *testing.T, f *joinFixture) []string {
			inventory := filepath.Join(f.dir, "in", "inventory.json")
			writeInput(t, inventory, []byte("{}\n"))
			f.actionsOut = inventory
			return f.args("--input-manifest", inventory)
		}, errOutputAlias},
		"symlinked parent": {func(t *testing.T, f *joinFixture) []string {
			link := filepath.Join(f.dir, "link")
			if err := os.Symlink(filepath.Join(f.dir, "in"), link); err != nil {
				t.Fatal(err)
			}
			f.out = filepath.Join(link, filepath.Base(f.findings))
			return f.args()
		}, errOutputAlias},
		// Neither path exists yet: only resolving the directory chain can
		// tell that both name one file.
		"symlinked parent of another output": {func(t *testing.T, f *joinFixture) []string {
			if err := os.MkdirAll(filepath.Dir(f.out), 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(f.dir, "outlink")
			if err := os.Symlink(filepath.Dir(f.out), link); err != nil {
				t.Fatal(err)
			}
			f.firewallOut = filepath.Join(link, filepath.Base(f.actionsOut))
			return f.args()
		}, errOutputAlias},
		"symlinked parent of the salt": {func(t *testing.T, f *joinFixture) []string {
			link := filepath.Join(f.dir, "saltlink")
			if err := os.Symlink(f.dir, link); err != nil {
				t.Fatal(err)
			}
			f.manifest = filepath.Join(link, filepath.Base(f.salt))
			return f.args()
		}, errOutputAlias},
		"hardlink of input": {func(t *testing.T, f *joinFixture) []string {
			if err := os.MkdirAll(filepath.Dir(f.out), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(f.actions, f.actionsOut); err != nil {
				t.Fatal(err)
			}
			return f.args()
		}, errOutputAlias},
		"symlink output": {func(t *testing.T, f *joinFixture) []string {
			if err := os.MkdirAll(filepath.Dir(f.out), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(f.dir, "elsewhere.gz"), f.out); err != nil {
				t.Fatal(err)
			}
			return f.args()
		}, errUnsafeDestination},
		"directory output": {func(t *testing.T, f *joinFixture) []string {
			if err := os.MkdirAll(f.manifest, 0o700); err != nil {
				t.Fatal(err)
			}
			return f.args()
		}, errUnsafeDestination},
	} {
		t.Run(name, func(t *testing.T) {
			f := newJoinFixture(t)
			if err := os.Remove(f.salt); err != nil {
				t.Fatal(err)
			}
			args := tc.prepare(t, f)
			before := snapshot(t, f.findings, f.actions, f.firewall, f.out, f.actionsOut, f.firewallOut, f.salt)
			var stdout bytes.Buffer
			err := testRun().execute(args, &stdout)
			if !errors.Is(err, tc.want) || stdout.Len() != 0 {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			assertUnchanged(t, before)
			if _, err := os.Lstat(f.salt); !errors.Is(err, os.ErrNotExist) && f.manifest != f.salt {
				t.Fatal("a refused run created the salt")
			}
		})
	}
}

// A leaked value injected after the transform must be refused by the
// verifier. The same injection with verification removed must reach the
// output, which is what makes these tests fail when the verifier is bypassed.
func TestRunVerifierRefusesInjectedLeaks(t *testing.T) {
	for name, inject := range map[string]func(r *anonymizeRun){
		"action raw target": func(r *anonymizeRun) {
			r.action = func(a *Anonymizer, rec actionlog.Record) (anonAction, error) {
				out, err := a.Action(rec)
				if out.TargetKind == "ip" {
					out.Target = rec.Target
				}
				return out, err
			}
		},
		"action raw finding id": func(r *anonymizeRun) {
			r.action = func(a *Anonymizer, rec actionlog.Record) (anonAction, error) {
				out, err := a.Action(rec)
				out.FindingID = rec.FindingID
				return out, err
			}
		},
		"action raw reason": func(r *anonymizeRun) {
			r.action = func(a *Anonymizer, rec actionlog.Record) (anonAction, error) {
				out, err := a.Action(rec)
				out.ReasonKind = "alice"
				return out, err
			}
		},
		"action raw path": func(r *anonymizeRun) {
			r.action = func(a *Anonymizer, rec actionlog.Record) (anonAction, error) {
				out, err := a.Action(rec)
				if out.TargetKind == "path" {
					out.Target = rec.Target
				}
				return out, err
			}
		},
		"firewall raw target": func(r *anonymizeRun) {
			r.firewall = func(a *Anonymizer, e firewall.AuditEntry) (anonFirewallAudit, error) {
				out, err := a.FirewallAudit(e)
				if out.TargetKind == "ip" {
					out.Target = e.IP
				}
				return out, err
			}
		},
		"firewall raw reason": func(r *anonymizeRun) {
			r.firewall = func(a *Anonymizer, e firewall.AuditEntry) (anonFirewallAudit, error) {
				out, err := a.FirewallAudit(e)
				out.ReasonKind = "carol"
				return out, err
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newJoinFixture(t)
			before := snapshot(t, f.outputs()...)
			r := testRun()
			inject(r)
			var stdout bytes.Buffer
			err := r.execute(f.args(), &stdout)
			if !errors.Is(err, errLeak) || stdout.Len() != 0 {
				t.Fatalf("injected leak not refused: %v %q", err, stdout.String())
			}
			assertUnchanged(t, before)
		})
	}
}

// failingOps fails one filesystem step of publication. step names the
// operation, n is which call of it fails (1-based).
type failingOps struct {
	step  string
	n     int
	calls map[string]int
}

var errInjected = errors.New("injected failure")

func (f *failingOps) hit(step string) bool {
	f.calls[step]++
	return step == f.step && f.calls[step] == f.n
}

type failingFile struct {
	*os.File
	ops   *failingOps
	wrote bool
}

// Only the first write of each staged file counts, so n picks the output.
func (w *failingFile) Write(p []byte) (int, error) {
	first := !w.wrote
	w.wrote = true
	if first && w.ops.hit("write") {
		return 0, errInjected
	}
	return w.File.Write(p)
}

func (w *failingFile) Sync() error {
	if w.ops.hit("sync") {
		return errInjected
	}
	return w.File.Sync()
}

func (w *failingFile) Close() error {
	err := w.File.Close()
	if w.ops.hit("close") {
		return errInjected
	}
	return err
}

func injectFailure(r *anonymizeRun, step string, n int) *failingOps {
	f := &failingOps{step: step, n: n, calls: map[string]int{}}
	real := r.ops
	r.ops = fileOps{
		createTemp: func(dir, pattern string) (stagedFile, error) {
			if f.hit("create") {
				return nil, errInjected
			}
			file, err := os.CreateTemp(dir, pattern)
			if err != nil {
				return nil, err
			}
			return &failingFile{File: file, ops: f}, nil
		},
		link: func(oldname, newname string) error {
			if f.hit("link") {
				return errInjected
			}
			return real.link(oldname, newname)
		},
		rename: func(oldpath, newpath string) error {
			if f.hit("rename") {
				return errInjected
			}
			return real.rename(oldpath, newpath)
		},
		remove: real.remove,
	}
	return f
}

func TestPublishFailureKeepsThePreviousBundle(t *testing.T) {
	steps := map[string]int{"create": 4, "write": 4, "sync": 4, "close": 4, "link": 4, "rename": 4}
	for _, existing := range []bool{false, true} {
		for step, max := range steps {
			for n := 1; n <= max; n++ {
				t.Run(fmt.Sprintf("existing=%t/%s/%d", existing, step, n), func(t *testing.T) {
					f := newJoinFixture(t)
					if existing {
						if err := testRun().execute(f.args(), io.Discard); err != nil {
							t.Fatal(err)
						}
						// The next run produces different bytes.
						f.findingsRaw[0].Message = "changed message"
						f.findingRows = encodeLines(t, anySlice(f.findingsRaw)...)
						f.write(t)
					}
					before := snapshot(t, f.outputs()...)
					r := testRun()
					ops := injectFailure(r, step, n)
					var stdout bytes.Buffer
					err := r.execute(f.args(), &stdout)
					if step == "link" && !existing {
						// Fresh outputs need no backup link.
						if err != nil || ops.calls["link"] != 0 {
							t.Fatalf("fresh publication linked or failed: %v", err)
						}
						return
					}
					if !errors.Is(err, errPublish) || stdout.Len() != 0 {
						t.Fatalf("got %v, summary %q", err, stdout.String())
					}
					assertUnchanged(t, before)
					assertNoStaging(t, filepath.Dir(f.out))
				})
			}
		}
	}
}

func TestPublishReportsFailedRollback(t *testing.T) {
	f := newJoinFixture(t)
	if err := testRun().execute(f.args(), io.Discard); err != nil {
		t.Fatal(err)
	}
	f.findingsRaw[0].Message = "changed message"
	f.findingRows = encodeLines(t, anySlice(f.findingsRaw)...)
	f.write(t)
	r := testRun()
	real := r.ops
	renames := 0
	r.ops.rename = func(oldpath, newpath string) error {
		renames++
		// Publish the first two outputs, fail the third, then fail the
		// restore of the first.
		if renames == 3 || renames == 4 {
			return errInjected
		}
		return real.rename(oldpath, newpath)
	}
	err := r.execute(f.args(), io.Discard)
	if !errors.Is(err, errRollback) {
		t.Fatalf("got %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(f.out))
	backups := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".finding-stream-backup-") {
			backups++
		}
	}
	if backups == 0 {
		t.Fatal("a failed rollback discarded the recovery copies")
	}
}

func TestPublishEncodingErrorKeepsPreviousOutput(t *testing.T) {
	f := newJoinFixture(t)
	if err := testRun().execute(f.args(), io.Discard); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, f.outputs()...)
	r := testRun()
	r.event = func(a *Anonymizer, e alert.AuditEvent) alert.AuditEvent {
		out := a.Event(e)
		// json cannot encode a year past 9999.
		out.Timestamp = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		return out
	}
	if err := r.execute(f.args(), io.Discard); !errors.Is(err, errPublish) {
		t.Fatalf("got %v", err)
	}
	assertUnchanged(t, before)
	assertNoStaging(t, filepath.Dir(f.out))
}

// Audit logs from before timestamps were filled in carry rows with a zero
// time. They are kept and counted, and do not stretch the time span.
func TestRunKeepsAndCountsUnstampedFindings(t *testing.T) {
	f := newJoinFixture(t)
	unstamped := f.findingsRaw[0]
	unstamped.Timestamp, unstamped.FindingID = time.Time{}, "aaaabbbbccccdddd"
	f.findingsRaw = append(f.findingsRaw, unstamped)
	f.findingRows = encodeLines(t, anySlice(f.findingsRaw)...)
	f.write(t)
	if err := testRun().execute(f.args(), io.Discard); err != nil {
		t.Fatal(err)
	}
	findings, _ := readGzipRows(t, f.out)
	if len(findings) != 3 || findings[2]["ts"] != "0001-01-01T00:00:00Z" {
		t.Fatalf("unstamped row not kept: %v", findings)
	}
	manifest, _ := readManifest(t, f.manifest)
	if got := manifest["join"].(map[string]any)["finding_rows_unstamped"]; got != 1.0 {
		t.Fatalf("finding_rows_unstamped = %v", got)
	}
	in := manifest["inputs"].([]any)[0].(map[string]any)
	out := manifest["outputs"].([]any)[0].(map[string]any)
	for _, file := range []map[string]any{in, out} {
		if file["records"] != 3.0 || file["min_ts"] != "2026-09-08T10:00:00Z" || file["max_ts"] != "2026-09-08T10:01:00Z" {
			t.Fatalf("unstamped row changed the span: %v", file)
		}
	}
}
