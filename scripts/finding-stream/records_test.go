package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/privops"
	"github.com/pidginhost/csm/internal/processctx"
)

var recordTS = time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)

// fieldClass is how the typed transform treats one input field. The tables
// below are the reviewed classification of every field of the real input
// types; a new field fails TestTypedRecordFieldsAreClassified until someone
// decides what may leave the host.
type fieldClass int

const (
	classEnum     fieldClass = iota // closed vocabulary; anything else refuses
	classFree                       // free text or identity; accepted, never copied
	classID                         // opaque identifier; replaced by a salted ID
	classTarget                     // mapped address or salted ID, never copied
	classNumber                     // typed number; a string refuses
	classTime                       // timestamp; a string that is not a time refuses
	classBool                       // boolean; a string refuses
	classNested                     // object with its own table
	classDuration                   // parsed duration; anything else refuses
)

var recordFieldClasses = map[string]fieldClass{
	"v": classNumber, "ts": classTime, "hostname": classFree, "op": classEnum, "action": classEnum,
	"actor": classEnum, "actor_detail": classFree, "finding_id": classID, "incident_id": classID,
	"action_id": classID, "action_version": classNumber, "undo_of": classID, "target": classTarget,
	"account": classFree, "reason": classFree, "command": classFree, "before": classNested,
	"after": classNested, "result": classEnum, "error": classFree, "undo": classFree, "recovery_path": classFree,
}

var fileStateFieldClasses = map[string]fieldClass{
	"exists": classBool, "sha256": classFree, "size": classNumber, "mode": classFree, "uid": classNumber, "gid": classNumber,
}

var firewallFieldClasses = map[string]fieldClass{
	"timestamp": classTime, "action": classEnum, "ip": classTarget, "reason": classFree, "source": classEnum, "duration": classDuration,
}

func jsonNames(t reflect.Type) []string {
	var names []string
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		names = append(names, name)
	}
	return names
}

func TestTypedRecordFieldsAreClassified(t *testing.T) {
	for _, tc := range []struct {
		typ     reflect.Type
		classes map[string]fieldClass
	}{
		{reflect.TypeFor[actionlog.Record](), recordFieldClasses},
		{reflect.TypeFor[actionlog.FileState](), fileStateFieldClasses},
		{reflect.TypeFor[firewall.AuditEntry](), firewallFieldClasses},
	} {
		names := jsonNames(tc.typ)
		for _, n := range names {
			if _, ok := tc.classes[n]; !ok {
				t.Errorf("%s field %q has no reviewed classification", tc.typ, n)
			}
		}
		for n := range tc.classes {
			if !slices.Contains(names, n) {
				t.Errorf("%s: classified field %q no longer exists", tc.typ, n)
			}
		}
	}
}

func fullRecord() actionlog.Record {
	return actionlog.Record{
		V: actionlog.SchemaVersion, Timestamp: recordTS, Hostname: "srv.example.com", Op: "respond.block_ip", Action: "block",
		Actor: actionlog.Daemon, ActorDetail: "expires in 1h0m0s", FindingID: "finding-raw-0001", IncidentID: "incident-raw-0001",
		ActionID: "action-raw-0001", ActionVersion: 3, UndoOf: "action-raw-0000", Target: "203.0.113.9", Account: "alice",
		Reason:  "CSM auto-block: brute force from 203.0.113.9 on alice",
		Command: []string{"nft", "add", "element", "203.0.113.9"},
		Before:  &actionlog.FileState{Exists: true, Digest: strings.Repeat("a", 64), Size: 10, Mode: "-rw-r--r--", UID: 1003, GID: 1003},
		After:   &actionlog.FileState{Exists: false}, Result: actionlog.Applied, Error: "nft: /home/alice/x failed",
		Undo: "csm firewall unblock 203.0.113.9", RecoveryPath: "/var/lib/csm/quarantine/alice/x",
	}
}

func marshalMap(t *testing.T, v any) (map[string]any, string) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m, string(raw)
}

func TestActionOutputKeysAreExact(t *testing.T) {
	a := NewAnonymizer(testSalt())
	out, err := a.Action(fullRecord())
	if err != nil {
		t.Fatal(err)
	}
	got, raw := marshalMap(t, out)
	want := map[string]any{
		"v": 1.0, "format_version": 1.0, "ts": "2026-09-08T10:00:00Z", "hostname": a.Host("srv.example.com"),
		"account": a.Account("alice"), "op": "respond.block_ip", "action": "block", "actor": "daemon",
		"duration_ns": float64(time.Hour), "finding_id": a.ID(idFinding, "finding-raw-0001"),
		"incident_id": a.ID(idIncident, "incident-raw-0001"), "action_id": a.ID(idAction, "action-raw-0001"),
		"action_version": 3.0, "undo_of": a.ID(idAction, "action-raw-0000"), "target": a.IPv4("203.0.113.9"),
		"target_kind": "ip", "reason_kind": "scan", "result": "applied", "has_error": true,
		"before_exists": true, "after_exists": false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("action row:\n got %v\nwant %v", got, want)
	}
	for _, raw0 := range []string{"alice", "203.0.113.9", "/home/", "nft", "finding-raw", "action-raw", "incident-raw", "srv.example.com", strings.Repeat("a", 64), "rw-r", "1003", "quarantine"} {
		if strings.Contains(raw, raw0) {
			t.Errorf("action row carries %q: %s", raw0, raw)
		}
	}
}

func TestActionTransformNeverCopiesFreeText(t *testing.T) {
	a := NewAnonymizer(testSalt())
	quarantine := actionlog.Record{V: 1, Timestamp: recordTS, Op: "respond.quarantine_file", Actor: actionlog.Daemon,
		Target: "/var/tmp/customer-marker.php", Account: "1003", Result: actionlog.Applied, ActorDetail: "alice"}
	out, err := a.Action(quarantine)
	if err != nil {
		t.Fatal(err)
	}
	if out.TargetKind != "path" || out.Target != a.ID(idTarget, "/var/tmp/customer-marker.php") {
		t.Fatalf("path target = %q (%s)", out.Target, out.TargetKind)
	}
	if !strings.HasPrefix(out.Account, "acct-") || out.Account == "1003" {
		t.Fatalf("numeric account passed through: %q", out.Account)
	}
	_, raw := marshalMap(t, out)
	for _, leak := range []string{"customer-marker", "var/tmp", "1003", "alice", "actor_detail", "duration_ns", "actor_ip"} {
		if strings.Contains(raw, leak) {
			t.Errorf("row carries %q: %s", leak, raw)
		}
	}
	quarantine.Account = "root"
	if out, err = a.Action(quarantine); err != nil || !strings.HasPrefix(out.Account, "acct-") {
		t.Fatalf("system account passed through: %q %v", out.Account, err)
	}

	block := fullRecord()
	for detail, check := range map[string]func(anonAction) bool{
		"198.51.100.4":        func(o anonAction) bool { return o.ActorIP == a.IPv4("198.51.100.4") && o.DurationNS == 0 },
		"2001:db8:5::4":       func(o anonAction) bool { return o.ActorIP == a.IPv6("2001:db8:5::4") },
		"expires in 30m":      func(o anonAction) bool { return o.DurationNS == int64(30*time.Minute) && o.ActorIP == "" },
		"expires in 0s":       func(o anonAction) bool { return o.DurationNS == 0 },
		"expires in -1s":      func(o anonAction) bool { return o.DurationNS == 0 },
		"expires in 1h, root": func(o anonAction) bool { return o.DurationNS == 0 },
		"/usr/bin/php":        func(o anonAction) bool { return o.DurationNS == 0 && o.ActorIP == "" },
	} {
		block.ActorDetail = detail
		o, err := a.Action(block)
		if err != nil || !check(o) {
			t.Errorf("actor detail %q -> %+v, %v", detail, o, err)
		}
	}
}

// reviewedActionLogActions is the action vocabulary audited against every
// production writer at the implementation base.
var reviewedActionLogActions = []string{
	"allow", "allow_port", "apply", "block", "block_subnet", "configure_port_allow", "evict_temp", "flush",
	"permblock", "promote", "remove_allow", "remove_port_allow", "state", "temp_allow", "temp_allow_expired",
	"temp_subnet_expired", "unblock", "unblock_subnet",
}

var reviewedFirewallAuditActions = []string{
	"allow", "allow_port", "block", "block_subnet", "evict_temp", "flush", "permblock", "remove_allow",
	"remove_port_allow", "temp_allow", "temp_allow_expired", "temp_subnet_expired", "unblock", "unblock_subnet",
}

func TestTypedVocabulariesMatchReviewedWriters(t *testing.T) {
	if got := sortedKeys(firewallActionLogActions); !slices.Equal(got, reviewedActionLogActions) {
		t.Errorf("action log vocabulary = %v", got)
	}
	if got := sortedKeys(firewallAuditActions); !slices.Equal(got, reviewedFirewallAuditActions) {
		t.Errorf("firewall audit vocabulary = %v", got)
	}
	ids := map[string]bool{}
	for _, op := range privops.Operations() {
		ids[op.ID] = true
	}
	for op := range actionOps {
		if !ids[op] {
			t.Errorf("accepted op %q is not a privileged operation", op)
		}
	}
	sources := []string{firewall.SourceUnknown, firewall.SourceWebUI, firewall.SourceCLI, firewall.SourceAutoResponse,
		firewall.SourceChallenge, firewall.SourceWhitelist, firewall.SourceDynDNS, firewall.SourceSystem}
	slices.Sort(sources)
	if got := sortedKeys(firewallSources); !slices.Equal(got, sources) {
		t.Errorf("firewall sources = %v", got)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func TestActionKnownWriterFixtures(t *testing.T) {
	for _, tc := range []struct{ op, action, target, kind string }{
		{"respond.block_ip", "block", "203.0.113.9", "ip"},
		{"respond.block_ip", "permblock", "203.0.113.9", "ip"},
		{"respond.block_ip", "promote", "203.0.113.9", "ip"},
		{"respond.block_ip", "evict_temp", "2001:db8::9", "ip"},
		{"respond.block_ip", "block_subnet", "203.0.113.0/24", "cidr"},
		{"respond.block_ip", "temp_subnet_expired", "203.0.113.0/24", "cidr"},
		{"respond.block_ip", "temp_allow_expired", "203.0.113.9", "ip"},
		{"respond.block_ip", "allow", "203.0.113.9", "ip"},
		{"respond.block_ip", "temp_allow", "203.0.113.9", "ip"},
		{"respond.block_ip", "state", "*", "opaque"},
		{"respond.block_ip", "apply", "csm", "opaque"},
		{"operate.manual_firewall", "unblock", "203.0.113.9", "ip"},
		{"operate.manual_firewall", "remove_allow", "203.0.113.9", "ip"},
		{"operate.manual_firewall", "allow_port", "203.0.113.9:443/tcp", "endpoint"},
		{"operate.manual_firewall", "remove_port_allow", "2001:db8::9:25/tcp", "endpoint"},
		{"operate.manual_firewall", "configure_port_allow", "203.0.113.9:21/udp", "endpoint"},
		{"operate.manual_firewall", "flush", "", "empty"},
		{"operate.manual_firewall", "flush", "*", "opaque"},
		{"operate.manual_firewall", "unblock_subnet", "2001:db8:1::/48", "cidr"},
		{"operate.manual_firewall", "rollback", "/var/lib/csm/firewall/rollback.nft", "path"},
		{"operate.manual_firewall", "rollback_config", "/etc/csm/csm.yaml", "path"},
		{"integrate.firewall_ruleset", "apply", "csm", "opaque"},
		{"respond.kill_process", "", "pid 4242", "opaque"},
		{"respond.quarantine_file", "", "/home/alice/public_html/x.php", "path"},
		{"respond.clean_file", "", "/home/alice/public_html/y.php", "path"},
	} {
		t.Run(tc.op+"/"+tc.action, func(t *testing.T) {
			a := NewAnonymizer(testSalt())
			rec := actionlog.Record{V: 1, Timestamp: recordTS, Op: tc.op, Action: tc.action, Actor: actionlog.Daemon, Target: tc.target, Result: actionlog.Applied}
			out, err := a.Action(rec)
			if err != nil {
				t.Fatal(err)
			}
			if out.TargetKind != tc.kind || out.Op != tc.op || out.Action != tc.action {
				t.Fatalf("got %+v", out)
			}
			if err := a.VerifyAction(out); err != nil {
				t.Fatalf("verifier refused a transformed row: %v", err)
			}
		})
	}
	a := NewAnonymizer(testSalt())
	rec := actionlog.Record{V: 1, Timestamp: recordTS, Op: "respond.block_ip", Action: "block", Actor: actionlog.Daemon, Target: "203.0.113.9"}
	outcomes := map[string]bool{}
	for _, result := range []actionlog.Result{"verified", "unknown", "failed", actionlog.Applied, actionlog.DryRun, actionlog.Refused} {
		rec.Result = result
		out, err := a.Action(rec)
		if err != nil {
			t.Fatalf("result %q refused: %v", result, err)
		}
		outcomes[out.Result] = true
	}
	if len(outcomes) != 6 {
		t.Fatalf("lifecycle outcomes collapsed: %v", outcomes)
	}
}

func TestActionTransformRefusals(t *testing.T) {
	unwritten := ""
	for _, op := range privops.Operations() {
		if _, ok := actionOps[op.ID]; !ok {
			unwritten = op.ID
			break
		}
	}
	if unwritten == "" {
		t.Fatal("no privileged operation without an audited writer to test against")
	}
	for name, tc := range map[string]struct {
		mutate func(*actionlog.Record)
		want   error
	}{
		"version0":            {func(r *actionlog.Record) { r.V = 0 }, errRecordVersion},
		"version2":            {func(r *actionlog.Record) { r.V = 2 }, errRecordVersion},
		"zero time":           {func(r *actionlog.Record) { r.Timestamp = time.Time{} }, errRecordTime},
		"unknown op":          {func(r *actionlog.Record) { r.Op = "respond.alice" }, errUnknownOp},
		"empty op":            {func(r *actionlog.Record) { r.Op = "" }, errUnknownOp},
		"unwritten op":        {func(r *actionlog.Record) { r.Op = unwritten; r.Action = "" }, errUnknownOp},
		"alphabetic action":   {func(r *actionlog.Record) { r.Action = "alice" }, errUnknownAction},
		"injected action":     {func(r *actionlog.Record) { r.Action = "block; rm -rf /" }, errUnknownAction},
		"undo action":         {func(r *actionlog.Record) { r.Action = "undo" }, errUnknownAction},
		"restart action":      {func(r *actionlog.Record) { r.Action = "restart" }, errUnknownAction},
		"empty action":        {func(r *actionlog.Record) { r.Action = "" }, errUnknownAction},
		"rollback on block":   {func(r *actionlog.Record) { r.Action = "rollback" }, errUnknownAction},
		"action on file op":   {func(r *actionlog.Record) { r.Op = "respond.quarantine_file"; r.Target = "/x" }, errUnknownAction},
		"empty actor":         {func(r *actionlog.Record) { r.Actor = "" }, errUnknownActor},
		"unknown actor":       {func(r *actionlog.Record) { r.Actor = "root" }, errUnknownActor},
		"empty result":        {func(r *actionlog.Record) { r.Result = "" }, errUnknownResult},
		"planned result":      {func(r *actionlog.Record) { r.Result = "planned" }, errUnknownResult},
		"executing result":    {func(r *actionlog.Record) { r.Result = "executing" }, errUnknownResult},
		"name as address":     {func(r *actionlog.Record) { r.Target = "alice" }, errTargetAddress},
		"path as address":     {func(r *actionlog.Record) { r.Target = "/home/alice/x" }, errTargetAddress},
		"opaque as address":   {func(r *actionlog.Record) { r.Target = "csm" }, errTargetAddress},
		"missing file target": {func(r *actionlog.Record) { r.Op = "respond.clean_file"; r.Action = ""; r.Target = "" }, errTargetMissing},
		"missing pid target":  {func(r *actionlog.Record) { r.Op = "respond.kill_process"; r.Action = ""; r.Target = "" }, errTargetMissing},
	} {
		t.Run(name, func(t *testing.T) {
			rec := fullRecord()
			tc.mutate(&rec)
			if _, err := NewAnonymizer(testSalt()).Action(rec); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

var seedMarkers = []string{
	"alice", "carol@example.com", "/home/alice/public_html/wp-config.php", "/var/tmp/customer-marker.php",
	"203.0.113.9", "2001:db8:1::9", "finding-raw-7f3a91", "srv.example.com",
}

// seedJSON rewrites one slot of a marshalled record.
func seedJSON(t *testing.T, base any, set func(map[string]any)) []byte {
	t.Helper()
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	set(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func seedBaseRecord() actionlog.Record {
	return actionlog.Record{
		V: 1, Timestamp: recordTS, Hostname: "h1.example.net", Op: "respond.quarantine_file", Actor: actionlog.Daemon,
		ActorDetail: "x", FindingID: "f", IncidentID: "i", ActionID: "a", ActionVersion: 1, UndoOf: "u",
		Target: "/home/bob/x.php", Account: "bob", Reason: "r", Command: []string{"c"},
		Before: &actionlog.FileState{Exists: true, Digest: "d", Size: 1, Mode: "m", UID: 1, GID: 1},
		After:  &actionlog.FileState{Exists: true, Digest: "d", Size: 1, Mode: "m", UID: 1, GID: 1},
		Result: actionlog.Applied, Error: "e", Undo: "u", RecoveryPath: "p",
	}
}

// Every slot of the real schema, every nested file-state slot, every command
// element and unknown keys at both levels are seeded with each identity on
// its own. A slot either refuses the record or the identity never reaches
// the output, and whatever was accepted passes the typed verifier.
func TestActionTransformSeedsEveryStringSlot(t *testing.T) {
	type slot struct {
		name  string
		class fieldClass
		set   func(m map[string]any, marker string)
	}
	var slots []slot
	for key, class := range recordFieldClasses {
		switch key {
		case "before", "after":
			for sub, subClass := range fileStateFieldClasses {
				slots = append(slots, slot{key + "." + sub, subClass, func(m map[string]any, v string) { m[key].(map[string]any)[sub] = v }})
			}
			slots = append(slots, slot{key + ".unknown", classEnum, func(m map[string]any, v string) { m[key].(map[string]any)["extra"] = v }})
			slots = append(slots, slot{key + ".marker-key", classEnum, func(m map[string]any, v string) { m[key].(map[string]any)[v] = "x" }})
		case "command":
			slots = append(slots, slot{key, class, func(m map[string]any, v string) { m[key].([]any)[0] = v }})
		default:
			slots = append(slots, slot{key, class, func(m map[string]any, v string) { m[key] = v }})
		}
	}
	slots = append(slots,
		slot{"unknown", classEnum, func(m map[string]any, v string) { m["extra"] = v }},
		slot{"marker-key", classEnum, func(m map[string]any, v string) { m[v] = "x" }},
		slot{"nested-unknown", classEnum, func(m map[string]any, v string) { m["extra"] = map[string]any{"k": v} }},
	)
	for _, s := range slots {
		for _, marker := range seedMarkers {
			t.Run(s.name+"/"+marker, func(t *testing.T) {
				data := seedJSON(t, seedBaseRecord(), func(m map[string]any) { s.set(m, marker) })
				a := NewAnonymizer(testSalt())
				var rec actionlog.Record
				err := decodeStrict(data, &rec)
				var out anonAction
				if err == nil {
					out, err = a.Action(rec)
				}
				switch s.class {
				case classEnum, classNumber, classTime, classBool, classDuration:
					if err == nil {
						t.Fatalf("slot accepted %q", marker)
					}
					return
				}
				if err != nil {
					t.Fatalf("free slot refused %q: %v", marker, err)
				}
				_, raw := marshalMap(t, out)
				if strings.Contains(strings.ToLower(raw), strings.ToLower(marker)) {
					t.Fatalf("marker reached the output: %s", raw)
				}
				if err := a.VerifyAction(out); err != nil {
					t.Fatalf("verifier refused a transformed row: %v", err)
				}
			})
		}
	}
}

func TestFirewallAuditSeedsEveryStringSlot(t *testing.T) {
	base := firewall.AuditEntry{Timestamp: recordTS, Action: "block", IP: "198.51.100.20", Reason: "CSM auto-block: x", Source: "auto_response", Duration: "24h0m0s"}
	addresses := map[string]bool{"203.0.113.9": true, "2001:db8:1::9": true}
	for key, class := range firewallFieldClasses {
		for _, marker := range seedMarkers {
			t.Run(key+"/"+marker, func(t *testing.T) {
				data := seedJSON(t, base, func(m map[string]any) { m[key] = marker })
				a := NewAnonymizer(testSalt())
				var entry firewall.AuditEntry
				err := decodeStrict(data, &entry)
				var out anonFirewallAudit
				if err == nil {
					out, err = a.FirewallAudit(entry)
				}
				accept := class == classFree || (class == classTarget && addresses[marker])
				if !accept {
					if err == nil {
						t.Fatalf("slot accepted %q", marker)
					}
					return
				}
				if err != nil {
					t.Fatalf("slot refused %q: %v", marker, err)
				}
				_, raw := marshalMap(t, out)
				if strings.Contains(strings.ToLower(raw), strings.ToLower(marker)) {
					t.Fatalf("marker reached the output: %s", raw)
				}
				if err := a.VerifyFirewallAudit(out); err != nil {
					t.Fatalf("verifier refused a transformed row: %v", err)
				}
			})
		}
	}
	for _, name := range []string{"extra", "alice"} {
		data := seedJSON(t, base, func(m map[string]any) { m[name] = "203.0.113.9" })
		if err := decodeStrict(data, &firewall.AuditEntry{}); !errors.Is(err, errUnknownField) {
			t.Errorf("unknown firewall field %q: %v", name, err)
		}
	}
}

func TestFirewallAuditTransform(t *testing.T) {
	a := NewAnonymizer(testSalt())
	full := firewall.AuditEntry{Timestamp: recordTS, Action: "block", IP: "203.0.113.9", Reason: "CSM auto-block: brute force on alice", Source: "auto_response", Duration: "24h0m0s"}
	out, err := a.FirewallAudit(full)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := marshalMap(t, out)
	want := map[string]any{
		"format_version": 1.0, "ts": "2026-09-08T10:00:00Z", "action": "block", "target": a.IPv4("203.0.113.9"),
		"target_kind": "ip", "reason_kind": "scan", "source": "auto_response", "duration_ns": float64(24 * time.Hour),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("firewall row:\n got %v\nwant %v", got, want)
	}
	for _, tc := range []struct{ action, target, kind string }{
		{"block", "203.0.113.9", "ip"}, {"unblock", "2001:db8::9", "ip"}, {"allow", "203.0.113.9", "ip"},
		{"temp_allow", "203.0.113.9", "ip"}, {"remove_allow", "203.0.113.9", "ip"}, {"permblock", "203.0.113.9", "ip"},
		{"evict_temp", "203.0.113.9", "ip"}, {"temp_allow_expired", "203.0.113.9", "ip"},
		{"allow_port", "203.0.113.9:443/tcp", "endpoint"}, {"remove_port_allow", "2001:db8::9:25/tcp", "endpoint"},
		{"block_subnet", "203.0.113.0/24", "cidr"}, {"unblock_subnet", "2001:db8:1::/48", "cidr"},
		{"temp_subnet_expired", "203.0.113.0/24", "cidr"}, {"flush", "", "empty"},
	} {
		entry := firewall.AuditEntry{Timestamp: recordTS, Action: tc.action, IP: tc.target}
		o, err := a.FirewallAudit(entry)
		if err != nil || o.TargetKind != tc.kind || o.Source != "unknown" {
			t.Errorf("%s %q -> %+v %v", tc.action, tc.target, o, err)
			continue
		}
		if err := a.VerifyFirewallAudit(o); err != nil {
			t.Errorf("%s: verifier refused a transformed row: %v", tc.action, err)
		}
	}
	for name, tc := range map[string]struct {
		mutate func(*firewall.AuditEntry)
		want   error
	}{
		"apply":          {func(e *firewall.AuditEntry) { e.Action = "apply"; e.IP = "" }, errUnknownAction},
		"state":          {func(e *firewall.AuditEntry) { e.Action = "state"; e.IP = "" }, errUnknownAction},
		"undo":           {func(e *firewall.AuditEntry) { e.Action = "undo" }, errUnknownAction},
		"alphabetic":     {func(e *firewall.AuditEntry) { e.Action = "alice" }, errUnknownAction},
		"empty action":   {func(e *firewall.AuditEntry) { e.Action = "" }, errUnknownAction},
		"unknown source": {func(e *firewall.AuditEntry) { e.Source = "alice" }, errUnknownSource},
		"bad duration":   {func(e *firewall.AuditEntry) { e.Duration = "banana" }, errDuration},
		"zero duration":  {func(e *firewall.AuditEntry) { e.Duration = "0s" }, errDuration},
		"neg duration":   {func(e *firewall.AuditEntry) { e.Duration = "-1s" }, errDuration},
		"zero time":      {func(e *firewall.AuditEntry) { e.Timestamp = time.Time{} }, errRecordTime},
		"opaque target":  {func(e *firewall.AuditEntry) { e.IP = "csm" }, errTargetAddress},
		"path target":    {func(e *firewall.AuditEntry) { e.IP = "/var/tmp/x" }, errTargetAddress},
	} {
		e := full
		tc.mutate(&e)
		if _, err := a.FirewallAudit(e); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
}

func TestAddressTargetsUseTheFindingMapping(t *testing.T) {
	a := NewAnonymizer(testSalt())
	for raw, want := range map[string]anonTarget{
		"2001:DB8:0:0::7":     {Target: a.IPv6("2001:db8::7"), TargetKind: "ip"},
		"2001:db8::7":         {Target: a.IPv6("2001:db8::7"), TargetKind: "ip"},
		"::ffff:203.0.113.9":  {Target: a.IPv4("203.0.113.9"), TargetKind: "ip"},
		"203.0.113.77/24":     {Target: a.IPv4("203.0.113.0"), TargetKind: "cidr", TargetPrefix: 24},
		"2001:db8:1::5/48":    {Target: a.IPv6("2001:db8:1::"), TargetKind: "cidr", TargetPrefix: 48},
		"203.0.113.9:443/tcp": {Target: a.IPv4("203.0.113.9"), TargetKind: "endpoint", TargetPort: 443, TargetProto: "tcp"},
		"2001:db8::9:25/udp":  {Target: a.IPv6("2001:db8::9"), TargetKind: "endpoint", TargetPort: 25, TargetProto: "udp"},
		"":                    {TargetKind: "empty"},
	} {
		got, err := a.addressTarget(raw)
		if err != nil || got != want {
			t.Errorf("%q -> %+v %v, want %+v", raw, got, err, want)
		}
	}
	for text, raw := range map[string]string{"denied 203.0.113.9 twice": "::ffff:203.0.113.9", "from 2001:db8::7": "2001:DB8::7"} {
		target, err := a.addressTarget(raw)
		if err != nil || !strings.Contains(a.Text(text), target.Target) {
			t.Errorf("target %q (%q) disagrees with the finding mapping of %q: %v", raw, target.Target, a.Text(text), err)
		}
	}
	for _, raw := range []string{
		"203.0.113.9:0/tcp", ":443/tcp", "203.0.113.9:65536/tcp", "203.0.113.9:443/icmp", "203.0.113.9:0443/tcp",
		"203.0.113.9:+443/tcp", "fe80::1%eth0", "[2001:db8::1]:443/tcp", "203.0.113.300", "alice", "203.0.113.9/33",
		"203.0.113.9:443/tcp ", " 203.0.113.9", "203.0.113.9/24/tcp", "fe80::1%eth0/64", "0.0.0.0/0", "::/0",
	} {
		if got, err := a.addressTarget(raw); !errors.Is(err, errTargetAddress) {
			t.Errorf("%q accepted as %+v (%v)", raw, got, err)
		}
	}
}

func TestReasonKinds(t *testing.T) {
	for reason, want := range map[string]string{
		"":                                                        "empty",
		"CSM auto-block: 12 denies from x":                        "scan",
		"CSM auto-block (subnet): spray from x":                   "scan_subnet",
		"CSM auto-block (asn-crawl): crawl":                       "asn_crawl",
		"CSM challenge-timeout: no solve":                         "challenge_timeout",
		"challenge timeout: no solve":                             "challenge_timeout",
		"central-intel (locally corroborated)":                    "central_intel",
		"CSM credential_spray: 9 mailboxes":                       "credential_spray",
		"CSM incident: brute_force HIGH (x)":                      "incident",
		"Auto-netblock: 5 IPs from x within 1h":                   "netblock",
		"PERMBLOCK: 4 temp blocks within 24h":                     "permblock",
		"temp deny limit reached; evicted soonest-expiring entry": "temp_limit_eviction",
		"CSM whitelist: customer IP":                              "whitelist",
		"CSM temp whitelist":                                      "whitelist",
		"CSM bulk whitelist":                                      "whitelist",
		"dyndns: office.example.net":                              "dyndns",
		"source: whitelist":                                       "allow_source",
		"cleared 42 entries":                                      "flush",
		"Blocked via CLI":                                         "operator_cli",
		"Bulk allow via CLI":                                      "operator_cli",
		"Blocked via CSM Web UI":                                  "operator_webui",
		"Undo: re-block via CSM Web UI":                           "operator_webui",
		"manual process termination":                              "operator",
		"AF_ALG socket open":                                      "af_alg",
		"CSM rule escalation: 949110":                             "other",
		"csm auto-block: lowercase":                               "other",
		"alice":                                                   "other",
		"203.0.113.9":                                             "other",
		"CSM temp whitelist for alice":                            "other",
		"xCSM auto-block: prefixed":                               "other",
		"temp deny limit reached; alice":                          "other",
	} {
		if got := reasonKind(reason); got != want {
			t.Errorf("reasonKind(%q) = %q, want %q", reason, got, want)
		}
	}
}

func TestRecordIDs(t *testing.T) {
	a := NewAnonymizer(testSalt())
	id := a.ID(idFinding, "abc")
	if !strings.HasPrefix(id, "fid-") || len(id) != 4+32 {
		t.Fatalf("id = %q", id)
	}
	if _, err := hex.DecodeString(id[4:]); err != nil || strings.ToLower(id) != id {
		t.Fatalf("id is not lower-case hex: %q", id)
	}
	for kind, prefix := range map[idKind]string{idFinding: "fid-", idAction: "aid-", idIncident: "iid-", idTarget: "tid-"} {
		if got := a.ID(kind, "abc"); !strings.HasPrefix(got, prefix) {
			t.Errorf("%s id = %q", kind, got)
		}
	}
	if a.ID(idFinding, "abc") != id || NewAnonymizer(testSalt()).ID(idFinding, "abc") != id {
		t.Fatal("same salt and value gave different ids")
	}
	if NewAnonymizer(bytes.Repeat([]byte{0x99}, 32)).ID(idFinding, "abc") == id {
		t.Fatal("different salts gave the same id")
	}
	if a.ID(idFinding, "abc")[4:] == a.ID(idAction, "abc")[4:] {
		t.Fatal("kinds are not domain separated")
	}
	if a.ID(idAction, "ID") == a.ID(idAction, "id") {
		t.Fatal("ids fold case")
	}
	if a.ID(idFinding, "") != "" {
		t.Fatal("empty id was replaced")
	}
	seen := map[string]bool{}
	for i := range 20000 {
		seen[a.ID(idAction, fmt.Sprintf("action-%d", i))] = true
	}
	if len(seen) != 20000 {
		t.Fatalf("%d distinct values gave %d ids", 20000, len(seen))
	}

	original := fullRecord()
	undo := fullRecord()
	undo.ActionID, undo.UndoOf = "action-raw-0002", original.ActionID
	o1, err1 := a.Action(original)
	o2, err2 := a.Action(undo)
	if err1 != nil || err2 != nil || o2.UndoOf != o1.ActionID || o1.FindingID != a.ID(idFinding, original.FindingID) {
		t.Fatalf("ids do not join: %+v %+v %v %v", o1, o2, err1, err2)
	}
}

func TestVerifyTypedRowsRequireEmittedTokens(t *testing.T) {
	a := NewAnonymizer(testSalt())
	good, err := a.Action(fullRecord())
	if err != nil {
		t.Fatal(err)
	}
	if err = a.VerifyAction(good); err != nil {
		t.Fatal(err)
	}
	other := NewAnonymizer(bytes.Repeat([]byte{0x99}, 32))
	forged := "fid-" + strings.Repeat("ab", 16)
	for name, mutate := range map[string]func(*anonAction){
		"raw target":           func(o *anonAction) { o.Target = "203.0.113.9" },
		"foreign pseudonym":    func(o *anonAction) { o.Target = other.IPv4("203.0.113.9") },
		"forged finding id":    func(o *anonAction) { o.FindingID = forged },
		"raw finding id":       func(o *anonAction) { o.FindingID = "finding-raw-0001" },
		"wrong id kind":        func(o *anonAction) { o.FindingID = good.ActionID },
		"raw hostname":         func(o *anonAction) { o.Hostname = "srv.example.com" },
		"raw account":          func(o *anonAction) { o.Account = "alice" },
		"raw actor ip":         func(o *anonAction) { o.ActorIP = "198.51.100.4" },
		"free reason":          func(o *anonAction) { o.ReasonKind = "alice" },
		"unknown op":           func(o *anonAction) { o.Op = "alice" },
		"unknown action":       func(o *anonAction) { o.Action = "alice" },
		"unknown actor":        func(o *anonAction) { o.Actor = "alice" },
		"unknown result":       func(o *anonAction) { o.Result = "alice" },
		"kind mismatch":        func(o *anonAction) { o.TargetKind = "path" },
		"cidr without prefix":  func(o *anonAction) { o.TargetKind = "cidr" },
		"endpoint port 0":      func(o *anonAction) { o.TargetKind = "endpoint"; o.TargetProto = "tcp" },
		"stray port":           func(o *anonAction) { o.TargetPort = 443 },
		"wrong format version": func(o *anonAction) { o.Format = 2 },
		"zero time":            func(o *anonAction) { o.Timestamp = time.Time{} },
	} {
		row := good
		mutate(&row)
		if a.VerifyAction(row) == nil {
			t.Errorf("%s: verifier accepted %+v", name, row)
		}
	}

	fw, err := a.FirewallAudit(firewall.AuditEntry{Timestamp: recordTS, Action: "block", IP: "203.0.113.9", Source: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyFirewallAudit(fw); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*anonFirewallAudit){
		"raw target":     func(o *anonFirewallAudit) { o.Target = "203.0.113.9" },
		"opaque target":  func(o *anonFirewallAudit) { o.Target = a.ID(idTarget, "csm"); o.TargetKind = "opaque" },
		"unknown action": func(o *anonFirewallAudit) { o.Action = "apply" },
		"unknown source": func(o *anonFirewallAudit) { o.Source = "" },
		"free reason":    func(o *anonFirewallAudit) { o.ReasonKind = "203.0.113.9" },
		"zero time":      func(o *anonFirewallAudit) { o.Timestamp = time.Time{} },
	} {
		row := fw
		mutate(&row)
		if a.VerifyFirewallAudit(row) == nil {
			t.Errorf("%s: verifier accepted %+v", name, row)
		}
	}
}

// A hosting account can share a name with an id prefix. Only ids this run
// emitted are masked before the account scan; a forged id-shaped token is
// still read as text.
func TestVerifyMasksOnlyEmittedIDs(t *testing.T) {
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{{TenantID: "fid"}})
	id := a.ID(idFinding, "raw")
	if problems := a.Verify([]alert.AuditEvent{{FindingID: id, Message: "row " + id}}); len(problems) != 0 {
		t.Fatalf("emitted id reported as a leak: %v", problems)
	}
	if problems := a.Verify([]alert.AuditEvent{{Message: "row fid-" + strings.Repeat("cd", 16)}}); len(problems) == 0 {
		t.Fatal("forged id-shaped token hid a learned account")
	}
}

func TestLearnActionsFeedsTextScrubbingAndVerification(t *testing.T) {
	a := NewAnonymizer(testSalt())
	a.LearnActions([]actionlog.Record{{Hostname: "cp9.example.net", Account: "dave", FindingID: "0123456789abcdef", ActionID: "act-7777-raw"}})
	if got := a.Text("login by dave on cp9"); strings.Contains(got, "dave") || strings.Contains(got, "cp9") {
		t.Fatalf("action identities not scrubbed from text: %q", got)
	}
	for _, raw := range []string{"dave", "cp9.example.net", "0123456789abcdef", "act-7777-raw"} {
		if problems := a.Verify([]alert.AuditEvent{{Details: "x " + raw + " y"}}); len(problems) == 0 {
			t.Errorf("learned action identity %q escaped verification", raw)
		}
	}
	// Short raw ids are left to the typed verifier: a token scan for "a" or
	// "csm" would flag every row of ordinary text.
	a.LearnActions([]actionlog.Record{{ActionID: "csm", FindingID: "a1"}})
	if problems := a.Verify([]alert.AuditEvent{{Details: "csm a1"}}); len(problems) != 0 {
		t.Fatalf("short raw ids flagged ordinary text: %v", problems)
	}
}

func validRecordJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(fullRecord())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDecodeStrict(t *testing.T) {
	valid := validRecordJSON(t)
	trimmed := valid[:len(valid)-1]
	with := func(extra string) []byte { return []byte(string(trimmed) + "," + extra + "}") }
	for name, tc := range map[string]struct {
		data []byte
		want error
	}{
		"valid":            {valid, nil},
		"empty":            {nil, errNotObject},
		"array":            {[]byte(`[]`), errNotObject},
		"null":             {[]byte(`null`), errNotObject},
		"string":           {[]byte(`"x"`), errNotObject},
		"number":           {[]byte(`1`), errNotObject},
		"unknown field":    {with(`"zzz":1`), errUnknownField},
		"duplicate object": {with(`"after":{"exists":true}`), errDuplicateKey},
		"duplicate key":    {with(`"op":"respond.block_ip"`), errDuplicateKey},
		"case alias":       {with(`"OP":"respond.block_ip"`), errUnknownField},
		"null nested":      {[]byte(strings.Replace(string(valid), `"after":{"exists":false}`, `"after":null`, 1)), errNull},
		"null scalar":      {[]byte(strings.Replace(string(valid), `"account":"alice"`, `"account":null`, 1)), errNull},
		"second object":    {append(append([]byte{}, valid...), valid...), errTrailing},
		"trailing scalar":  {append(append([]byte{}, valid...), " 1"...), errTrailing},
		"trailing garbage": {append(append([]byte{}, valid...), " x"...), errTrailing},
		"unmatched close":  {append(append([]byte{}, valid...), "]"...), errTrailing},
		"string version":   {[]byte(strings.Replace(string(valid), `"v":1`, `"v":"1"`, 1)), errType},
		"negative version": {[]byte(strings.Replace(string(valid), `"action_version":3`, `"action_version":-1`, 1)), errType},
		"bad time":         {[]byte(strings.Replace(string(valid), `"ts":"2026-09-08T10:00:00Z"`, `"ts":"yesterday"`, 1)), errType},
		"scalar command":   {[]byte(strings.Replace(string(valid), `"command":["nft","add","element","203.0.113.9"]`, `"command":"nft"`, 1)), errType},
		"array state":      {[]byte(strings.Replace(string(valid), `"after":{"exists":false}`, `"after":[]`, 1)), errType},
		"uid overflow":     {[]byte(strings.Replace(string(valid), `"uid":1003`, `"uid":4294967296`, 1)), errType},
	} {
		t.Run(name, func(t *testing.T) {
			var rec actionlog.Record
			if err := decodeStrict(tc.data, &rec); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	onlyNested := []byte(strings.Replace(string(valid), `"after":{"exists":false}`, `"after":{"exists":false,"extra":1}`, 1))
	if err := decodeStrict(onlyNested, &actionlog.Record{}); !errors.Is(err, errUnknownField) {
		t.Fatalf("nested unknown field: %v", err)
	}
}

func TestDecodeStrictLimits(t *testing.T) {
	valid := validRecordJSON(t)
	setField := func(key string, value any) []byte {
		return seedJSON(t, fullRecord(), func(m map[string]any) { m[key] = value })
	}
	decode := func(data []byte) error { return decodeStrict(data, &actionlog.Record{}) }

	padded := append(append([]byte{}, valid...), bytes.Repeat([]byte{' '}, maxLineBytes-len(valid))...)
	if err := decode(padded); err != nil {
		t.Fatalf("line at the limit: %v", err)
	}
	if err := decode(append(padded, ' ')); !errors.Is(err, errLineTooLong) {
		t.Fatalf("line over the limit: %v", err)
	}
	// Discarded text fields are bounded too: a limit applies before anything
	// decides what to keep.
	for _, key := range []string{"reason", "error", "target", "undo"} {
		if err := decode(setField(key, strings.Repeat("x", maxTextBytes))); err != nil {
			t.Errorf("%s at the text limit: %v", key, err)
		}
		if err := decode(setField(key, strings.Repeat("x", maxTextBytes+1))); !errors.Is(err, errTooLong) {
			t.Errorf("%s over the text limit: %v", key, err)
		}
	}
	for _, key := range []string{"account", "op", "finding_id", "hostname"} {
		if err := decode(setField(key, strings.Repeat("x", maxScalarBytes))); err != nil {
			t.Errorf("%s at the scalar limit: %v", key, err)
		}
		if err := decode(setField(key, strings.Repeat("x", maxScalarBytes+1))); !errors.Is(err, errTooLong) {
			t.Errorf("%s over the scalar limit: %v", key, err)
		}
	}
	long := []byte(strings.Replace(string(valid), `"action_version":3`, `"action_version":1`+strings.Repeat("0", maxScalarBytes), 1))
	if err := decode(long); !errors.Is(err, errTooLong) {
		t.Errorf("overlong number: %v", err)
	}
	command := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = "a"
		}
		return out
	}
	if err := decode(setField("command", command(maxArrayItems))); err != nil {
		t.Errorf("command at the element limit: %v", err)
	}
	if err := decode(setField("command", command(maxArrayItems+1))); !errors.Is(err, errTooMany) {
		t.Errorf("command over the element limit: %v", err)
	}
	if err := decode(setField("command", []any{strings.Repeat("x", maxTextBytes+1)})); !errors.Is(err, errTooLong) {
		t.Errorf("command element over the text limit: %v", err)
	}

	chain := func(parents int) []byte {
		p := &processctx.ProcessContext{Comm: "leaf"}
		for range parents {
			p = &processctx.ProcessContext{Comm: "child", Parent: p}
		}
		raw, err := json.Marshal(alert.AuditEvent{V: 1, Timestamp: recordTS, Check: "x", Process: p})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if err := decodeStrict(chain(maxParentDepth), &alert.AuditEvent{}); err != nil {
		t.Errorf("process chain at the parent limit: %v", err)
	}
	if err := decodeStrict(chain(maxParentDepth+1), &alert.AuditEvent{}); !errors.Is(err, errTooDeep) {
		t.Errorf("process chain over the parent limit: %v", err)
	}
}

// Refusals are fixed codes. None may repeat a byte of the record.
func TestRecordErrorsCarryNoInput(t *testing.T) {
	a := NewAnonymizer(testSalt())
	rec := fullRecord()
	rec.Op, rec.Target = "respond.alice-marker", "alice-marker"
	_, err := a.Action(rec)
	if err == nil || strings.Contains(err.Error(), "alice") {
		t.Fatalf("error = %v", err)
	}
	for _, data := range []string{`{"alice-marker":1}`, `{"op":"alice-marker","op":"x"}`, `{"v":"alice-marker"}`, `{"ts":"alice-marker"}`} {
		err := decodeStrict([]byte(data), &actionlog.Record{})
		if err == nil || strings.Contains(err.Error(), "alice") {
			t.Errorf("%s -> %v", data, err)
		}
	}
}
