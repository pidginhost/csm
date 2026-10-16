package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// appliedRow is the applied audit row of a verified block of addr by the
// action named by digit.
func appliedRow(t *testing.T, digit, addr string, expires time.Time) admission.AuditRow {
	t.Helper()
	target, err := admission.CanonicalAddress(addr, admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	return admission.AuditRow{
		Attempt: admission.Attempt{ID: admission.ActionID("act_" + strings.Repeat(digit, 32)), Seq: 1},
		State:   admission.StateVerified, Disposition: admission.DispositionApplied,
		Kind: admission.KindBlockIP, Target: target, Check: "ssh_brute", ExpiresAt: expires, At: time.Now(),
	}
}

// Design P14: the production owner hands each applied block to the
// daemon, which records it where the legacy path records its own: the
// attack database's blocked marker for every applied row, as the legacy
// path marks a block that applied, and a threat database row that lapses
// with the block. The threat row is written only while the action's
// verified firewall row still stands and before its expiry. A repeated
// row changes nothing.
func TestAdmissionRecordsAppliedBlocks(t *testing.T) {
	dir := t.TempDir()
	sdb, cleanup := openTestBoltStore(t, t.TempDir())
	t.Cleanup(cleanup)
	expires := time.Now().Add(time.Hour).UTC()
	standing, removed, expired := appliedRow(t, "1", "203.0.113.40", expires), appliedRow(t, "2", "203.0.113.41", expires), appliedRow(t, "3", "203.0.113.42", time.Now().Add(-time.Minute))
	held := appliedRow(t, "4", "203.0.113.44", expires)
	data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{
		{IP: "203.0.113.40", Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse, ActionID: string(standing.Attempt.ID), ExpiresAt: expires},
		{IP: "203.0.113.42", Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse, ActionID: string(expired.Attempt.ID), ExpiresAt: expired.ExpiresAt},
		{IP: "203.0.113.44", Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse, ActionID: string(held.Attempt.ID), ExpiresAt: expires, Unverified: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "firewall", "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checks.SetGlobalThreatDBForTest(dir))
	adb := attackdb.NewForTest(map[string]*attackdb.IPRecord{
		"203.0.113.40": {IP: "203.0.113.40"}, "203.0.113.41": {IP: "203.0.113.41"}, "203.0.113.42": {IP: "203.0.113.42"}, "203.0.113.43": {IP: "203.0.113.43"},
		"203.0.113.44": {IP: "203.0.113.44"},
	})
	previous := attackdb.Global()
	attackdb.SetGlobal(adb)
	t.Cleanup(func() { attackdb.SetGlobal(previous) })

	d := New(&config.Config{StatePath: dir}, nil, nil, "")
	opts := d.admissionOptions(nil)
	if opts.Applied == nil {
		t.Fatal("production hands applied blocks to no one")
	}
	rows := []admission.AuditRow{standing, removed, expired, held}
	for range 2 {
		if err = opts.Applied(rows); err != nil {
			t.Fatal(err)
		}
	}
	first, found := sdb.GetPermanentBlock("203.0.113.40")
	if !found {
		t.Fatal("applied outcome has no durable threat row")
	}
	attack := adb.LookupIP("203.0.113.40")
	if _, err = sdb.AppendUndoEntry("operator", store.UndoEntry{Inverse: "test", Targets: []string{"203.0.113.40"}}); err != nil {
		t.Fatal(err)
	}
	// A fresh consumer has no in-memory duplicate guard after restart.
	t.Cleanup(checks.SetGlobalThreatDBForTest(dir))
	if err = opts.Applied(rows); err != nil {
		t.Fatal(err)
	}
	if again, _ := sdb.GetPermanentBlock("203.0.113.40"); !reflect.DeepEqual(again, first) {
		t.Fatalf("replay changed the durable row: %+v -> %+v", first, again)
	}
	if !reflect.DeepEqual(attack, adb.LookupIP("203.0.113.40")) {
		t.Fatal("replay changed the attack record")
	}
	if _, ok, err := sdb.LatestUndoEntry("operator"); err != nil || !ok {
		t.Fatalf("replay invalidated undo: %t, %v", ok, err)
	}
	tdb := checks.GetThreatDB()
	if match, ok := tdb.LookupMatch("203.0.113.40"); !ok || match.Source != "CSM auto-block: ssh_brute" || !match.ExpiresAt.Equal(expires) {
		t.Fatalf("standing block threat row = %+v, %t", match, ok)
	}
	for _, ip := range []string{"203.0.113.41", "203.0.113.42", "203.0.113.44"} {
		if _, found := sdb.GetPermanentBlock(ip); found {
			t.Errorf("%s: stale block wrote durable threat evidence", ip)
		}
		if match, ok := tdb.LookupMatch(ip); ok {
			t.Errorf("%s: a block that no longer stands recorded threat evidence %+v", ip, match)
		}
	}
	for _, ip := range []string{"203.0.113.40", "203.0.113.41", "203.0.113.42", "203.0.113.44"} {
		if rec := adb.LookupIP(ip); rec == nil || !rec.AutoBlocked {
			t.Errorf("%s: applied block not marked in the attack database: %+v", ip, rec)
		}
	}
	if rec := adb.LookupIP("203.0.113.43"); rec == nil || rec.AutoBlocked {
		t.Fatalf("an address no block named was marked: %+v", rec)
	}
}

func TestAdmissionAppliedReadAndWriteFailures(t *testing.T) {
	dir := t.TempDir()
	sdb, cleanup := openTestBoltStore(t, t.TempDir())
	t.Cleanup(cleanup)
	t.Cleanup(checks.SetGlobalThreatDBForTest(dir))
	d := New(&config.Config{StatePath: dir}, nil, nil, "")
	row := appliedRow(t, "6", "203.0.113.46", time.Now().Add(time.Hour).UTC())
	adb := attackdb.NewForTest(map[string]*attackdb.IPRecord{"203.0.113.46": {IP: "203.0.113.46"}})
	previous := attackdb.Global()
	attackdb.SetGlobal(adb)
	t.Cleanup(func() { attackdb.SetGlobal(previous) })
	before := adb.LookupIP("203.0.113.46")
	assertNoThreat := func() {
		t.Helper()
		if match, ok := checks.GetThreatDB().LookupMatch("203.0.113.46"); ok {
			t.Errorf("failed delivery published threat evidence: %+v", match)
		}
	}
	path := filepath.Join(dir, "firewall", "state.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.consumeAppliedBlocks([]admission.AuditRow{row}); err == nil {
		t.Fatal("an unreadable state image reported consumption")
	}
	assertNoThreat()
	if after := adb.LookupIP("203.0.113.46"); !reflect.DeepEqual(before, after) {
		t.Errorf("an unreadable state image changed the attack record: %+v -> %+v", before, after)
	}
	data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{{
		IP: "203.0.113.46", Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse,
		ActionID: string(row.Attempt.ID), ExpiresAt: row.ExpiresAt,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = sdb.Close(); err != nil {
		t.Fatal(err)
	}
	if err = d.consumeAppliedBlocks([]admission.AuditRow{row}); err == nil {
		t.Fatal("a failed threat write reported consumption")
	}
	assertNoThreat()
	// The attack database is its own destination: the block applied, so it
	// is marked whatever the threat store does.
	if rec := adb.LookupIP("203.0.113.46"); rec == nil || !rec.AutoBlocked {
		t.Errorf("a failed threat write held back the attack mark: %+v", rec)
	}
}

func TestAdmissionAppliedBlockAddressFamilies(t *testing.T) {
	for _, raw := range []string{"2001:db8::46", "::ffff:203.0.113.46"} {
		t.Run(raw, func(t *testing.T) {
			dir := t.TempDir()
			sdb, cleanup := openTestBoltStore(t, t.TempDir())
			t.Cleanup(cleanup)
			t.Cleanup(checks.SetGlobalThreatDBForTest(dir))
			row := appliedRow(t, "6", raw, time.Now().Add(time.Hour).UTC())
			addr, _ := row.Target.Addr()
			ip := addr.String()
			adb := attackdb.NewForTest(map[string]*attackdb.IPRecord{ip: {IP: ip}})
			previous := attackdb.Global()
			attackdb.SetGlobal(adb)
			t.Cleanup(func() { attackdb.SetGlobal(previous) })
			data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{{
				IP: ip, Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse,
				ActionID: string(row.Attempt.ID), ExpiresAt: row.ExpiresAt,
			}}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "firewall", "state.json")
			if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			d := New(&config.Config{StatePath: dir}, nil, nil, "")
			if err = d.consumeAppliedBlocks([]admission.AuditRow{row}); err != nil {
				t.Fatal(err)
			}
			if entry, ok := sdb.GetPermanentBlock(ip); !ok || !entry.ExpiresAt.Equal(row.ExpiresAt) {
				t.Errorf("canonical address has no stored evidence: %+v, %t", entry, ok)
			}
			if match, ok := checks.GetThreatDB().LookupMatch(ip); !ok || !match.ExpiresAt.Equal(row.ExpiresAt) {
				t.Errorf("canonical address has no threat evidence: %+v, %t", match, ok)
			}
			if rec := adb.LookupIP(ip); rec == nil || !rec.AutoBlocked {
				t.Errorf("canonical address was not marked: %+v", rec)
			}
		})
	}
}

// A replayed applied row can be delivered before the daemon opens its threat
// or attack database. It stays pending until both exist: acknowledging it
// would lose its evidence for good.
func TestAdmissionAppliedWaitsForItsDestinations(t *testing.T) {
	for _, missing := range []string{"threat", "attack"} {
		t.Run(missing, func(t *testing.T) {
			dir := t.TempDir()
			sdb, cleanup := openTestBoltStore(t, t.TempDir())
			t.Cleanup(cleanup)
			row := appliedRow(t, "7", "203.0.113.47", time.Now().Add(time.Hour).UTC())
			data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{{
				IP: "203.0.113.47", Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse,
				ActionID: string(row.Attempt.ID), ExpiresAt: row.ExpiresAt,
			}}})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "firewall", "state.json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			adb := attackdb.NewForTest(map[string]*attackdb.IPRecord{"203.0.113.47": {IP: "203.0.113.47"}})
			previous := attackdb.Global()
			t.Cleanup(func() { attackdb.SetGlobal(previous) })
			if missing == "threat" {
				t.Cleanup(checks.ClearGlobalThreatDBForTest())
				attackdb.SetGlobal(adb)
			} else {
				t.Cleanup(checks.SetGlobalThreatDBForTest(dir))
				attackdb.SetGlobal(nil)
			}
			d := New(&config.Config{StatePath: dir}, nil, nil, "")
			if err = d.consumeAppliedBlocks([]admission.AuditRow{row}); err == nil {
				t.Fatalf("an applied row was consumed without the %s database", missing)
			}
			if _, found := sdb.GetPermanentBlock("203.0.113.47"); found {
				t.Errorf("a refused delivery stored threat evidence")
			}
			if rec := adb.LookupIP("203.0.113.47"); rec.AutoBlocked {
				t.Errorf("a refused delivery marked the attack record")
			}
		})
	}
}
