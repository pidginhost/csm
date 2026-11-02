//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// importRow is a row a legacy automatic block stamped at ip, lasting ttl
// from the fixture's clock.
func (f *batchFixture) importRow(ip string, ttl time.Duration) BlockedEntry {
	return BlockedEntry{IP: ip, Reason: "auto-block: legacy", Source: SourceAutoResponse, BlockedAt: f.at.Add(-time.Minute), ExpiresAt: f.at.Add(ttl), Automatic: true}
}

// importOf is the import the engine lists for row, and the victim a member
// names to evict it.
func importOf(row BlockedEntry) BlockImport {
	return BlockImport{ID: blockEffectID(row), IP: row.IP, ExpiresAt: row.ExpiresAt}
}

func victimOf(row BlockedEntry) BlockVictim {
	return BlockVictim{Action: blockEffectID(row), IP: row.IP, ExpiresAt: row.ExpiresAt}
}

// The snapshot lists the imports admission may evict: a timed row a legacy
// automatic block stamped, alone at its address, verified, with an element
// whose lifetime it proves. Soonest expiry first, then name. Every other
// occupant stays out of the list, even an import the class counts.
func TestBlockAdmissionSnapshotListsTheImports(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	soon, later := f.importRow("2001:db8::70", time.Hour), f.importRow("203.0.113.70", 2*time.Hour)
	tie := f.importRow("203.0.113.77", 2*time.Hour)
	unproven, aliased := f.importRow("203.0.113.71", time.Hour), f.importRow("203.0.113.72", time.Hour)
	alias := aliased
	alias.IP = "::ffff:203.0.113.72"
	unverified := f.importRow("203.0.113.73", time.Hour)
	unverified.Unverified = true
	gone := f.importRow("203.0.113.76", time.Hour)
	rows := []BlockedEntry{later, soon, tie, unproven, aliased, alias, unverified, gone,
		{IP: "203.0.113.74", Reason: "operator", BlockedAt: f.at, ExpiresAt: f.at.Add(time.Hour)},
		{IP: "203.0.113.75", Reason: "CSM auto-block: owner", BlockedAt: f.at, ExpiresAt: f.at.Add(time.Hour), ActionID: victimAction(5)},
	}
	writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: rows})
	for _, row := range rows[:7] {
		f.live[stateIPKey(row.IP)] = row.ExpiresAt.Sub(f.at)
	}
	f.live["203.0.113.74"], f.live["203.0.113.75"] = time.Hour, time.Hour
	f.expires["203.0.113.71"] = 10 * time.Minute
	got, err := f.e.BlockAdmissionSnapshot(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []BlockImport{importOf(soon), importOf(later), importOf(tie)}
	if want[1].ID > want[2].ID {
		want[1], want[2] = want[2], want[1]
	}
	if fmt.Sprint(got.Imports) != fmt.Sprint(want) {
		t.Fatalf("imports %+v\nwant %+v", got.Imports, want)
	}
	if got.Imported != 5 {
		t.Fatalf("imported %d, want the 5 verified stamped occupants counted whether listed or not", got.Imported)
	}
}

// The list holds the MaxBlockImports soonest to expire.
func TestBlockAdmissionSnapshotBoundsTheImports(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	var rows []BlockedEntry
	for i := MaxBlockImports; i >= 0; i-- {
		row := f.importRow(fmt.Sprintf("2001:db8::%x", i+1), time.Hour+time.Duration(i)*time.Minute)
		rows = append(rows, row)
		f.live[row.IP] = row.ExpiresAt.Sub(f.at)
	}
	writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: rows})
	got, err := f.e.BlockAdmissionSnapshot(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Imports) != MaxBlockImports {
		t.Fatalf("listed %d imports, want %d", len(got.Imports), MaxBlockImports)
	}
	if got.Imports[0] != importOf(rows[MaxBlockImports]) || got.Imports[MaxBlockImports-1] != importOf(rows[1]) {
		t.Fatalf("%d imports from %+v to %+v", len(got.Imports), got.Imports[0], got.Imports[len(got.Imports)-1])
	}
}

// While startup could not prove admission outcomes no row makes room, so
// the snapshot lists no import.
func TestBlockAdmissionSnapshotListsNoImportWhileActionsAreUnproven(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	row := f.importRow("203.0.113.70", time.Hour)
	writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row}})
	f.live[row.IP] = time.Hour
	f.e.SetBlockActionsUnproven(errors.New("ledger unavailable"))
	if got, err := f.e.BlockAdmissionSnapshot(nil, nil); err != nil || len(got.Imports) != 0 || got.Imported != 1 {
		t.Fatalf("snapshot %+v, %v; want the import counted, not listed", got, err)
	}
}

// Member checks age both the row's lease and its sampled kernel lifetime.
// A wall step must not hide a live import or list one past its lease.
func TestBlockAdmissionSnapshotAgesImportProofs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		delay    time.Duration
		wallStep time.Duration
		alias    bool
		listed   bool
	}{
		{name: "slow check", delay: 3 * time.Second, listed: true},
		{name: "wall back", delay: 3 * time.Second, wallStep: -time.Hour, listed: true},
		{name: "expired during check", delay: time.Hour},
		{name: "wall forward", wallStep: time.Hour},
		{name: "operator alias expires", delay: 3 * time.Second, alias: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			row := f.importRow("203.0.113.70", time.Hour)
			rows := []BlockedEntry{row}
			imported, unclaimed := 1, 0
			if tc.alias {
				rows = append(rows, BlockedEntry{IP: "::ffff:203.0.113.70", Reason: "operator", ExpiresAt: f.at.Add(2 * time.Second)})
				imported, unclaimed = 0, 1
			}
			writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: rows})
			f.live[row.IP] = time.Hour
			clock := &leaseSteps{wall: f.at, elapsed: f.at}
			f.e.leaseClock, f.e.expiryClock = clock.read, func() time.Time { return clock.wall }
			checks := 0
			f.e.localAddrsLookup = func() ([]string, error) {
				checks++
				clock.advance(tc.delay)
				clock.step(tc.wallStep)
				return nil, nil
			}
			got, err := f.e.BlockAdmissionSnapshot([]BlockMember{f.member("act_new", "203.0.113.71")}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if checks != 1 || len(got.Answers) != 1 || got.Answers[0].Refusal != "" {
				t.Fatalf("checks %d, answers %+v; want one successful check", checks, got.Answers)
			}
			if got.Temporary != 1 || got.Imported != imported || got.Admission != 0 || got.Unclaimed != unclaimed {
				t.Fatalf("import proof changed occupancy: %+v", got)
			}
			if tc.listed {
				if len(got.Imports) != 1 || got.Imports[0] != importOf(row) {
					t.Fatalf("imports %+v; want the live import %+v", got.Imports, importOf(row))
				}
			} else if len(got.Imports) != 0 {
				t.Fatalf("imports %+v; want no eligible import", got.Imports)
			}
		})
	}
}

// newImportFixture is a batch fixture whose temporary set of two is full:
// an import and an operator tempban, which is never a victim.
func newImportFixture(t *testing.T) (*batchFixture, BlockedEntry) {
	t.Helper()
	f := newBatchFixture(t, FirewallState{})
	row := f.importRow("203.0.113.60", time.Hour)
	writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row, {IP: "203.0.113.61", Reason: "operator", ExpiresAt: f.at.Add(time.Hour)}}})
	f.e.cfg.DenyTempIPLimit = 2
	f.live[row.IP], f.live["203.0.113.61"] = time.Hour, time.Hour
	return f, row
}

// A member may take an import's slot when the import is still the row the
// ledger claimed: its name, its expiry, alone at its address, stamped,
// verified and proven live. Anything else leaves the member needing a
// free slot.
func TestBlockVictimMayBeAnImport(t *testing.T) {
	for name, tc := range map[string]struct {
		victim func(*batchFixture, BlockedEntry) BlockVictim
		state  func(*testing.T, *batchFixture, BlockedEntry)
		evicts bool
	}{
		"the import": {evicts: true},
		"an operator re-block": {state: func(t *testing.T, f *batchFixture, row BlockedEntry) {
			row.Automatic, row.Reason, row.Source = false, "operator", "operator"
			writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row}})
		}},
		"an unstamped automatic reason": {state: func(t *testing.T, f *batchFixture, row BlockedEntry) {
			row.Automatic = false
			writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row}})
		}},
		"a changed source": {state: func(t *testing.T, f *batchFixture, row BlockedEntry) {
			row.Source = "other"
			writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row}})
		}},
		"a legacy eviction filled by other work": {state: func(_ *testing.T, f *batchFixture, row BlockedEntry) {
			delete(f.live, row.IP)
			f.live["203.0.113.62"] = time.Hour
		}},
		"another stamp": {victim: func(_ *batchFixture, row BlockedEntry) BlockVictim {
			row.BlockedAt = row.BlockedAt.Add(-time.Second)
			return victimOf(row)
		}},
		"another expiry": {victim: func(_ *batchFixture, row BlockedEntry) BlockVictim {
			v := victimOf(row)
			v.ExpiresAt = v.ExpiresAt.Add(time.Second)
			return v
		}},
		"the operator's tempban": {victim: func(f *batchFixture, _ BlockedEntry) BlockVictim {
			return victimOf(BlockedEntry{IP: "203.0.113.61", Reason: "operator", ExpiresAt: f.at.Add(time.Hour)})
		}},
		"an unverified import": {state: func(t *testing.T, f *batchFixture, row BlockedEntry) {
			row.Unverified = true
			writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row}})
		}},
		"an alias row": {state: func(t *testing.T, f *batchFixture, row BlockedEntry) {
			alias := row
			alias.IP = "::ffff:" + row.IP
			writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row, alias, {IP: "203.0.113.61", Reason: "operator", ExpiresAt: f.at.Add(time.Hour)}}})
		}},
		"a zoned alias row": {state: func(t *testing.T, f *batchFixture, row BlockedEntry) {
			alias := row
			alias.IP = "::ffff:" + row.IP + "%eth0"
			writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row, alias, {IP: "203.0.113.61", Reason: "operator", ExpiresAt: f.at.Add(time.Hour)}}})
		}},
		"an unproven lifetime": {state: func(_ *testing.T, f *batchFixture, row BlockedEntry) { f.expires[row.IP] = 10 * time.Minute }},
		"unproven actions": {state: func(_ *testing.T, f *batchFixture, _ BlockedEntry) {
			f.e.SetBlockActionsUnproven(errors.New("ledger unavailable"))
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f, row := newImportFixture(t)
			if tc.state != nil {
				tc.state(t, f, row)
			}
			victim := victimOf(row)
			if tc.victim != nil {
				victim = tc.victim(f, row)
			}
			refusals, evicts := f.checkMembers(t, []BlockMember{f.evicting("act_evict", "203.0.113.21", victim)})
			want := BlockRefusedFull
			if tc.evicts {
				want = ""
			}
			if refusals[0] != want || evicts[0] != tc.evicts {
				t.Fatalf("refusal %q, evicts %v; want %q, %v", refusals[0], evicts[0], want, tc.evicts)
			}
		})
	}
}

// The batch deletes an import in its member's transaction and proves it
// gone; its row stays until the owner retires it by name, which removes
// that stamped row and nothing else.
func TestApplyBlockBatchEvictsAnImport(t *testing.T) {
	f, row := newImportFixture(t)
	sent := f.modelKernel(t, nil)
	m := f.evicting("act_evict", "203.0.113.21", victimOf(row))
	results, err := f.e.ApplyBlockBatch([]BlockMember{m})
	if err != nil || effects(results) != "applied/" || results[0].Victim != VictimRemoved {
		t.Fatalf("results %+v, %v", results, err)
	}
	if adds, dels := sentElements(t, (*sent)[0]); len(*sent) != 1 || fmt.Sprint(dels) != "[203.0.113.60]" || adds[m.IP] == 0 {
		t.Fatalf("%d transactions, adds %v, deletes %v", len(*sent), adds, dels)
	}
	if rows := f.storedRows(t); rows[row.IP].Automatic != true {
		t.Fatalf("rows %v; the batch keeps the import's row", rows)
	}
	clear, err := f.e.RetireBlockActions([]BlockAction{{Action: blockEffectID(row), IP: row.IP}})
	if err != nil || fmt.Sprint(clear) != "[true]" {
		t.Fatalf("retiring the import = %v, %v", clear, err)
	}
	if rows := f.storedRows(t); len(rows) != 2 || rows[row.IP].IP != "" || rows["203.0.113.61"].Reason != "operator" {
		t.Fatalf("rows %v; want the import's row gone and the rest kept", rows)
	}
}

// Retirement knows an import by its name. One whose element is still
// there is not retired; a name that matches an operator's row removes
// nothing, since only a stamped row is retirable under that name.
func TestRetireBlockActionsKnowsImportsByName(t *testing.T) {
	f, row := newImportFixture(t)
	operator := BlockedEntry{IP: "203.0.113.62", Reason: "operator", ExpiresAt: f.at.Add(time.Hour)}
	unstamped := f.importRow("203.0.113.63", time.Hour)
	unstamped.Automatic = false
	writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row, operator, unstamped}})
	clear, err := f.e.RetireBlockActions([]BlockAction{{Action: blockEffectID(row), IP: row.IP}, {Action: blockEffectID(operator), IP: operator.IP}, {Action: blockEffectID(unstamped), IP: unstamped.IP}})
	if err != nil || fmt.Sprint(clear) != "[false true true]" {
		t.Fatalf("retire = %v, %v; want the live import held", clear, err)
	}
	if rows := f.storedRows(t); len(rows) != 3 || rows[row.IP] != row || rows[operator.IP] != operator || rows[unstamped.IP] != unstamped {
		t.Fatalf("rows %v; want the live import and both unstamped rows kept", rows)
	}
}

// Aliases with different names can prove the same live element. They must
// not retire one another and leave that element without a retained row.
func TestRetireBlockActionsKeepsLiveImportAliases(t *testing.T) {
	for _, aliasIP := range []string{"203.0.113.60", "::ffff:203.0.113.60", "::ffff:203.0.113.60%eth0"} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%t", aliasIP, reverse), func(t *testing.T) {
				f := newBatchFixture(t, FirewallState{})
				row := f.importRow("203.0.113.60", time.Hour)
				alias := row
				alias.IP, alias.Source = aliasIP, "other automatic source"
				rows := []BlockedEntry{row, alias}
				if reverse {
					rows[0], rows[1] = rows[1], rows[0]
				}
				writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: rows})
				f.live[row.IP] = time.Hour
				actions := []BlockAction{{Action: blockEffectID(rows[0]), IP: row.IP}, {Action: blockEffectID(rows[1]), IP: row.IP}}
				clear, err := f.e.RetireBlockActions(actions)
				if err != nil || fmt.Sprint(clear) != "[false false]" {
					t.Fatalf("live aliases retired one another: %v, %v", clear, err)
				}
				if got := readRawFirewallState(t, f.e).Blocked; fmt.Sprint(got) != fmt.Sprint(rows) {
					t.Fatalf("retirement changed live rows: %+v; want %+v", got, rows)
				}
				delete(f.live, row.IP)
				clear, err = f.e.RetireBlockActions(actions)
				if err != nil || fmt.Sprint(clear) != "[true true]" {
					t.Fatalf("retiring absent aliases: %v, %v", clear, err)
				}
				if got := readRawFirewallState(t, f.e).Blocked; len(got) != 0 {
					t.Fatalf("retirement kept absent imports: %+v", got)
				}
			})
		}
	}
}

// A replacement with a different proven lifetime still releases the old
// import; only the live replacement keeps its row.
func TestRetireBlockActionsRetiresReplacedImport(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	old := f.importRow("203.0.113.60", time.Hour)
	replacement := f.importRow("::ffff:203.0.113.60", 2*time.Hour)
	writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{old, replacement}})
	f.live[old.IP] = 2 * time.Hour
	clear, err := f.e.RetireBlockActions([]BlockAction{{Action: blockEffectID(old), IP: old.IP}, {Action: blockEffectID(replacement), IP: old.IP}})
	if err != nil || fmt.Sprint(clear) != "[true false]" {
		t.Fatalf("retiring replaced import: %v, %v", clear, err)
	}
	if got := readRawFirewallState(t, f.e).Blocked; len(got) != 1 || got[0] != replacement {
		t.Fatalf("retirement changed replacement: %+v; want %+v", got, replacement)
	}
}

// Import identity follows the raw row's name and its kernel address. A
// mapped row can be evicted and retired by the snapshot's canonical IP;
// another retained row at that address, including a zone, disqualifies it.
func TestImportIdentityAcrossAddressSpellings(t *testing.T) {
	for _, tc := range []struct{ name, raw, canonical, alias string }{
		{"mapped", "::ffff:203.0.113.60", "203.0.113.60", ""},
		{"v6", "2001:0db8::60", "2001:db8::60", ""},
		{"mapped alias", "203.0.113.60", "203.0.113.60", "::ffff:203.0.113.60"},
		{"zoned alias", "2001:db8::60", "2001:db8::60", "2001:db8::60%eth0"},
		{"zoned row", "2001:db8::60%eth0", "2001:db8::60", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			f.e.cfg.DenyTempIPLimit = 1
			row := f.importRow(tc.raw, time.Hour)
			rows := []BlockedEntry{row}
			if tc.alias != "" {
				alias := row
				alias.IP = tc.alias
				rows = append(rows, alias)
			}
			writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: rows})
			f.live[tc.canonical] = time.Hour
			adm, err := f.e.BlockAdmissionSnapshot(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			eligible := tc.alias == "" && tc.name != "zoned row"
			wantCount := 0
			if eligible {
				wantCount = 1
			}
			if len(adm.Imports) != wantCount {
				t.Fatalf("imports %+v; want %d for %s", adm.Imports, wantCount, tc.name)
			}
			if adm.Imported+adm.Unclaimed != 1 || adm.Admission != 0 || len(adm.Imports) > adm.Imported {
				t.Fatalf("import list disagrees with occupancy: %+v", adm)
			}
			v := victimOf(row)
			v.IP = tc.canonical
			m := f.evicting("act_evict", "203.0.113.21", v)
			refusals, evicts := f.checkMembers(t, []BlockMember{m})
			wantRefusal := BlockRefusedFull
			if eligible {
				wantRefusal = ""
			}
			if refusals[0] != wantRefusal || evicts[0] != eligible {
				t.Fatalf("victim eligibility %v, refusals %v; want %t, %q", evicts, refusals, eligible, wantRefusal)
			}
			if !eligible {
				return
			}
			if adm.Imports[0] != (BlockImport{ID: blockEffectID(row), IP: tc.canonical, ExpiresAt: row.ExpiresAt}) {
				t.Fatalf("import identity changed: %+v", adm.Imports[0])
			}
			action := BlockAction{Action: v.Action, IP: v.IP}
			if clear, err := f.e.RetireBlockActions([]BlockAction{action}); err != nil || fmt.Sprint(clear) != "[false]" {
				t.Fatalf("retirement mistook a live import: %v, %v", clear, err)
			}
			f.modelKernel(t, nil)
			if result, err := f.e.ApplyBlockBatch([]BlockMember{m}); err != nil || len(result) != 1 || result[0].Effect != BlockApplied || result[0].Victim != VictimRemoved {
				t.Fatalf("eviction %+v, %v", result, err)
			}
			if clear, err := f.e.RetireBlockActions([]BlockAction{action}); err != nil || fmt.Sprint(clear) != "[true]" {
				t.Fatalf("retiring removed import: %v, %v", clear, err)
			}
			if rows := f.storedRows(t); len(rows) != 1 || rows[m.IP].ActionID != m.Action {
				t.Fatalf("retirement kept the import or removed its replacement: %+v", rows)
			}
		})
	}
}
