//go:build linux

package firewall

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

// A timed row a legacy automatic block writes says so in its own field,
// never in its reason text (spec 6): the field, not a user-editable reason,
// is what later lets admission treat the row as a known automatic import.
// Permanent rows, operator rows and a row an operator block replaces carry
// no mark.
func TestLegacyAutomaticBlockStampsItsRow(t *testing.T) {
	now := time.Now()
	stamped := BlockedEntry{IP: "192.0.2.63", Reason: "auto-block: earlier", BlockedAt: now, ExpiresAt: now.Add(time.Hour), Automatic: true}
	for _, tc := range []struct {
		name      string
		prior     []BlockedEntry
		automatic bool
		ip        string
		reason    string
		ttl       time.Duration
		want      bool
	}{
		{"automatic timed block", nil, true, "192.0.2.60", "auto-block: test", time.Hour, true},
		{"automatic request with manual reason", nil, true, "192.0.2.67", "operator", time.Hour, true},
		{"automatic permanent block", nil, true, "192.0.2.61", "auto-block: test", 0, false},
		{"operator timed block", nil, false, "192.0.2.62", "operator", time.Hour, false},
		{"operator block with automatic reason text", nil, false, "192.0.2.66", "auto-block: copied by hand", time.Hour, false},
		{"operator block over a stamped row", []BlockedEntry{stamped}, false, stamped.IP, "operator", 2 * time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := nftConnReturningErrsThenOK(t)
			e := newBlockedSetWireTestEngine(t, conn)
			writeRawFirewallState(t, e, FirewallState{Blocked: tc.prior})
			var err error
			if tc.automatic {
				_, err = e.BlockIPOutcome(tc.ip, tc.reason, tc.ttl)
			} else {
				err = e.BlockIPForce(tc.ip, tc.reason, tc.ttl)
			}
			if err != nil {
				t.Fatalf("block: %v", err)
			}
			row, ok := blockedStateEntry(readRawFirewallState(t, e), tc.ip)
			if !ok || row.Automatic != tc.want {
				t.Fatalf("row = %+v, %t; want automatic %t", row, ok, tc.want)
			}
		})
	}
}

// The mark is optional on the wire, so state files of older builds read as
// unmarked and older builds ignore it.
func TestBlockedEntryAutomaticIsOmittedUnlessSet(t *testing.T) {
	plain, err := json.Marshal(BlockedEntry{IP: "192.0.2.64"})
	if err != nil || strings.Contains(string(plain), "automatic") {
		t.Fatalf("unmarked row encodes as %s, %v", plain, err)
	}
	marked, err := json.Marshal(BlockedEntry{IP: "192.0.2.64", Automatic: true})
	if err != nil || !strings.Contains(string(marked), `"automatic":true`) {
		t.Fatalf("marked row encodes as %s, %v", marked, err)
	}
	var old BlockedEntry
	if err := json.Unmarshal([]byte(`{"ip":"192.0.2.64","reason":"auto-block: old","blocked_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z"}`), &old); err != nil || old.Automatic {
		t.Fatalf("an older row decodes as %+v, %v", old, err)
	}
}

// Two snapshots of a row differ when only the mark does.
func TestSameBlockedEntryComparesTheMark(t *testing.T) {
	row := BlockedEntry{IP: "192.0.2.65", ExpiresAt: time.Unix(1_700_000_000, 0)}
	marked := row
	marked.Automatic = true
	if SameBlockedEntry(row, marked) {
		t.Fatal("rows that differ only in the automatic mark compare equal")
	}
}

// An operator block never removes a block an admission action owns (spec
// 5.6: a manual addition deletes no occupant admission accounts for). At
// the temporary limit it counts only the other rows: while admission rows
// make up the difference it is added above the limit, and otherwise it
// evicts the soonest other row even when an admission row ends sooner. An
// admission row the block replaces, with no element left, is no occupant.
func TestOperatorBlockNeverEvictsAnAdmissionRow(t *testing.T) {
	now := time.Now()
	owned := BlockedEntry{IP: "192.0.2.70", Reason: "CSM auto-block: owner", Source: SourceAutoResponse, BlockedAt: now, ExpiresAt: now.Add(time.Minute), ActionID: "act_00000000000000000000000000000070"}
	other := BlockedEntry{IP: "192.0.2.71", Reason: "operator tempban", BlockedAt: now, ExpiresAt: now.Add(time.Hour)}
	for _, tc := range []struct {
		name   string
		limit  int
		rows   []BlockedEntry
		live   int
		target string
		evicts bool
	}{
		{"admission rows make room above the limit", 2, []BlockedEntry{owned, other}, 2, "203.0.113.70", false},
		{"only admission rows fill the limit", 1, []BlockedEntry{owned}, 1, "203.0.113.70", false},
		{"other rows at the limit lose their soonest", 1, []BlockedEntry{owned, other}, 2, "203.0.113.70", true},
		{"a replaced admission row without its element is no occupant", 1, []BlockedEntry{owned, other}, 1, owned.IP, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := newBlockedSetWireTestEngine(t, conn)
			e.cfg.DenyTempIPLimit = tc.limit
			e.liveBlockCounts = func() (int, int, error) { return 0, tc.live, nil }
			e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
				var elements []nftables.SetElement
				for _, row := range tc.rows {
					if tc.target == owned.IP && row.IP == owned.IP {
						continue
					}
					if set == e.setBlocked {
						elements = append(elements, nftables.SetElement{Key: net.ParseIP(row.IP).To4(), Timeout: time.Hour, Expires: time.Hour})
					}
				}
				return elements, nil
			}
			writeRawFirewallState(t, e, FirewallState{Blocked: tc.rows})
			if err := e.BlockIPForce(tc.target, "operator", time.Hour); err != nil {
				t.Fatalf("operator block: %v", err)
			}
			state := readRawFirewallState(t, e)
			if row, ok := blockedStateEntry(state, owned.IP); tc.target != owned.IP && (!ok || !SameBlockedEntry(row, owned)) {
				t.Fatalf("the admission row changed: %+v", state.Blocked)
			}
			if row, ok := blockedStateEntry(state, tc.target); !ok || row.Reason != "operator" || row.ActionID != "" {
				t.Fatalf("the operator block is missing: %+v", state.Blocked)
			}
			_, had := blockedStateEntry(FirewallState{Blocked: tc.rows}, other.IP)
			_, kept := blockedStateEntry(state, other.IP)
			_, replaces := blockedStateEntry(FirewallState{Blocked: tc.rows}, tc.target)
			// A replaced row's element is deleted and added again in the same batch.
			deletes := delSetElemCount(t, *captured, "blocked_ips")
			if kept != (had && !tc.evicts) || deletes != map[bool]int{true: 1}[tc.evicts]+map[bool]int{true: 1}[replaces] {
				t.Fatalf("evicts=%v: other row kept %v, %d kernel deletes", tc.evicts, kept, deletes)
			}
		})
	}
}

// Ownership discounts must describe the same population as occupancy.
func TestOperatorOccupancyUsesOnePopulation(t *testing.T) {
	for _, mode := range []string{"live", "fallback"} {
		for _, kind := range []string{"missing", "expired", "unverified absent", "unverified live", "expired unverified live", "permanent", "alias", "replaced", "wall rollback"} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				f := newBatchFixture(t, FirewallState{})
				at := f.at
				row := BlockedEntry{IP: "203.0.113.90", ActionID: "act_owned", ExpiresAt: at.Add(time.Hour)}
				other := BlockedEntry{IP: "203.0.113.91", ExpiresAt: at.Add(2 * time.Hour)}
				state := FirewallState{Blocked: []BlockedEntry{row, other}}
				f.live[other.IP] = time.Hour
				want := 1
				exclude := ""
				switch kind {
				case "missing":
				case "expired":
					state.Blocked[0].ExpiresAt = at
				case "unverified absent":
					state.Blocked[0].Unverified = true
				case "unverified live":
					state.Blocked[0].Unverified = true
					f.live[row.IP] = time.Hour
				case "expired unverified live":
					state.Blocked[0].Unverified = true
					state.Blocked[0].ExpiresAt = at
					f.live[row.IP] = time.Hour
					if mode == "live" {
						want = 2
					}
				case "permanent":
					state.Blocked[0].ExpiresAt = time.Time{}
					f.live[row.IP] = time.Hour
				case "alias":
					alias := row
					alias.IP = "::ffff:203.0.113.90"
					alias.ActionID = ""
					state.Blocked = append(state.Blocked, alias)
					f.live[row.IP] = time.Hour
					want = 2
				case "replaced":
					exclude = other.IP
					want = 0
				case "wall rollback":
					f.e.leaseClock = func() (time.Time, time.Time) { return at.Add(2 * time.Hour), at.Add(2 * time.Hour) }
					leaseNow(f.e)
					f.e.leaseClock = func() (time.Time, time.Time) { return at.Add(-time.Hour), at.Add(2 * time.Hour) }
					f.live[row.IP] = time.Hour
					// Expired intent no longer discounts a still-live kernel element.
					if mode == "live" {
						want = 2
					} else {
						want = 0
					}
				}
				if mode == "fallback" {
					f.e.liveBlockedDump = nil
					f.e.conn = nil
				}
				f.e.mu.Lock()
				got := f.e.operatorTempCountLocked(state, exclude)
				f.e.mu.Unlock()
				if got != want {
					t.Fatalf("non-admission occupants = %d, want %d", got, want)
				}
			})
		}
	}
}

// Normalization and an unrelated upsert preserve the whole selected row;
// operator undo restores its lifetime but creates no automatic provenance.
func TestLegacyStampSurvivesStateAndUndo(t *testing.T) {
	conn, _ := nftConnReturningErrsThenOK(t)
	e := newBlockedSetWireTestEngine(t, conn)
	now := time.Now()
	row := BlockedEntry{IP: "192.0.2.90", Reason: "auto-block: test", BlockedAt: now, ExpiresAt: now.Add(time.Hour), Automatic: true}
	alias := row
	alias.IP = "::ffff:192.0.2.90"
	alias.ExpiresAt = now.Add(-time.Hour)
	alias.Automatic = false
	state := FirewallState{Blocked: []BlockedEntry{alias, row}}
	normalizeFirewallStateIPs(&state)
	if len(state.Blocked) != 1 || !SameBlockedEntry(state.Blocked[0], row) {
		t.Fatalf("normalization lost the selected row: %+v", state)
	}
	upsertBlockedEntryInState(&state, BlockedEntry{IP: "203.0.113.90"})
	copied := copyFirewallState(state)
	if got, ok := blockedStateEntry(copied, row.IP); !ok || !SameBlockedEntry(got, row) {
		t.Fatalf("upsert/copy lost provenance: %+v", copied)
	}
	writeRawFirewallState(t, e, state)
	before, after, err := e.BlockIPForUndo(row.IP, "operator", 2*time.Hour)
	if err != nil || before == nil || after == nil || !before.Automatic || after.Automatic {
		t.Fatalf("undo snapshots: %+v %+v %v", before, after, err)
	}
	if err = e.RestoreBlockIfUnchanged(row.IP, after, before); err != nil {
		t.Fatal(err)
	}
	restored, ok := blockedStateEntry(readRawFirewallState(t, e), row.IP)
	if !ok || restored.Automatic || !restored.ExpiresAt.Equal(row.ExpiresAt) {
		t.Fatalf("undo restored ownership or changed expiry: %+v", restored)
	}
}

func TestOperatorAllowanceNeedsAdmissionRows(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.cfg.DenyTempIPLimit = 1
	f.e.liveBlockCounts = func() (int, int, error) { return 0, 1, nil }
	// No admission rows: retain the pre-existing limit decision even if a
	// subsequent dump would be empty. This allowance is not a legacy fix.
	f.e.mu.Lock()
	_, _, _, _, err := f.e.blockIPTargetFromStates("203.0.113.90", time.Hour, false, FirewallState{}, FirewallState{})
	f.e.mu.Unlock()
	if err == nil {
		t.Fatal("operator allowance activated without admission rows")
	}
}
