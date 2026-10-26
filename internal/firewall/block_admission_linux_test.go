//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/google/nftables"
)

// The admission snapshot answers each member's local checks as a batch
// check does, but no member takes a temporary slot and no repeat is a
// duplicate: the owner decides which members are ready. Each answer names
// its member.
func TestBlockAdmissionSnapshotChecksWithoutSlots(t *testing.T) {
	f := newBatchFixture(t, FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.40", Reason: "operator"},
			{IP: "203.0.113.43", ActionID: "act_0123456789abcdef0123456789abcdef", ExpiresAt: time.Date(2026, 3, 4, 6, 6, 7, 0, time.UTC)},
		},
		Allowed: []AllowedEntry{{IP: "203.0.113.30", Reason: "operator"}},
	})
	f.e.cfg.DenyTempIPLimit = 1
	f.live["203.0.113.41"] = time.Hour
	f.live["203.0.113.43"] = time.Hour
	members := []BlockMember{
		f.member("act_one", "203.0.113.20"),
		f.member("act_two", "203.0.113.20"),
		f.member("act_three", "2001:db8::20"),
		f.member("act bad", "203.0.113.21"),
		f.member("act_infra", "198.51.100.1"),
		f.member("act_allowed", "203.0.113.30"),
		f.member("act_bot", "203.0.113.32"),
		f.member("act_row", "203.0.113.40"),
		f.member("act_kernel", "203.0.113.41"),
		f.member("act_existing", "203.0.113.43"),
	}
	got, err := f.e.BlockAdmissionSnapshot(members, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []BlockRefusal{"", "", "", BlockRefusedInvalid, BlockRefusedProtected, BlockRefusedAllowed, BlockRefusedAllowed, BlockRefusedPending, BlockRefusedPending, BlockRefusedExisting}
	if len(got.Answers) != len(members) {
		t.Fatalf("%d answers for %d members", len(got.Answers), len(members))
	}
	for i, a := range got.Answers {
		if a.Action != members[i].Action || a.IP != members[i].IP || a.Refusal != want[i] {
			t.Errorf("answer %d = %+v, want %s %s %q", i, a, members[i].Action, members[i].IP, want[i])
		}
	}
	if link := got.Answers[9].Existing; link.ID != "act_0123456789abcdef0123456789abcdef" {
		t.Fatalf("existing block = %+v", link)
	}
	if got.Temporary != 2 || got.Limit != 1 || !got.Full() {
		t.Fatalf("occupancy %d of %d, full %v", got.Temporary, got.Limit, got.Full())
	}
}

// The snapshot names the forecast addresses the sets already hold, as a
// timed element or an untimed one, both address families together.
func TestBlockAdmissionSnapshotCountsShadowOverlap(t *testing.T) {
	f := newBatchFixture(t, FirewallState{
		Blocked: []BlockedEntry{{IP: "203.0.113.52", Reason: "operator"}},
	})
	f.live["203.0.113.50"] = time.Hour
	f.live["203.0.113.51"] = 0
	f.live["203.0.113.52"] = 0
	f.live["2001:db8::50"] = time.Hour
	f.live["203.0.113.60"] = time.Hour
	got, err := f.e.BlockAdmissionSnapshot(nil, []string{"203.0.113.50", "203.0.113.51", "203.0.113.52", "2001:db8::50", "203.0.113.53", "2001:db8::53"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Temporary != 3 || !maps.Equal(got.ShadowHeld, map[string]bool{"203.0.113.50": true, "203.0.113.51": true, "203.0.113.52": true, "2001:db8::50": true}) || len(got.Answers) != 0 {
		t.Fatalf("snapshot = %+v", got)
	}
}

// Only an address element counts as coverage. A forecast address inside a
// real permanent subnet block is not held, so the forecast still models it
// as temporary demand; a permanent subnet takes no temporary slot.
func TestBlockAdmissionSnapshotIgnoresSubnetCoverage(t *testing.T) {
	f := newBatchFixture(t, FirewallState{
		BlockedNet: []SubnetEntry{{CIDR: "203.0.113.0/24", Reason: "operator"}, {CIDR: "2001:db8::/64", Reason: "operator"}},
	})
	got, err := f.e.BlockAdmissionSnapshot(nil, []string{"203.0.113.70", "2001:db8::70"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Temporary != 0 || got.Unclaimed != 0 || len(got.ShadowHeld) != 0 {
		t.Fatalf("snapshot = %+v, want no coverage from subnet blocks", got)
	}
}

// The snapshot sorts the set's timed occupants by recorded ownership
// (spec 5.6). Elements of admission rows are admission's own. Elements of
// rows a legacy automatic block marked are known automatic imports. Every
// other timed element, an operator's or one with no row, and two elements
// for each timed subnet row, are unclaimed: admission never evicts them.
// Untimed elements, rows without an element and expired subnet rows take
// no temporary slot. Drain is when the last unclaimed or imported occupant
// ends; admission occupants do not delay it.
func TestBlockAdmissionSnapshotClassesTheTimedOccupants(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.80", Reason: "CSM auto-block: owner", BlockedAt: at, ExpiresAt: at.Add(5 * time.Hour), ActionID: "act_0123456789abcdef0123456789abcd80"},
			{IP: "203.0.113.81", Reason: "auto-block: legacy", BlockedAt: at, ExpiresAt: at.Add(30 * time.Minute), Automatic: true},
			{IP: "2001:db8::81", Reason: "auto-block: legacy", BlockedAt: at, ExpiresAt: at.Add(10 * time.Minute), Automatic: true},
			{IP: "203.0.113.82", Reason: "operator tempban", BlockedAt: at, ExpiresAt: at.Add(2 * time.Hour)},
			{IP: "203.0.113.84", Reason: "operator"},
			{IP: "203.0.113.85", Reason: "auto-block: gone", BlockedAt: at, ExpiresAt: at.Add(4 * time.Hour), Automatic: true},
		},
		BlockedNet: []SubnetEntry{
			{CIDR: "198.51.100.64/26", Reason: "auto-netblock", BlockedAt: at, ExpiresAt: at.Add(time.Hour)},
			{CIDR: "192.0.2.0/24", Reason: "operator"},
			{CIDR: "192.0.2.128/25", Reason: "auto-netblock", BlockedAt: at.Add(-2 * time.Hour), ExpiresAt: at.Add(-time.Hour)},
		},
	}
	f := newBatchFixture(t, state)
	f.live["203.0.113.80"] = 5 * time.Hour
	f.live["203.0.113.81"] = 30 * time.Minute
	f.live["2001:db8::81"] = 10 * time.Minute
	f.live["203.0.113.82"] = 2 * time.Hour
	f.live["203.0.113.83"] = 90 * time.Minute
	f.live["203.0.113.84"] = 0
	got, err := f.e.BlockAdmissionSnapshot(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Temporary != 5 || got.Admission != 1 || got.Imported != 2 || got.Unclaimed != 4 || got.Drain != 2*time.Hour {
		t.Fatalf("occupants = %+v; want 5 timed elements: 1 admission, 2 imported, 4 unclaimed with the subnet, draining in 2h", got)
	}
	// A subnet row that ends last sets the drain.
	state.BlockedNet[0].ExpiresAt = at.Add(3 * time.Hour)
	writeEngineStateFile(t, f.e.statePath, state)
	if got, err = f.e.BlockAdmissionSnapshot(nil, nil); err != nil || got.Unclaimed != 4 || got.Drain != 3*time.Hour {
		t.Fatalf("with a later subnet: %+v, %v; want 4 unclaimed draining in 3h", got, err)
	}
}

// A malformed call refuses before any snapshot: too many members or
// forecast addresses, or an address not in canonical form. A failed
// snapshot refuses the whole call.
func TestBlockAdmissionSnapshotRefusesTheWholeCall(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	tooMany := make([]BlockMember, MaxBlockBatchMembers+1)
	for i := range tooMany {
		tooMany[i] = f.member(fmt.Sprintf("act_%d", i), fmt.Sprintf("203.0.113.%d", i))
	}
	shadow := make([]string, MaxShadowBlocks+1)
	for i := range shadow {
		shadow[i] = fmt.Sprintf("2001:db8::%x", i+1)
	}
	dumps := 0
	f.e.liveBlockedDump = func(*nftables.Set) ([]nftables.SetElement, error) {
		dumps++
		return nil, nil
	}
	for name, call := range map[string]func() (BlockAdmission, error){
		"members":     func() (BlockAdmission, error) { return f.e.BlockAdmissionSnapshot(tooMany, nil) },
		"shadow":      func() (BlockAdmission, error) { return f.e.BlockAdmissionSnapshot(nil, shadow) },
		"mapped":      func() (BlockAdmission, error) { return f.e.BlockAdmissionSnapshot(nil, []string{"::ffff:203.0.113.5"}) },
		"upper case":  func() (BlockAdmission, error) { return f.e.BlockAdmissionSnapshot(nil, []string{"2001:DB8::5"}) },
		"not an addr": func() (BlockAdmission, error) { return f.e.BlockAdmissionSnapshot(nil, []string{"203.0.113.0/24"}) },
		"repeated": func() (BlockAdmission, error) {
			return f.e.BlockAdmissionSnapshot(nil, []string{"203.0.113.5", "203.0.113.5"})
		},
	} {
		if got, err := call(); err == nil || got.Answers != nil {
			t.Errorf("%s: %+v, %v; want a refusal", name, got, err)
		}
	}
	if dumps != 0 {
		t.Fatalf("a refused call read the kernel %d times", dumps)
	}
	if got, err := f.e.BlockAdmissionSnapshot(nil, shadow[:MaxShadowBlocks]); err != nil || len(got.ShadowHeld) != 0 {
		t.Fatalf("the full forecast bound = %+v, %v", got, err)
	}
	cause := errors.New("dump failed")
	f.e.liveBlockedDump = func(*nftables.Set) ([]nftables.SetElement, error) { return nil, cause }
	if _, err := f.e.BlockAdmissionSnapshot([]BlockMember{f.member("act_one", "203.0.113.20")}, nil); !errors.Is(err, cause) {
		t.Fatalf("failed snapshot = %v", err)
	}
}

// The verified-crawler callback can do remote work: it runs outside the
// engine lock.
func TestBlockAdmissionSnapshotVerifiedCallbackRunsOutsideLock(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	calls := 0
	f.e.softAllowFn = func(string) bool {
		calls++
		if !f.e.mu.TryLock() {
			t.Fatal("verified callback runs under engine lock")
		}
		f.e.mu.Unlock()
		return false
	}
	got, err := f.e.BlockAdmissionSnapshot([]BlockMember{f.member("act_one", "203.0.113.20")}, nil)
	if err != nil || len(got.Answers) != 1 || got.Answers[0].Refusal != "" || calls != 1 {
		t.Fatalf("snapshot = %+v, %v, %d calls", got, err, calls)
	}
}

func TestBlockAdmissionSnapshotUsesUnmergedOwnership(t *testing.T) {
	for _, kind := range []string{"unverified import", "unverified admission", "mixed alias", "different actions", "permanent intent", "no element"} {
		t.Run(kind, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			row := BlockedEntry{IP: "203.0.113.90", Automatic: true, ExpiresAt: f.at.Add(time.Hour)}
			state := FirewallState{Blocked: []BlockedEntry{row}}
			f.live[row.IP] = time.Hour
			wantA, wantI, wantU, wantT := 0, 0, 1, 1
			switch kind {
			case "unverified import":
				state.Blocked[0].Unverified = true
			case "unverified admission":
				state.Blocked[0].Unverified = true
				state.Blocked[0].ActionID = "act_one"
				wantA, wantU = 1, 0
			case "mixed alias":
				alias := row
				alias.IP = "::ffff:203.0.113.90"
				alias.Automatic = false
				alias.ExpiresAt = f.at.Add(time.Minute)
				state.Blocked = append(state.Blocked, alias)
			case "different actions":
				state.Blocked[0].ActionID = "act_one"
				alias := row
				alias.IP = "::ffff:203.0.113.90"
				alias.ActionID = "act_two"
				alias.ExpiresAt = f.at.Add(time.Minute)
				state.Blocked = append(state.Blocked, alias)
			case "permanent intent":
				state.Blocked[0].ExpiresAt = time.Time{}
				wantU, wantT = 0, 0
			case "no element":
				delete(f.live, row.IP)
				wantU, wantT = 0, 0
			}
			for pass := 0; pass < 2; pass++ {
				if len(state.Blocked) == 2 {
					state.Blocked[0], state.Blocked[1] = state.Blocked[1], state.Blocked[0]
				}
				writeEngineStateFile(t, f.e.statePath, state)
				got, err := f.e.BlockAdmissionSnapshot(nil, nil)
				if err != nil || got.Admission != wantA || got.Imported != wantI || got.Unclaimed != wantU || got.Temporary != wantT {
					t.Fatalf("occupants: %+v %v", got, err)
				}
			}
		})
	}
}

// Subnet expiry uses the wall clock even when the address lease clock is ahead.
func TestBlockAdmissionSnapshotSubnetClock(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	wall := f.at
	f.e.expiryClock = func() time.Time { return wall }
	f.e.leaseClock = func() (time.Time, time.Time) { return f.at.Add(3 * time.Hour), f.at }
	state := FirewallState{BlockedNet: []SubnetEntry{{CIDR: "203.0.113.0/24", ExpiresAt: f.at.Add(time.Hour)}}}
	writeEngineStateFile(t, f.e.statePath, state)
	got, err := f.e.BlockAdmissionSnapshot(nil, nil)
	if err != nil || got.Unclaimed != 2 || got.Drain != time.Hour {
		t.Fatalf("subnet used lease clock: %+v %v", got, err)
	}
	dump := f.e.liveBlockedDump
	f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) { wall = f.at.Add(time.Hour); return dump(set) }
	got, err = f.e.BlockAdmissionSnapshot(nil, nil)
	if err != nil || got.Unclaimed != 0 || got.Drain != 0 {
		t.Fatalf("subnet expired during dump: %+v %v", got, err)
	}
}

// A positive timeout without a remaining expiry cannot promise a drain horizon.
func TestBlockAdmissionSnapshotUnknownDrain(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.live["203.0.113.90"] = time.Hour
	f.expires["203.0.113.90"] = 0
	f.live["203.0.113.91"] = 2 * time.Hour
	state := FirewallState{BlockedNet: []SubnetEntry{{CIDR: "192.0.2.0/24", ExpiresAt: f.at.Add(3 * time.Hour)}}}
	writeEngineStateFile(t, f.e.statePath, state)
	got, err := f.e.BlockAdmissionSnapshot(nil, nil)
	if err != nil || got.Unclaimed != 4 || got.Drain != -time.Second {
		t.Fatalf("missing expiry advertised a horizon: %+v %v", got, err)
	}
}

// Ended verified aliases are not live ownership; uncertain aliases still are.
// Admission identity takes precedence over the legacy stamp.
func TestBlockAdmissionSnapshotAliasLifetimes(t *testing.T) {
	for _, kind := range []string{"expired alias", "expired unverified alias", "same action different stamp", "same action different verification", "permanent alias"} {
		t.Run(kind, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			row := BlockedEntry{IP: "203.0.113.90", ActionID: "act_owned", ExpiresAt: f.at.Add(time.Hour)}
			alias := row
			alias.IP = "::ffff:203.0.113.90"
			wantA, wantU, wantT := 1, 0, 1
			switch kind {
			case "expired alias", "expired unverified alias":
				alias.ActionID, alias.ExpiresAt = "", f.at
				if kind == "expired unverified alias" {
					alias.Unverified, wantA, wantU = true, 0, 1
				}
			case "same action different stamp":
				alias.Automatic = true
			case "same action different verification":
				alias.Unverified = true
			case "permanent alias":
				alias.ActionID, alias.ExpiresAt, wantA, wantT = "", time.Time{}, 0, 0
			}
			f.live[row.IP] = time.Hour
			rows := []BlockedEntry{row, alias}
			for pass := 0; pass < 2; pass++ {
				rows[0], rows[1] = rows[1], rows[0]
				writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: rows})
				got, err := f.e.BlockAdmissionSnapshot(nil, nil)
				if err != nil || got.Admission != wantA || got.Imported != 0 || got.Unclaimed != wantU || got.Temporary != wantT {
					t.Fatalf("alias %s: %+v %v", kind, got, err)
				}
			}
		})
	}
}

func TestBlockAdmissionSnapshotFamilyBoundaries(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		f := newBatchFixture(t, FirewallState{})
		f.live["203.0.113.90"] = time.Hour
		f.live["2001:db8::90"] = time.Hour
		if disabled {
			f.e.cfg.IPv6, f.e.setBlocked6 = false, nil
		}
		cause := errors.New("second family unavailable")
		dump, calls := f.e.liveBlockedDump, 0
		f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
			calls++
			if calls == 2 {
				return nil, cause
			}
			return dump(set)
		}
		got, err := f.e.BlockAdmissionSnapshot(nil, nil)
		if disabled {
			if err != nil || calls != 1 || got.Unclaimed != 1 || got.Temporary != 1 {
				t.Fatalf("IPv4-only: %+v %v calls=%d", got, err, calls)
			}
		} else if !errors.Is(err, cause) || calls != 2 || got.Temporary != 0 || got.Admission != 0 || got.Imported != 0 || got.Unclaimed != 0 || got.Drain != 0 || len(got.ShadowHeld) != 0 {
			t.Fatalf("partial snapshot published: %+v %v calls=%d", got, err, calls)
		}
	}
}
