//go:build linux

package firewall

import (
	"errors"
	"fmt"
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

// The snapshot counts which forecast addresses the sets already hold, as a
// timed element and as an untimed one, both address families together.
// Addresses the sets do not hold count in neither.
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
	if got.Temporary != 3 || got.ShadowTemporary != 2 || got.ShadowPermanent != 2 || len(got.Answers) != 0 {
		t.Fatalf("snapshot = %+v", got)
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
		shadow[i] = fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&0xff, i&0xff)
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
	if got, err := f.e.BlockAdmissionSnapshot(nil, shadow[:MaxShadowBlocks]); err != nil || got.ShadowTemporary != 0 {
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
