//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

type batchFixture struct {
	e       *Engine
	at      time.Time
	live    map[string]time.Duration // address -> kernel timeout, 0 = permanent
	expires map[string]time.Duration // address -> time left, when not its timeout
	err     error                    // dump failure
	sends   int                      // kernel batches sent
	reply   func([]netlink.Message) ([]netlink.Message, error)
	onFlush func() // what an acknowledged batch leaves in the kernel
}

func newBatchFixture(t *testing.T, state FirewallState) *batchFixture {
	t.Helper()
	dir := t.TempDir()
	writeEngineStateFile(t, dir, state)
	f := &batchFixture{at: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC), live: map[string]time.Duration{}, expires: map[string]time.Duration{}}
	table := &nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}
	f.e = &Engine{
		statePath:        dir,
		cfg:              &FirewallConfig{IPv6: true, InfraIPs: []string{"198.51.100.0/28"}},
		setBlocked:       &nftables.Set{Table: table, Name: "blocked_ips", KeyType: nftables.TypeIPAddr, HasTimeout: true},
		setBlocked6:      &nftables.Set{Table: table, Name: "blocked_ips6", KeyType: nftables.TypeIP6Addr, HasTimeout: true},
		localAddrsLookup: func() ([]string, error) { return []string{"192.0.2.50"}, nil },
		softAllowFn:      func(ip string) bool { return ip == "203.0.113.32" },
	}
	f.e.expiryClock = func() time.Time { return f.at }
	f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
		if f.err != nil {
			return nil, f.err
		}
		var out []nftables.SetElement
		for ip, timeout := range f.live {
			parsed := net.ParseIP(ip)
			key := []byte(parsed.To4())
			if key == nil {
				key = parsed.To16()
			}
			if (len(key) == net.IPv4len) != (set == f.e.setBlocked) {
				continue
			}
			left, ok := f.expires[ip]
			if !ok {
				left = timeout
			}
			out = append(out, nftables.SetElement{Key: key, Timeout: timeout, Expires: left})
		}
		return out, nil
	}
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		f.sends++
		if f.reply != nil {
			return f.reply(req)
		}
		if f.onFlush != nil {
			f.onFlush()
		}
		var acks []netlink.Message
		for _, msg := range req {
			if msg.Header.Flags&netlink.Acknowledge != 0 {
				acks = append(acks, netlink.Message{Header: netlink.Header{Length: 4, Type: netlink.Error, Sequence: msg.Header.Sequence, PID: msg.Header.PID}, Data: []byte{0, 0, 0, 0}})
			}
		}
		return acks, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	f.e.conn = conn
	return f
}

func (f *batchFixture) member(action, ip string) BlockMember {
	return BlockMember{Action: action, IP: ip, Reason: "lane general", ExpiresAt: f.at.Add(time.Hour)}
}

func TestCheckBlockBatchRefusesOnlyInvalidMembers(t *testing.T) {
	f := newBatchFixture(t, FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.40", Reason: "operator"},
			{IP: "203.0.113.42", ActionID: "act_earlier", Unverified: true, ExpiresAt: time.Date(2026, 3, 4, 6, 0, 0, 0, time.UTC)},
		},
		Allowed:     []AllowedEntry{{IP: "203.0.113.30", Reason: "operator"}},
		PortAllowed: []PortAllowEntry{{IP: "203.0.113.31", Port: 443, Proto: "tcp"}},
	})
	f.live["203.0.113.41"] = time.Hour

	m := func(action, ip string, edit func(*BlockMember)) BlockMember {
		member := f.member(action, ip)
		if edit != nil {
			edit(&member)
		}
		return member
	}
	cases := []struct {
		member BlockMember
		want   BlockRefusal
	}{
		{m("act_v4", "203.0.113.20", nil), ""},
		{m("act bad", "203.0.113.21", nil), BlockRefusedInvalid},
		{m("", "203.0.113.21", nil), BlockRefusedInvalid},
		{m(strings.Repeat("a", 65), "203.0.113.21", nil), BlockRefusedInvalid},
		{m("act_badip", "203.0.113.999", nil), BlockRefusedInvalid},
		{m("act_upper", "2001:DB8::21", nil), BlockRefusedInvalid},
		{m("act_mapped", "::ffff:203.0.113.22", nil), BlockRefusedInvalid},
		{m("act_newline", "203.0.113.23", func(b *BlockMember) { b.Reason = "a\nb" }), BlockRefusedInvalid},
		{m("act_utf8", "203.0.113.23", func(b *BlockMember) { b.Reason = "\xff" }), BlockRefusedInvalid},
		{m("act_long", "203.0.113.23", func(b *BlockMember) { b.Reason = strings.Repeat("r", MaxBlockReasonBytes+1) }), BlockRefusedInvalid},
		{m("act_permanent", "203.0.113.23", func(b *BlockMember) { b.ExpiresAt = time.Time{} }), BlockRefusedInvalid},
		{m("act_expired", "203.0.113.24", func(b *BlockMember) { b.ExpiresAt = f.at.Add(500 * time.Microsecond) }), BlockRefusedExpired},
		{m("act_infra", "198.51.100.1", nil), BlockRefusedProtected},
		{m("act_loop", "127.0.0.1", nil), BlockRefusedProtected},
		{m("act_local", "192.0.2.50", nil), BlockRefusedProtected},
		{m("act_allowed", "203.0.113.30", nil), BlockRefusedAllowed},
		{m("act_port", "203.0.113.31", nil), BlockRefusedAllowed},
		{m("act_bot", "203.0.113.32", nil), BlockRefusedAllowed},
		{m("act_again", "203.0.113.20", nil), BlockRefusedDuplicate},
		{m("act_v4", "203.0.113.25", nil), BlockRefusedDuplicate},
		{m("act_row", "203.0.113.40", nil), BlockRefusedExisting},
		{m("act_kernel", "203.0.113.41", nil), BlockRefusedExisting},
		{m("act_unknown", "203.0.113.42", nil), BlockRefusedExisting},
		{m("act_v6", "2001:db8::20", nil), ""},
		{m("act_after", "203.0.113.21", nil), ""},
	}
	members := make([]BlockMember, len(cases))
	for i, tc := range cases {
		members[i] = tc.member
	}
	got, err := f.e.CheckBlockBatch(members)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range cases {
		if got[i] != tc.want {
			t.Errorf("member %d (%s %s) = %q, want %q", i, tc.member.Action, tc.member.IP, got[i], tc.want)
		}
	}
}

func TestCheckBlockBatchRefusesIPv6WithoutItsSet(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.cfg.IPv6 = false
	f.e.setBlocked6 = nil
	got, err := f.e.CheckBlockBatch([]BlockMember{f.member("act_v6", "2001:db8::20"), f.member("act_v4", "203.0.113.20")})
	if err != nil || got[0] != BlockRefusedUnsupported || got[1] != "" {
		t.Fatalf("CheckBlockBatch = %q, %v; want unsupported then accepted", got, err)
	}
}

func TestCheckBlockBatchSkipsDisabledIPv6WithAStaleSet(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.cfg.IPv6 = false
	f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
		if set == f.e.setBlocked6 {
			t.Fatal("disabled IPv6 reached a stale set")
		}
		return nil, nil
	}
	got, err := f.e.CheckBlockBatch([]BlockMember{f.member("act_v6", "2001:db8::20"), f.member("act_v4", "203.0.113.20")})
	if err != nil || len(got) != 2 || got[0] != BlockRefusedUnsupported || got[1] != "" {
		t.Fatalf("answers %q, %v; disabled IPv6 must refuse alone", got, err)
	}
}

func TestCheckBlockBatchFillsTheTemporarySetInOrder(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.cfg.DenyTempIPLimit = 3
	f.live["203.0.113.50"] = time.Hour
	f.live["203.0.113.51"] = 0 // permanent: takes no temporary slot
	members := []BlockMember{
		f.member("act_one", "203.0.113.20"),
		f.member("act bad", "203.0.113.21"),
		f.member("act_two", "2001:db8::20"),
		f.member("act_three", "203.0.113.22"),
		f.member("act_four", "203.0.113.23"),
	}
	got, err := f.e.CheckBlockBatch(members)
	want := []BlockRefusal{"", BlockRefusedInvalid, "", BlockRefusedFull, BlockRefusedFull}
	if err != nil || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("CheckBlockBatch = %q, %v; want %q", got, err, want)
	}
}

func TestCheckBlockBatchRefusesTheWholeCall(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	tooMany := make([]BlockMember, MaxBlockBatchMembers+1)
	for i := range tooMany {
		tooMany[i] = f.member(fmt.Sprintf("act_%d", i), fmt.Sprintf("203.0.113.%d", i+1))
	}
	if _, err := f.e.CheckBlockBatch(tooMany); err == nil {
		t.Fatal("a batch over the member bound was checked")
	}
	if got, err := f.e.CheckBlockBatch(tooMany[:MaxBlockBatchMembers]); err != nil || len(got) != MaxBlockBatchMembers {
		t.Fatalf("a full batch = %d results, %v", len(got), err)
	}
	if _, err := f.e.CheckBlockBatch(nil); err == nil {
		t.Fatal("an empty batch was checked")
	}

	f.err = errors.New("dump failed")
	if _, err := f.e.CheckBlockBatch(tooMany[:1]); err == nil {
		t.Fatal("a batch was checked without a kernel snapshot")
	}
	f.err = nil

	f.e.setBlocked = nil
	if _, err := f.e.CheckBlockBatch(tooMany[:1]); err == nil {
		t.Fatal("a batch was checked before the ruleset exists")
	}

	durable := newBatchFixture(t, FirewallState{})
	durable.e.lifecycle = &Lifecycle{}
	if _, err := durable.e.CheckBlockBatch(tooMany[:1]); err == nil {
		t.Fatal("a batch was checked against durable state")
	}
}

func TestCheckBlockBatchUsesOneAllowSnapshot(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
			f := newBatchFixture(t, FirewallState{Allowed: []AllowedEntry{
				{IP: "203.0.113.20", ExpiresAt: at.Add(time.Second)},
				{IP: "2001:db8::20", ExpiresAt: at.Add(time.Second)},
			}})
			reads := 0
			f.e.expiryClock = func() time.Time { reads++; return at.Add(time.Duration(reads-1) * time.Hour) }
			f.e.liveBlockedDump = func(*nftables.Set) ([]nftables.SetElement, error) {
				if replace {
					writeEngineStateFile(t, f.e.statePath, FirewallState{})
				}
				return nil, nil
			}
			got, err := f.e.CheckBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20"), f.member("act_v6", "2001:db8::20")})
			if err != nil || reads != 1 || len(got) != 2 || got[0] != BlockRefusedAllowed || got[1] != BlockRefusedAllowed {
				t.Fatalf("answers %q, error %v, clock reads %d; want one allow snapshot", got, err, reads)
			}
		})
	}
}

func TestCheckBlockBatchRejectsUnrepresentableExpiryAlone(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	bad := f.member("act_v4", "203.0.113.20")
	bad.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := f.e.CheckBlockBatch([]BlockMember{bad, f.member("act_v4", "203.0.113.20")})
	if err != nil || len(got) != 2 || got[0] != BlockRefusedInvalid || got[1] != "" {
		t.Fatalf("answers %q, %v; invalid expiry must not poison a valid member", got, err)
	}
}

func TestCheckBlockBatchValidatesTheExpiryInstantYear(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.at = time.Date(9999, 12, 31, 23, 0, 0, 0, time.UTC)
	f.e.expiryClock = func() time.Time { return f.at }
	bad := f.member("act_v4", "203.0.113.20")
	bad.ExpiresAt = bad.ExpiresAt.In(time.FixedZone("example", -60*60))
	good := f.member("act_v4", "203.0.113.20")
	good.ExpiresAt = f.at.Add(30 * time.Minute)
	got, err := f.e.CheckBlockBatch([]BlockMember{bad, good})
	if err != nil || len(got) != 2 || got[0] != BlockRefusedInvalid || got[1] != "" {
		t.Fatalf("answers %q, %v; expiry instant outside JSON years must refuse alone", got, err)
	}
}

func TestCheckBlockBatchIgnoresWrongFamilyKeys(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.cfg.DenyTempIPLimit = 1
	f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
		if set == f.e.setBlocked6 {
			return []nftables.SetElement{{Key: net.ParseIP("203.0.113.20").To16(), Timeout: time.Hour}}, nil
		}
		return nil, nil
	}
	got, err := f.e.CheckBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20")})
	if err != nil || len(got) != 1 || got[0] != "" {
		t.Fatalf("answers %q, %v; wrong-family key must not take a slot or name a target", got, err)
	}
}

func TestCheckBlockBatchVerifiedCallbackRunsOutsideLock(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.softAllowFn = func(string) bool {
		if !f.e.mu.TryLock() {
			t.Fatal("verified callback runs under engine lock")
		}
		f.e.mu.Unlock()
		return false
	}
	if got, err := f.e.CheckBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20")}); err != nil || got[0] != "" {
		t.Fatalf("answers %q, %v", got, err)
	}
}

func TestCheckBlockBatchRefusesStateIntegrityHoldBeforeDump(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	cause := errors.New("state persistence failed")
	f.e.blockBatchStateErr = errors.Join(ErrBlockBatchState, cause)
	f.e.liveBlockedDump = func(*nftables.Set) ([]nftables.SetElement, error) {
		t.Fatal("state integrity hold reached kernel snapshot")
		return nil, nil
	}
	got, err := f.e.CheckBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20")})
	if got != nil || !errors.Is(err, ErrBlockBatchState) || !errors.Is(err, cause) {
		t.Fatalf("answers %q, %v; state-integrity hold must refuse before dump", got, err)
	}
}
