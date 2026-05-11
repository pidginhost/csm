package challenge

import (
	"sync"
	"testing"
	"time"
)

func TestNewPortGateLoopbackReturnsNil(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "::1", "localhost", "", "   "} {
		gate, err := NewPortGate(PortGateConfig{
			ListenAddr: addr,
			ListenPort: 8439,
		})
		if err != nil {
			t.Fatalf("%q: unexpected err %v", addr, err)
		}
		if gate != nil {
			t.Fatalf("%q: expected nil gate for loopback listener", addr)
		}
	}
}

func TestFamilyForListenAddrPicksRight(t *testing.T) {
	cases := []struct {
		addr   string
		wantV4 bool
		wantV6 bool
	}{
		{"", true, false},
		{"0.0.0.0", true, false},
		{"::", true, true},
		{"203.0.113.5", true, false},
		{"2001:db8::1", false, true},
		{"[2001:db8::1]", false, true},
		{"not-an-ip", true, false},
	}
	for _, c := range cases {
		got := familyForListenAddr(c.addr)
		if got.v4 != c.wantV4 || got.v6 != c.wantV6 {
			t.Errorf("familyForListenAddr(%q) = {v4=%v v6=%v}, want {v4=%v v6=%v}",
				c.addr, got.v4, got.v6, c.wantV4, c.wantV6)
		}
	}
}

// fakeGate records every Allow / Revoke / Close it sees so the IPList
// wiring can be asserted without a real nftables connection.
type fakeGate struct {
	mu       sync.Mutex
	allows   []allowCall
	revokes  []string
	closeErr error
	closed   bool
}

type allowCall struct {
	ip  string
	ttl time.Duration
}

func (f *fakeGate) Allow(ip string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allows = append(f.allows, allowCall{ip: ip, ttl: ttl})
	return nil
}

func (f *fakeGate) Revoke(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes = append(f.revokes, ip)
	return nil
}

func (f *fakeGate) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.closeErr
}

func (f *fakeGate) snapshot() (allows []allowCall, revokes []string, closed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	allows = append([]allowCall(nil), f.allows...)
	revokes = append([]string(nil), f.revokes...)
	closed = f.closed
	return
}

func TestIPListWiresGateAddRemove(t *testing.T) {
	dir := t.TempDir()
	l := NewIPListWithMapPath(dir, dir+"/challenge_ips.txt")
	g := &fakeGate{}
	l.SetPortGate(g)

	l.Add("203.0.113.5", "test", 7*time.Minute)
	l.Add("198.51.100.42", "test2", 5*time.Minute)
	l.Remove("203.0.113.5")

	allows, revokes, _ := g.snapshot()
	if len(allows) != 2 {
		t.Fatalf("allows = %d, want 2", len(allows))
	}
	if allows[0].ip != "203.0.113.5" || allows[0].ttl != 7*time.Minute {
		t.Errorf("first allow = %+v", allows[0])
	}
	if allows[1].ip != "198.51.100.42" || allows[1].ttl != 5*time.Minute {
		t.Errorf("second allow = %+v", allows[1])
	}
	if len(revokes) != 1 || revokes[0] != "203.0.113.5" {
		t.Errorf("revokes = %v, want [203.0.113.5]", revokes)
	}
}

func TestIPListNoGateIsNoOp(t *testing.T) {
	dir := t.TempDir()
	l := NewIPListWithMapPath(dir, dir+"/challenge_ips.txt")
	// no SetPortGate call; Add/Remove must not panic.
	l.Add("203.0.113.7", "noop", 1*time.Minute)
	l.Remove("203.0.113.7")
}
