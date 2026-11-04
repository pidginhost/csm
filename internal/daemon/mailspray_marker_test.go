package daemon

import (
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"
)

// markerSprayConfig is testSprayConfig with the default spray block length.
func markerSprayConfig() sprayConfig {
	cfg := testSprayConfig()
	cfg.BlockTTL = 720 * time.Hour
	return cfg
}

// sprayBlock fails ip on fresh mailboxes until it draws a breadth block.
func sprayBlock(t *testing.T, m *mailSpray, ip string) {
	t.Helper()
	for _, mb := range []string{"a@example.com", "b@example.com"} {
		if v := m.Failure(ip, mb, mailboxExists); v != nil {
			wantRule(t, v, sprayRuleBreadth, true)
			return
		}
	}
	t.Fatalf("setup: %s drew no block verdict", ip)
}

// An address already blocked for less than the spray length (an older 24h
// block is not extended) comes back after its evidence aged out. Its first
// failure, even on a mailbox it trusts, blocks it for the spray length.
func TestMailSprayMarkerReblocksAfterShortBlock(t *testing.T) {
	m, clock := newTestSpray(markerSprayConfig())
	const ip = "192.0.2.7"
	sprayBlock(t, m, ip)
	clock.advance(8 * 24 * time.Hour)
	ageTrust(t, m, clock, ip, "t@example.com")
	v := m.Failure(ip, "t@example.com", mailboxExists)
	wantRule(t, v, sprayRuleRepeat, true)
	if v.BlockTTL != 720*time.Hour {
		t.Fatalf("BlockTTL = %v, want 720h", v.BlockTTL)
	}
}

func TestMailSprayMarkerExpires(t *testing.T) {
	cfg := markerSprayConfig()
	m, clock := newTestSpray(cfg)
	const ip = "192.0.2.7"
	sprayBlock(t, m, ip)
	if _, ok := m.blocks[ip]; !ok {
		t.Fatal("setup: no marker")
	}
	clock.advance(cfg.BlockTTL + cfg.Window + time.Minute)
	wantNoVerdict(t, m.Failure(ip, "t@example.com", mailboxExists))
	m.Purge()
	if len(m.blocks)+len(m.blocksByKey) != 0 {
		t.Fatalf("markers after expiry = %v %v, want none", m.blocks, m.blocksByKey)
	}

	// Turning the component off drops live markers too.
	sprayBlock(t, m, "192.0.2.8")
	off := cfg
	off.Window = 0
	m.SetConfig(off)
	if len(m.blocks)+len(m.blocksByKey) != 0 {
		t.Fatalf("markers with no window = %v %v, want none", m.blocks, m.blocksByKey)
	}
}

func TestMailSprayMarkerOnlyInEnforce(t *testing.T) {
	cfg := markerSprayConfig()
	observe := cfg
	observe.Mode = sprayObserve
	m, clock := newTestSpray(observe)
	const ip = "192.0.2.7"
	m.Failure(ip, "a@example.com", mailboxExists)
	wantRule(t, m.Failure(ip, "b@example.com", mailboxExists), sprayRuleBreadth, true)
	if len(m.blocks) != 0 {
		t.Fatalf("observe mode verdict left markers %v", m.blocks)
	}

	m.SetConfig(cfg)
	clock.advance(cfg.Suppression + time.Minute)
	wantRule(t, m.Failure(ip, "a@example.com", mailboxExists), sprayRuleBreadth, true)
	if _, ok := m.blocks[ip]; !ok {
		t.Fatal("enforce mode block verdict left no marker")
	}

	clock.advance(8 * 24 * time.Hour)
	m.SetConfig(observe)
	wantNoVerdict(t, m.Failure(ip, "c@example.com", mailboxExists))
	m.SetConfig(cfg)
	wantRule(t, m.Failure(ip, "c@example.com", mailboxExists), sprayRuleRepeat, true)
}

func TestMailSprayMarkerSuppressed(t *testing.T) {
	cfg := markerSprayConfig()
	m, clock := newTestSpray(cfg)
	const ip = "192.0.2.7"
	sprayBlock(t, m, ip)
	clock.advance(8 * 24 * time.Hour)
	wantRule(t, m.Failure(ip, "c@example.com", mailboxExists), sprayRuleRepeat, true)
	clock.advance(time.Minute)
	wantNoVerdict(t, m.Failure(ip, "c@example.com", mailboxExists))
	clock.advance(cfg.Suppression)
	wantRule(t, m.Failure(ip, "c@example.com", mailboxExists), sprayRuleRepeat, true)
}

// A repeat block starts a new marker, which outlives the first one.
func TestMailSprayMarkerRefreshed(t *testing.T) {
	cfg := markerSprayConfig()
	m, clock := newTestSpray(cfg)
	const ip = "192.0.2.7"
	sprayBlock(t, m, ip)
	clock.advance(8 * 24 * time.Hour)
	wantRule(t, m.Failure(ip, "c@example.com", mailboxExists), sprayRuleRepeat, true)
	if got, want := m.blocks[ip], clock.Now().Add(cfg.BlockTTL); !got.Equal(want) {
		t.Fatalf("marker end = %v, want %v", got, want)
	}

	// Past the first marker's end plus a window.
	clock.advance(cfg.BlockTTL + cfg.Window - 8*24*time.Hour + time.Hour)
	m.Purge()
	wantRule(t, m.Failure(ip, "c@example.com", mailboxExists), sprayRuleRepeat, true)
}

// Review focus 6: the marker belongs to the blocked address. Its /64
// siblings do not inherit it.
func TestMailSprayMarkerIsPerAddress(t *testing.T) {
	cfg := markerSprayConfig()
	m, clock := newTestSpray(cfg)
	const a, b = "2001:db8:1::a", "2001:db8:1::b"
	sprayBlock(t, m, a)
	if keys := slices.Collect(maps.Keys(m.blocks)); !slices.Equal(keys, []string{a}) {
		t.Fatalf("marker keys = %v, want the address %s", keys, a)
	}
	if got := m.blocksByKey["2001:db8:1::/64"]; len(got) != 1 {
		t.Fatalf("/64 index = %v, want %s", got, a)
	}
	clock.advance(cfg.Window + time.Minute)
	wantRule(t, m.Failure(a, "x@example.com", mailboxExists), sprayRuleRepeat, true)
	wantNoVerdict(t, m.Failure(b, "x@example.com", mailboxExists))
	if _, ok := m.blocks[b]; ok {
		t.Fatalf("sibling %s got a marker", b)
	}
}

// Review focus 7: one /64 cycling its addresses cannot evict the markers
// of other networks.
func TestMailSprayMarkerPerKeyBounded(t *testing.T) {
	m, clock := newTestSpray(markerSprayConfig())
	others := []string{"192.0.2.7", "2001:db8:2::1"}
	for _, ip := range others {
		sprayBlock(t, m, ip)
	}
	want := maps.Clone(m.blocks)
	addrs := make([]string, maxSprayNamesPerIP+1)
	for i := range addrs {
		clock.advance(time.Second)
		addrs[i] = fmt.Sprintf("2001:db8:1::%x", i+1)
		sprayBlock(t, m, addrs[i])
	}
	if n := len(m.blocksByKey["2001:db8:1::/64"]); n != maxSprayNamesPerIP {
		t.Fatalf("/64 markers = %d, want %d", n, maxSprayNamesPerIP)
	}
	if _, ok := m.blocks[addrs[0]]; ok {
		t.Fatalf("the soonest-ending marker of the /64 was kept")
	}
	for _, a := range addrs[1:] {
		if _, ok := m.blocks[a]; !ok {
			t.Fatalf("marker of %s dropped", a)
		}
	}
	for ip, end := range want {
		if got, ok := m.blocks[ip]; !ok || !got.Equal(end) {
			t.Fatalf("marker of %s = %v, %v; want %v untouched", ip, got, ok, end)
		}
	}
	if n := len(m.blocks); n != maxSprayNamesPerIP+len(others) {
		t.Fatalf("markers = %d, want %d", n, maxSprayNamesPerIP+len(others))
	}
}

func TestMailSprayMarkerBounded(t *testing.T) {
	m, clock := newTestSpray(markerSprayConfig())
	now := clock.Now()
	addr := func(i int) string { return fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff) }
	m.mu.Lock()
	for i := range maxSprayMarkers + 1 {
		m.noteBlock(addr(i), now.Add(time.Duration(i)*time.Second))
	}
	m.mu.Unlock()
	n := len(m.blocks)
	if n > maxSprayMarkers || n < maxSprayMarkers*95/100 || n != len(m.blocksByKey) {
		t.Fatalf("markers = %d, index keys = %d, cap %d", n, len(m.blocksByKey), maxSprayMarkers)
	}
	// The soonest-ending went first.
	dropped := maxSprayMarkers + 1 - n
	for i := range maxSprayMarkers + 1 {
		if _, ok := m.blocks[addr(i)]; ok != (i >= dropped) {
			t.Fatalf("marker %d kept = %v, want the %d soonest-ending dropped", i, ok, dropped)
		}
	}
}

// Every spelling of one address shares its marker, verdict cadence and
// trust, kept under the canonical form.
func TestMailSprayCanonicalAddress(t *testing.T) {
	m, clock := newTestSpray(markerSprayConfig())
	sprayBlock(t, m, "2001:DB8:1::A")
	sprayBlock(t, m, "::ffff:192.0.2.7")
	if keys := slices.Sorted(maps.Keys(m.blocks)); !slices.Equal(keys, []string{"192.0.2.7", "2001:db8:1::a"}) {
		t.Fatalf("marker keys = %v, want canonical addresses", keys)
	}
	if got := m.blocksByKey["2001:db8:1::/64"]; len(got) != 1 {
		t.Fatalf("/64 index = %v, want the canonical address", got)
	}
	// The same address spelt otherwise is still suppressed.
	wantNoVerdict(t, m.Failure("2001:db8:1:0::a", "c@example.com", mailboxExists))

	ageTrust(t, m, clock, "2001:DB8:2::B", "t@example.com")
	if _, ok := m.trust[sprayTrustKey{"2001:db8:2::b", "t@example.com"}]; !ok || !m.TrustedAll("2001:db8:2:0::b", []string{"t@example.com"}) {
		t.Fatalf("trust not kept under the canonical address: %v", m.trustByIP)
	}

	clock.advance(8 * 24 * time.Hour)
	wantRule(t, m.Failure("2001:db8:1::a", "c@example.com", mailboxExists), sprayRuleRepeat, true)
	wantRule(t, m.Failure("192.0.2.7", "c@example.com", mailboxExists), sprayRuleRepeat, true)
}
