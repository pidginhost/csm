package ipmap

import (
	"net/netip"
	"strings"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestBuildStrongestSourceWins(t *testing.T) {
	m := Build(Sources{Entries: map[string][]string{
		BlocklistDE.Name: {"203.0.113.10", "203.0.113.11"},
		Blocked.Name:     {"203.0.113.10"},
		CINS.Name:        {"203.0.113.11"},
	}})
	if got := m.Weight(addr("203.0.113.10")); got != Blocked.Tenths() {
		t.Errorf("203.0.113.10 = %d, want BLOCKED %d", got, Blocked.Tenths())
	}
	if got := m.Weight(addr("203.0.113.11")); got != BlocklistDE.Tenths() {
		t.Errorf("tie between equal symbols must pick rule order: %d", got)
	}
	if got := m.Weight(addr("203.0.113.12")); got != 0 {
		t.Errorf("unlisted = %d", got)
	}
}

// rspamd uses the most specific entry, so an address inside a listed
// network carries the stronger of the two and nothing stacks (spec 6.1).
func TestBuildAddressInsideNetwork(t *testing.T) {
	m := Build(Sources{Entries: map[string][]string{
		Drop.Name:        {"198.51.100.0/24"},
		Spam.Name:        {"198.51.100.7"},
		BlocklistDE.Name: {"203.0.113.0/24"},
		Blocked.Name:     {"203.0.113.9"},
	}})
	content, _ := m.Render()
	text := string(content)
	if strings.Contains(text, "\n198.51.100.7 ") {
		t.Error("a weaker address inside a DROP network got its own line")
	}
	if !strings.Contains(text, "\n203.0.113.9 CSM_IP_BLOCKED:0.6\n") {
		t.Error("a stronger address inside a weaker network lost its line")
	}
	if m.Weight(addr("198.51.100.7")) != Drop.Tenths() || m.Weight(addr("203.0.113.9")) != Blocked.Tenths() || m.Weight(addr("203.0.113.8")) != BlocklistDE.Tenths() {
		t.Error("weights do not follow the most specific entry")
	}
}

func TestBuildNeverListsExcludedAddresses(t *testing.T) {
	m := Build(Sources{
		Entries: map[string][]string{
			Drop.Name:    {"198.51.100.0/24", "10.0.0.0/8", "fd00::/8"},
			Blocked.Name: {"192.0.2.255", "127.0.0.1", "169.254.1.1", "203.0.113.20", "203.0.113.21", "not-an-ip", "::1", "172.16.0.9"},
			Spam.Name:    {"203.0.113.22"},
		},
		Never: []netip.Addr{addr("203.0.113.21"), addr("198.51.100.200"), addr("203.0.113.22")},
	})
	content, _ := m.Render()
	text := string(content)
	for _, never := range []string{"10.0.0.0/8", "fd00::/8", "127.0.0.1", "169.254.1.1", "203.0.113.21", "203.0.113.22", "not-an-ip", "198.51.100.0/24", "::1", "172.16.0.9"} {
		if strings.Contains(text, never) {
			t.Errorf("map lists excluded %q", never)
		}
	}
	if strings.Count(text, "192.0.2.255 ") != 1 || !strings.HasPrefix(text, "192.0.2.255 CSM_IP_CANARY:0:g") {
		t.Error("the canary address got a data line")
	}
	if !strings.Contains(text, "\n203.0.113.20 CSM_IP_BLOCKED:0.6\n") {
		t.Error("a public address was dropped")
	}
}

// netip accepts any text after an IPv6 zone separator, newlines included;
// a zoned address must never reach the map file as a line of its own.
func TestBuildRefusesZonedAddresses(t *testing.T) {
	m := Build(Sources{Entries: map[string][]string{
		Blocked.Name: {"2001:db8::1%eth0", "2001:db8::2%x\n0.0.0.0/0 CSM_IP_DROP:0.8", "2001:db8::3"},
	}})
	content, _ := m.Render()
	if text := string(content); strings.Contains(text, "%") || strings.Contains(text, "0.0.0.0/0") || m.Len() != 1 {
		t.Fatalf("zoned addresses reached the map:\n%s", text)
	}
}

func TestRenderStartsWithTheCanary(t *testing.T) {
	m := Build(Sources{Entries: map[string][]string{CINS.Name: {"203.0.113.30"}}})
	content, gen := m.Render()
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(gen) != 12 || lines[0] != CanaryAddr+" CSM_IP_CANARY:0:g"+gen || lines[1] != "203.0.113.30 CSM_IP_CINS:0.4" {
		t.Fatalf("gen %q, content:\n%s", gen, content)
	}
	other, gen2 := Build(Sources{Entries: map[string][]string{CINS.Name: {"203.0.113.31"}}}).Render()
	if gen2 == gen || string(other) == string(content) {
		t.Fatal("different data, same generation")
	}
	if _, again := Build(Sources{Entries: map[string][]string{CINS.Name: {"203.0.113.30"}}}).Render(); again != gen {
		t.Fatal("generation is not stable")
	}
}

func TestSymbolsMatchTheSpec(t *testing.T) {
	want := map[string]int{"CSM_IP_DROP": 40, "CSM_IP_BLOCKED": 30, "CSM_IP_MAIL_AUTH": 30, "CSM_IP_SPAM": 30,
		"CSM_IP_BLOCKLISTDE": 20, "CSM_IP_CINS": 20, "CSM_IP_CANARY": 0}
	got := map[string]int{}
	for _, s := range Symbols() {
		got[s.Name] = s.Tenths()
	}
	if len(got) != len(want) {
		t.Fatalf("symbols %v", got)
	}
	for name, tenths := range want {
		if got[name] != tenths {
			t.Errorf("%s = %d tenths, want %d", name, got[name], tenths)
		}
	}
	if Symbols()[len(Symbols())-1] != Canary {
		t.Error("the canary must come last in rule order")
	}
}
