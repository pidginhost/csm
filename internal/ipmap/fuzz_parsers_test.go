package ipmap

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, raw := range []string{
		"198.51.100.7", "198.51.100.7/24", "2001:db8::7", "2001:db8::7/32",
		"::ffff:198.51.100.7", "::ffff:198.51.100.7/120", "::ffff:198.51.100.7/80",
		"2001:db8::7%eth0", "2001:db8::7%x\n203.0.113.7 CSM_IP_DROP:0.8", "", "invalid",
	} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		p, ok := parse(raw)
		if !ok {
			return
		}
		if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			t.Fatalf("noncanonical prefix: %s", p)
		}
		if again, ok := parse(p.String()); !ok || again != p {
			t.Fatalf("prefix did not round-trip: %s", p)
		}
		m := Build(Sources{Entries: map[string][]string{Drop.Name: {raw}}})
		content, _ := m.Render()
		if m.Len() > 1 || bytes.Count(content, []byte{'\n'}) != m.Len()+1 {
			t.Fatalf("input injected map lines: %q", content)
		}
		if m.Len() == 1 {
			if got := m.Weight(p.Addr()); got != Drop.Tenths() {
				t.Fatalf("listed prefix %s has weight %d", p, got)
			}
			blocked := Build(Sources{Entries: map[string][]string{Drop.Name: {raw}}, Never: []netip.Addr{p.Addr()}})
			if blocked.Len() != 0 {
				t.Fatal("excluded address remains listed")
			}
		}
		if strings.Count(string(content), Canary.Name) != 1 || m.Weight(canaryAddr) != 0 {
			t.Fatal("canary is not reserved")
		}
	})
}
