package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// nft output with a static (no-timeout) IPv6 set whose members begin with hex
// letters. The structural-hash filter must treat every "elements = { ... }"
// member as dynamic regardless of leading character; otherwise a normal CSM
// block/unblock of an a-f-prefixed IPv6 self-reports "modified outside of CSM".
const v6FirewallBase = `table inet csm {
	chain input { }
	chain output { }
	set blocked_ips { type ipv4_addr; }
	set allowed_ips { type ipv4_addr; }
	set infra_ips { type ipv4_addr; }
	set allowed_ips6 {
		type ipv6_addr
		flags interval
		elements = { 2a01:db8::/32,
			     fe80::1234 }
	}
}`

func TestCheckFirewallV6ElementChangeDoesNotFlipHash(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte(v6FirewallBase), nil
		},
	})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true}

	_ = CheckFirewall(context.Background(), cfg, st) // baseline

	// Only the dynamic IPv6 membership changes (an a-f-prefixed address added).
	mutated := strings.Replace(v6FirewallBase, "fe80::1234 }", "fe80::1234,\n\t\t\t     abcd::9999 }", 1)
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte(mutated), nil
		},
	})
	findings := CheckFirewall(context.Background(), cfg, st)
	for _, f := range findings {
		if strings.Contains(f.Message, "modified outside of CSM") {
			t.Fatalf("IPv6 set membership change must not flip the structural hash: %+v", f)
		}
	}
}

// Guard: a genuine structural change (new chain) is still detected even when
// IPv6 element blocks are present, so the fix does not over-skip real edits.
func TestCheckFirewallV6StructuralChangeStillDetected(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte(v6FirewallBase), nil
		},
	})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true}

	_ = CheckFirewall(context.Background(), cfg, st) // baseline

	mutated := strings.Replace(v6FirewallBase, "chain output { }", "chain output { }\n\tchain forward { }", 1)
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte(mutated), nil
		},
	})
	findings := CheckFirewall(context.Background(), cfg, st)
	found := false
	for _, f := range findings {
		if strings.Contains(f.Message, "modified outside of CSM") {
			found = true
		}
	}
	if !found {
		t.Fatal("a real structural change (new chain) must still be detected with IPv6 elements present")
	}
}
