package checks

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// fakeNftWithDropCounter answers like nft: a stateful listing prints counter
// values that grow with traffic, a stateless one (-s) the bare statement.
func fakeNftWithDropCounter(prerouting bool) func(string, ...string) ([]byte, error) {
	packets := 0
	return func(name string, args ...string) ([]byte, error) {
		if name != "nft" {
			return nil, nil
		}
		packets += 7
		counter := fmt.Sprintf("counter packets %d bytes %d", packets, packets*60)
		if slices.Contains(args, "-s") {
			counter = "counter"
		}
		var b strings.Builder
		b.WriteString("table inet csm {\n\tset blocked_ips { type ipv4_addr; }\n\tset allowed_ips { type ipv4_addr; }\n\tset infra_ips { type ipv4_addr; }\n")
		if prerouting {
			b.WriteString("\tchain prerouting {\n\t\ttype filter hook prerouting priority -310; policy accept;\n\t\tmeta nfproto ipv4 meta l4proto tcp @nh,4,4 > 5 " + counter + " drop\n\t}\n")
		}
		b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t}\n}\n")
		return []byte(b.String()), nil
	}
}

func firewallCheckMessages(t *testing.T, st *state.Store, fc *firewall.FirewallConfig) []string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Firewall = fc
	var msgs []string
	for _, f := range CheckFirewall(context.Background(), cfg, st) {
		if f.Check == "firewall" {
			msgs = append(msgs, f.Message)
		}
	}
	return msgs
}

// Without an engine in this process the check compares the live table with
// the stored baseline. Drop counters are traffic, not structure: hashing them
// would report CSM's own rules as an external edit on every run.
func TestCheckFirewallStandaloneIgnoresDropCounters(t *testing.T) {
	withMockCmd(t, &mockCmd{runAllowNonZero: fakeNftWithDropCounter(true)})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fc := &firewall.FirewallConfig{Enabled: true, IPv6: true, DropIPv4Options: true}
	for run := range 3 {
		if msgs := firewallCheckMessages(t, st, fc); len(msgs) != 0 {
			t.Fatalf("run %d: %v", run, msgs)
		}
	}
}

func TestCheckFirewallRequiresIPv4OptionsChainWhenEnabled(t *testing.T) {
	for _, tc := range []struct {
		on, present, missing bool
	}{
		{on: true, present: true},
		{on: true, present: false, missing: true},
		{on: false, present: false},
	} {
		withMockCmd(t, &mockCmd{runAllowNonZero: fakeNftWithDropCounter(tc.present)})
		st, err := state.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		msgs := firewallCheckMessages(t, st, &firewall.FirewallConfig{Enabled: true, IPv6: true, DropIPv4Options: tc.on})
		_ = st.Close()
		got := slices.ContainsFunc(msgs, func(m string) bool { return strings.Contains(m, "chain prerouting") })
		if got != tc.missing {
			t.Errorf("drop_ipv4_options=%t chain present=%t: findings %v", tc.on, tc.present, msgs)
		}
	}
}
