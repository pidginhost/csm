package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

const (
	nftRulesetA = `table inet csm {
	set blocked_ips { type ipv4_addr }
	set allowed_ips { type ipv4_addr }
	set infra_ips { type ipv4_addr }
	chain input {
		type filter hook input priority filter; policy drop;
		meta nfproto ipv4 tcp dport 22 accept
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}`
	// Same table with an extra accepted port, i.e. the structural change a
	// config edit produces.
	nftRulesetB = `table inet csm {
	set blocked_ips { type ipv4_addr }
	set allowed_ips { type ipv4_addr }
	set infra_ips { type ipv4_addr }
	chain input {
		type filter hook input priority filter; policy drop;
		meta nfproto ipv4 tcp dport 22 accept
		meta nfproto ipv4 tcp dport 2087 accept
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}`
)

func firewallCfg(configHash string) *config.Config {
	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	cfg.Integrity.ConfigHash = configHash
	return cfg
}

func runFirewallCheck(t *testing.T, st *state.Store, cfg *config.Config, ruleset string) []string {
	t.Helper()
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "nft" {
				return []byte(ruleset), nil
			}
			return nil, nil
		},
	})
	var msgs []string
	for _, f := range CheckFirewall(context.Background(), cfg, st) {
		msgs = append(msgs, f.Message)
	}
	return msgs
}

func mentionsExternalEdit(msgs []string) bool {
	for _, m := range msgs {
		if strings.Contains(m, "modified outside of CSM") {
			return true
		}
	}
	return false
}

// Applying a config change rewrites the ruleset, so the structure hash moves.
// Reporting that as an external edit tells the operator their firewall was
// tampered with every time they legitimately reconfigure CSM, which trains
// them to ignore the one alert that would matter.
func TestCheckFirewallDoesNotReportOwnReconfiguration(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	runFirewallCheck(t, st, firewallCfg("sha256:aaa"), nftRulesetA)

	// Operator edits csm.yaml and rehashes: config hash moves with the ruleset.
	msgs := runFirewallCheck(t, st, firewallCfg("sha256:bbb"), nftRulesetB)
	if mentionsExternalEdit(msgs) {
		t.Errorf("CSM's own reconfiguration reported as external tampering: %v", msgs)
	}
}

// A ruleset that changes while the config did not is the real signal.
func TestCheckFirewallReportsEditWithUnchangedConfig(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	runFirewallCheck(t, st, firewallCfg("sha256:aaa"), nftRulesetA)

	msgs := runFirewallCheck(t, st, firewallCfg("sha256:aaa"), nftRulesetB)
	if !mentionsExternalEdit(msgs) {
		t.Errorf("external ruleset edit not reported: %v", msgs)
	}
}

// An unchanged ruleset is silent whatever the config did.
func TestCheckFirewallSilentWhenNothingChanged(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	runFirewallCheck(t, st, firewallCfg("sha256:aaa"), nftRulesetA)
	if msgs := runFirewallCheck(t, st, firewallCfg("sha256:aaa"), nftRulesetA); mentionsExternalEdit(msgs) {
		t.Errorf("reported tampering with no change at all: %v", msgs)
	}
}
