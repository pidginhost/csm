package checks

import (
	"context"
	"errors"
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

type monitoredFirewall struct {
	recordingIPBlocker
	current, applied string
	err              error
}

func (m *monitoredFirewall) RulesetSnapshot() (string, string, error) {
	return m.current, m.applied, m.err
}

func TestCheckFirewallUsesAppliedRulesInsteadOfConfigHash(t *testing.T) {
	previous := getIPBlocker()
	t.Cleanup(func() { SetIPBlocker(previous) })
	monitor := &monitoredFirewall{current: nftRulesetA, applied: nftRulesetA}
	SetIPBlocker(monitor)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := firewallCfg("sha256:aaa")
	runFirewallCheck(t, st, cfg, "")
	// Firewall re-apply does not require a rehash or an update to live config.
	monitor.current, monitor.applied = nftRulesetB, nftRulesetB
	if msgs := runFirewallCheck(t, st, cfg, ""); mentionsExternalEdit(msgs) {
		t.Fatalf("own apply reported as tampering: %v", msgs)
	}
	monitor.current = nftRulesetA
	cfg.Integrity.ConfigHash = "sha256:bbb"
	for range 2 {
		if msgs := runFirewallCheck(t, st, cfg, ""); !mentionsExternalEdit(msgs) {
			t.Fatalf("external edit lost despite trusted baseline: %v", msgs)
		}
	}
	monitor.current = nftRulesetB
	if msgs := runFirewallCheck(t, st, cfg, ""); mentionsExternalEdit(msgs) {
		t.Fatalf("restored rules still reported: %v", msgs)
	}
	monitor.applied = ""
	if msgs := runFirewallCheck(t, st, cfg, ""); !strings.Contains(strings.Join(msgs, " "), "baseline unavailable") {
		t.Fatalf("capture failure hidden: %v", msgs)
	}
	monitor.err = errors.New("nft unavailable")
	if msgs := runFirewallCheck(t, st, cfg, ""); !strings.Contains(strings.Join(msgs, " "), "not found") {
		t.Fatalf("live read failure hidden: %v", msgs)
	}
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

// A changed hash is not proof that CSM applied the rules. A config editor can
// also update this unkeyed digest, and SIGHUP rehashes restart-only edits while
// leaving the running firewall untouched.
func TestCheckFirewallReportsEditDespiteChangedConfigHash(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	runFirewallCheck(t, st, firewallCfg("sha256:aaa"), nftRulesetA)

	msgs := runFirewallCheck(t, st, firewallCfg("sha256:bbb"), nftRulesetB)
	if !mentionsExternalEdit(msgs) {
		t.Errorf("config hash change concealed an external ruleset edit: %v", msgs)
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
