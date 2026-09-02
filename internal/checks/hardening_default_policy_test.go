package checks

import (
	"os"
	"strings"
	"testing"
)

// The default-deny audit accepted any "policy drop" in the nft ruleset. A
// Docker host has one on its FORWARD chain, so an INPUT chain left at
// policy accept passed the audit and the MySQL exposure check treated the
// wildcard listener as firewalled.
const dockerStyleRuleset = `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
	}
	chain FORWARD {
		type filter hook forward priority filter; policy drop;
	}
}`

func TestFirewallDefaultPolicyIgnoresForwardChainDrop(t *testing.T) {
	r := checkFirewallDefaultPolicy(true, dockerStyleRuleset, false, "")
	if r.Status != "fail" {
		t.Fatalf("status = %q, want fail: %s", r.Status, r.Message)
	}
}

func TestFirewallDefaultPolicyAcceptsInputHookDrop(t *testing.T) {
	rules := "table inet filter {\n\tchain in {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}"
	if r := checkFirewallDefaultPolicy(true, rules, false, ""); r.Status != "pass" {
		t.Fatalf("status = %q, want pass: %s", r.Status, r.Message)
	}
	multiLine := "table inet filter {\n\tchain in {\n\t\ttype filter hook input priority 0;\n\t\tpolicy reject;\n\t}\n}"
	if r := checkFirewallDefaultPolicy(true, multiLine, false, ""); r.Status != "pass" {
		t.Fatalf("multi-line status = %q, want pass: %s", r.Status, r.Message)
	}
}

func TestCheckMySQLExposedWildcardForwardDropDoesNotCount(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" {
				return []byte("  sl  local_address rem_address   st tx_queue rx_queue\n   0: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	results := checkMySQLExposed(true, dockerStyleRuleset, false, "")
	if len(results) == 0 {
		t.Fatal("expected a result")
	}
	if strings.Contains(results[0].Message, "firewall blocks") {
		t.Fatalf("FORWARD-chain drop counted as blocking 3306: %q", results[0].Message)
	}
}
