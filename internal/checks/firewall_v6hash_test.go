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

func TestNFTRulesetStructureHashIgnoresElementLayouts(t *testing.T) {
	layouts := []string{
		"\t\telements = { 2a01:db8::/32, fe80::1234 }",
		"\t\telements = { 2a01:db8::/32,\n\t\t\t     fe80::1234 }",
		"\t\telements = { 2a01:db8::/32,\n\t\t\t     fe80::1234\n\t\t}",
		"\t\telements = { }",
	}

	want := nftRulesetStructureHash([]byte(nftRulesetWithElements(layouts[0])))
	for _, layout := range layouts[1:] {
		got := nftRulesetStructureHash([]byte(nftRulesetWithElements(layout)))
		if got != want {
			t.Fatalf("element layout changed structural hash:\n%s", layout)
		}
	}
}

func TestNFTRulesetStructureHashIgnoresQuotedBraceInElementComment(t *testing.T) {
	base := nftRulesetWithElements("\t\telements = { 2a01:db8::1 comment \"brace } in comment\",\n\t\t\t     fe80::1234 }")
	mutated := nftRulesetWithElements("\t\telements = { 2a01:db8::1 comment \"brace } in comment\",\n\t\t\t     fe80::1234,\n\t\t\t     abcd::9999 }")

	if nftRulesetStructureHash([]byte(base)) != nftRulesetStructureHash([]byte(mutated)) {
		t.Fatal("a quoted brace in an element comment must not end the skipped element block")
	}
}

func TestNFTRulesetStructureHashIgnoresElementMemberForms(t *testing.T) {
	tests := map[string]struct {
		setBody string
		base    string
		mutated string
	}{
		"ipv4": {
			setBody: "\t\ttype ipv4_addr",
			base:    "\t\telements = { 192.0.2.10, 198.51.100.20 }",
			mutated: "\t\telements = { 192.0.2.10, 203.0.113.30 }",
		},
		"ipv6": {
			setBody: "\t\ttype ipv6_addr",
			base:    "\t\telements = { 2001:db8::10, fe80::1234 }",
			mutated: "\t\telements = { 2001:db8::10, abcd::9999 }",
		},
		"interval": {
			setBody: "\t\ttype ipv4_addr\n\t\tflags interval",
			base:    "\t\telements = { 192.0.2.0/24, 198.51.100.10-198.51.100.20 }",
			mutated: "\t\telements = { 192.0.2.0/24, 203.0.113.10-203.0.113.20 }",
		},
		"concatenated": {
			setBody: "\t\ttype ipv4_addr . inet_service",
			base:    "\t\telements = { 192.0.2.10 . 25, 198.51.100.20 . 443 }",
			mutated: "\t\telements = { 192.0.2.10 . 25, 203.0.113.30 . 587 }",
		},
	}

	for name, tc := range tests {
		base := nftRulesetWithSetBody(tc.setBody, tc.base)
		mutated := nftRulesetWithSetBody(tc.setBody, tc.mutated)
		if nftRulesetStructureHash([]byte(base)) != nftRulesetStructureHash([]byte(mutated)) {
			t.Fatalf("%s set element change must not change structural hash", name)
		}
	}
}

func TestNFTRulesetStructureHashDetectsStructuralEditsWithElements(t *testing.T) {
	base := nftRulesetWithElements("\t\telements = { 2a01:db8::/32,\n\t\t\t     fe80::1234 }")
	baseHash := nftRulesetStructureHash([]byte(base))

	tests := map[string]string{
		"chain": strings.Replace(base, "\tchain output { }", "\tchain output { }\n\tchain forward { }", 1),
		"rule":  strings.Replace(base, "\tchain input { }", "\tchain input {\n\t\tip saddr @blocked_ips drop\n\t}", 1),
		"set":   strings.Replace(base, "\tset infra_ips { type ipv4_addr; }", "\tset extra_ips { type ipv4_addr; }\n\tset infra_ips { type ipv4_addr; }", 1),
		"type":  strings.Replace(base, "\t\ttype ipv6_addr", "\t\ttype inet_service", 1),
		"flags": strings.Replace(base, "\t\tflags interval", "\t\tflags timeout", 1),
	}

	for name, ruleset := range tests {
		if nftRulesetStructureHash([]byte(ruleset)) == baseHash {
			t.Fatalf("%s structural edit did not change hash", name)
		}
	}
}

func nftRulesetWithElements(elements string) string {
	return nftRulesetWithSetBody("\t\ttype ipv6_addr\n\t\tflags interval", elements)
}

func nftRulesetWithSetBody(setBody, elements string) string {
	return `table inet csm {
	chain input { }
	chain output { }
	set blocked_ips { type ipv4_addr; }
	set allowed_ips { type ipv4_addr; }
	set infra_ips { type ipv4_addr; }
	set allowed_ips6 {
` + setBody + `
` + elements + `
	}
}`
}
