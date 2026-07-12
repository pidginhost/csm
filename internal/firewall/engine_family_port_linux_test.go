//go:build linux

package firewall

import (
	"testing"

	"github.com/google/nftables/expr"
)

func TestFamilyPortRuleStartsWithMatchingGuard(t *testing.T) {
	assertIPv4NFProtoGuardPrefix(t, buildFamilyPortRuleExprs(2, 443, true))
	assertIPv6NFProtoGuardPrefix(t, buildFamilyPortRuleExprs(10, 587, true))
}

func TestFamilyBypassRuleAcceptsOnlyRequestedFamily(t *testing.T) {
	exprs := familyBypassRuleExprs(10)
	assertIPv6NFProtoGuardPrefix(t, exprs)
	verdict, ok := exprs[len(exprs)-1].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictAccept {
		t.Fatalf("family bypass verdict = %#v, want accept", exprs[len(exprs)-1])
	}
}
