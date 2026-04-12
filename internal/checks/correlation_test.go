package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestCorrelateFindings_CoordinatedAttack(t *testing.T) {
	// 3+ accounts with critical security events should trigger coordinated attack.
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/alice/public_html/shell.php"},
		{Severity: alert.Critical, Check: "obfuscated_php", Message: "Found in /home/bob/public_html/evil.php"},
		{Severity: alert.Critical, Check: "backdoor_binary", Message: "Found in /home/carol/public_html/backdoor"},
	}
	extra := CorrelateFindings(findings)
	found := false
	for _, f := range extra {
		if f.Check == "coordinated_attack" {
			found = true
		}
	}
	if !found {
		t.Error("3 affected accounts should trigger coordinated_attack")
	}
}

func TestCorrelateFindings_NoCorrelation(t *testing.T) {
	// Single account shouldn't trigger.
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/alice/public_html/a.php"},
		{Severity: alert.Critical, Check: "obfuscated_php", Message: "Found in /home/alice/public_html/b.php"},
	}
	extra := CorrelateFindings(findings)
	for _, f := range extra {
		if f.Check == "coordinated_attack" {
			t.Error("single account should not trigger coordinated_attack")
		}
	}
}

func TestCorrelateFindings_CrossAccountMalware(t *testing.T) {
	// Same malware type in 2+ accounts.
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/alice/public_html/wso.php"},
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/bob/public_html/wso.php"},
	}
	extra := CorrelateFindings(findings)
	found := false
	for _, f := range extra {
		if f.Check == "cross_account_malware" {
			found = true
		}
	}
	if !found {
		t.Error("same check in 2 accounts should trigger cross_account_malware")
	}
}

func TestCorrelateFindings_IgnoresNonSecurityEvents(t *testing.T) {
	// Static config checks (not in securityEventChecks) should be ignored.
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "waf_status", Message: "Account: alice"},
		{Severity: alert.Critical, Check: "open_basedir", Message: "Account: bob"},
		{Severity: alert.Critical, Check: "some_config", Message: "Account: carol"},
	}
	extra := CorrelateFindings(findings)
	for _, f := range extra {
		if f.Check == "coordinated_attack" {
			t.Error("config checks should not trigger correlation")
		}
	}
}

func TestCorrelateFindings_Empty(t *testing.T) {
	extra := CorrelateFindings(nil)
	if len(extra) != 0 {
		t.Errorf("nil findings should return empty, got %d", len(extra))
	}
}

func TestUniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"a", "b", "a", "c", "b"})
	if len(got) != 3 {
		t.Errorf("got %v, want 3 unique", got)
	}
}

func TestUniqueStringsEmpty(t *testing.T) {
	got := uniqueStrings(nil)
	if len(got) != 0 {
		t.Errorf("nil should return empty, got %v", got)
	}
}
