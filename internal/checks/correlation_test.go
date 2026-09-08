package checks

import (
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func critical(check, tenant string) alert.Finding {
	return alert.Finding{Severity: alert.Critical, Check: check, TenantID: tenant, Message: check + " on " + tenant}
}

func deepCopyFindings(in []alert.Finding) []alert.Finding {
	out := make([]alert.Finding, len(in))
	for i, f := range in {
		out[i] = f
		out[i].RelayBreakdown = append([]alert.RelayScriptHit(nil), f.RelayBreakdown...)
	}
	return out
}

func derivedChecks(res CorrelationResult) []string {
	var out []string
	for _, f := range res.Derived {
		out = append(out, f.Check)
	}
	return out
}

func TestCorrelateFindingsLegacyTextIdentityStillWorks(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/alice/public_html/shell.php"},
		{Severity: alert.Critical, Check: "obfuscated_php", Message: "Found in /home/bob/public_html/evil.php"},
		{Severity: alert.Critical, Check: "backdoor_binary", Message: "Found in /home/carol/public_html/backdoor"},
	}
	res := CorrelateFindings(findings)
	if got := derivedChecks(res); !reflect.DeepEqual(got, []string{"coordinated_attack"}) {
		t.Fatalf("derived %v", got)
	}
	if len(res.Unattributed) != 0 {
		t.Fatalf("unattributed %v", res.Unattributed)
	}
}

func TestCoordinatedAttackNeedsThreeAttributedAccounts(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	for n, batch := range [][]alert.Finding{
		nil,
		{critical("db_rogue_admin", "alice")},
		{critical("db_rogue_admin", "alice"), critical("db_rogue_admin", "bob"), critical("webshell_realtime", "bob")},
		{critical("db_rogue_admin", "alice"), critical("db_rogue_admin", "alice"), critical("yara_match_scheduled", "alice"), critical("db_rogue_admin", "bob")},
	} {
		if res := CorrelateFindings(batch); len(res.Derived) != 0 || len(res.Unattributed) != 0 {
			t.Fatalf("batch %d produced %+v", n, res)
		}
	}
	three := []alert.Finding{critical("db_rogue_admin", "alice"), critical("joomla_admin_injection", "bob"), critical("suspicious_crontab", "carol"), critical("db_rogue_admin", "alice")}
	res := CorrelateFindings(three)
	if len(res.Derived) != 1 {
		t.Fatalf("derived %+v", res.Derived)
	}
	got := res.Derived[0]
	want := alert.Finding{Severity: alert.Critical, Check: "coordinated_attack",
		Message: "Possible coordinated attack: 3 accounts have critical security events",
		Details: "Affected accounts: alice, bob, carol"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("coordinated finding %+v, want %+v", got, want)
	}
	if len(res.Unattributed) != 0 {
		t.Fatalf("unattributed %v", res.Unattributed)
	}
	// Owner keys are case-sensitive: Alice and alice are two accounts.
	mixed := []alert.Finding{critical("db_rogue_admin", "alice"), critical("db_rogue_admin", "Alice"), critical("db_rogue_admin", "bob")}
	if res := CorrelateFindings(mixed); len(res.Derived) != 1 || res.Derived[0].Details != "Affected accounts: Alice, alice, bob" {
		t.Fatalf("case-sensitive owners: %+v", res.Derived)
	}
}

func TestUnattributedRowsAreCountedNotCorrelated(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	in := []alert.Finding{
		{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: alice)"},
		{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: bob)"},
		{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: carol)"},
		{Severity: alert.High, Check: "db_rogue_admin", Message: "rogue admin (account: dave)"},
		{Severity: alert.Warning, Check: "webshell", Message: "no path"},
		{Severity: alert.Critical, Check: "webshell", Message: "no path either"},
		{Severity: alert.Critical, Check: "coordinated_attack", Message: "old derived"},
		{Severity: alert.Critical, Check: "not_registered", Message: "x"},
		{Severity: alert.Critical, Check: "ip_reputation", Message: "x"},
	}
	res := CorrelateFindings(in)
	if len(res.Derived) != 0 {
		t.Fatalf("derived %+v", res.Derived)
	}
	want := map[string]int{"db_rogue_admin": 3, "webshell": 2}
	if !reflect.DeepEqual(res.Unattributed, want) {
		t.Fatalf("unattributed %v, want %v", res.Unattributed, want)
	}
}

func TestIgnoredDerivedAndUnknownNeverCount(t *testing.T) {
	// Every registered name with three attributed Criticals: eligible
	// classes aggregate, everything else is silent.
	withAccountHomeRoots(t, "/home")
	for _, c := range checkRegistry {
		batch := []alert.Finding{critical(c.Name, "alice"), critical(c.Name, "bob"), critical(c.Name, "carol")}
		res := CorrelateFindings(batch)
		switch c.Correlation {
		case CorrelationSecurityEvent:
			if got := derivedChecks(res); !reflect.DeepEqual(got, []string{"coordinated_attack"}) {
				t.Errorf("%s: derived %v, want coordinated_attack only", c.Name, got)
			}
		case CorrelationMalwareArtifact:
			if got := derivedChecks(res); !reflect.DeepEqual(got, []string{"coordinated_attack", "cross_account_malware"}) {
				t.Errorf("%s: derived %v, want both aggregates", c.Name, got)
			}
		default:
			if len(res.Derived) != 0 || len(res.Unattributed) != 0 {
				t.Errorf("%s (class %d): produced %+v", c.Name, c.Correlation, res)
			}
		}
	}
	unknown := []alert.Finding{critical("not_a_check", "alice"), critical("not_a_check", "bob"), critical("not_a_check", "carol")}
	if res := CorrelateFindings(unknown); len(res.Derived) != 0 || len(res.Unattributed) != 0 {
		t.Fatalf("unknown check produced %+v", res)
	}
	// Derived outputs never feed back, even with tenants attached.
	feedback := []alert.Finding{critical("coordinated_attack", "alice"), critical("cross_account_malware", "bob"), critical("coordinated_attack", "carol")}
	if res := CorrelateFindings(feedback); len(res.Derived) != 0 || len(res.Unattributed) != 0 {
		t.Fatalf("derived input fed back: %+v", res)
	}
}

func TestMalwareArtifactAggregateAtAnySeverity(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	for _, check := range []string{"webshell", "new_webshell_file", "backdoor_binary", "new_executable_in_config"} {
		for _, sev := range []alert.Severity{alert.Warning, alert.High, alert.Critical} {
			in := []alert.Finding{{Severity: sev, Check: check, TenantID: "alice"}, {Severity: sev, Check: check, TenantID: "bob"}}
			res := CorrelateFindings(in)
			want := []alert.Finding{{Severity: alert.Critical, Check: "cross_account_malware",
				Message: "Same malware type (" + check + ") found in 2 accounts", Details: "Accounts: alice, bob"}}
			if !reflect.DeepEqual(res.Derived, want) {
				t.Fatalf("%s at %v: %+v", check, sev, res.Derived)
			}
		}
	}
	for _, check := range []string{"webshell_realtime", "obfuscated_php", "phishing_page", "db_rogue_admin"} {
		in := []alert.Finding{critical(check, "alice"), critical(check, "bob")}
		if res := CorrelateFindings(in); len(res.Derived) != 0 {
			t.Fatalf("%s must not raise cross_account_malware: %+v", check, res.Derived)
		}
	}
	mixed := []alert.Finding{critical("webshell", "alice"), critical("backdoor_binary", "bob")}
	if res := CorrelateFindings(mixed); len(res.Derived) != 0 {
		t.Fatalf("different malware checks must not combine: %+v", res.Derived)
	}
	// An unattributed malware row counts once whatever its severity.
	unattributed := []alert.Finding{{Severity: alert.Critical, Check: "webshell"}, {Severity: alert.Warning, Check: "webshell"}}
	if res := CorrelateFindings(unattributed); res.Unattributed["webshell"] != 2 || len(res.Derived) != 0 {
		t.Fatalf("unattributed malware rows: %+v", res)
	}
	// A non-Critical plain security event neither counts nor is reported.
	if res := CorrelateFindings([]alert.Finding{{Severity: alert.High, Check: "db_rogue_admin"}}); len(res.Unattributed) != 0 {
		t.Fatalf("non-Critical security event reported: %+v", res)
	}
}

func TestDerivedOutputIsDeterministicAndInputUntouched(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	in := []alert.Finding{critical("webshell", "carol"), critical("backdoor_binary", "bob"), critical("webshell", "alice"), critical("backdoor_binary", "alice"), critical("db_rogue_admin", "bob")}
	snapshot := deepCopyFindings(in)
	first := CorrelateFindings(in)
	shuffled := []alert.Finding{in[4], in[3], in[2], in[1], in[0]}
	second := CorrelateFindings(shuffled)
	want := []alert.Finding{
		{Severity: alert.Critical, Check: "coordinated_attack", Message: "Possible coordinated attack: 3 accounts have critical security events", Details: "Affected accounts: alice, bob, carol"},
		{Severity: alert.Critical, Check: "cross_account_malware", Message: "Same malware type (backdoor_binary) found in 2 accounts", Details: "Accounts: alice, bob"},
		{Severity: alert.Critical, Check: "cross_account_malware", Message: "Same malware type (webshell) found in 2 accounts", Details: "Accounts: alice, carol"},
	}
	for i, res := range []CorrelationResult{first, second} {
		if !reflect.DeepEqual(res.Derived, want) {
			t.Fatalf("run %d: derived %+v, want %+v", i, res.Derived, want)
		}
		for _, d := range res.Derived {
			if !d.Timestamp.IsZero() || d.TenantID != "" || d.FilePath != "" || d.SourceIP != "" || d.PID != 0 || d.CPUser != "" || d.ScriptKey != "" || len(d.MsgIDs) != 0 || d.RelayTotal != 0 || len(d.RelayBreakdown) != 0 {
				t.Fatalf("aggregate carries a target or timestamp: %+v", d)
			}
		}
	}
	if !reflect.DeepEqual(in, snapshot) {
		t.Fatal("input mutated")
	}
}

func TestUniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"a", "b", "a", "c", "b"})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("got %v, want [a b c]", got)
	}
	if got := uniqueStrings(nil); len(got) != 0 {
		t.Errorf("nil should return empty, got %v", got)
	}
}

// Attribution does not change identity: two otherwise identical rows that
// differ only in TenantID share a key and a fingerprint, so stamping can
// neither repair nor break deduplication.
func TestTenantIDDoesNotChangeFindingIdentity(t *testing.T) {
	a := alert.Finding{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin x", Details: "d"}
	b := a
	b.TenantID = "alice"
	if a.Key() != b.Key() || a.Fingerprint() != b.Fingerprint() {
		t.Fatal("TenantID must not take part in Key() or Fingerprint()")
	}
}
