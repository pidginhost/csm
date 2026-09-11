package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// CorrelationInputOf has to answer with the same rules CorrelateFindings
// applies internally, or anything built on it (calibration, diagnostics)
// explains a result the daemon did not produce.
func TestCorrelationInputOfMatchesCorrelationRules(t *testing.T) {
	withAccountHomeRoots(t, "/home")

	for _, tc := range []struct {
		name         string
		finding      alert.Finding
		wantAccount  string
		wantEligible bool
	}{
		{
			name:        "security event attributed by tenant",
			finding:     alert.Finding{Check: "webshell", Severity: alert.Critical, TenantID: "alice"},
			wantAccount: "alice", wantEligible: true,
		},
		{
			name:        "security event attributed by file path",
			finding:     alert.Finding{Check: "wp_core_integrity", Severity: alert.Critical, FilePath: "/home/bob/public_html/wp-load.php"},
			wantAccount: "bob", wantEligible: true,
		},
		{
			name:        "eligible but unattributed",
			finding:     alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "no account here"},
			wantAccount: "", wantEligible: true,
		},
		{
			name:        "ignored check is not an input however well attributed",
			finding:     alert.Finding{Check: "account_scan", Severity: alert.Critical, TenantID: "alice"},
			wantAccount: "alice", wantEligible: false,
		},
		{
			name:        "derived aggregate is never an input",
			finding:     alert.Finding{Check: "coordinated_attack", Severity: alert.Critical, TenantID: "alice"},
			wantAccount: "alice", wantEligible: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account, eligible := CorrelationInputOf(tc.finding)
			if account != tc.wantAccount {
				t.Errorf("account = %q, want %q", account, tc.wantAccount)
			}
			if eligible != tc.wantEligible {
				t.Errorf("eligible = %v, want %v", eligible, tc.wantEligible)
			}
		})
	}
}

// Whatever CorrelateFindings counts, CorrelationInputOf must agree with. This
// keeps the two from drifting when the classification changes.
func TestCorrelationInputOfAgreesWithCorrelateFindings(t *testing.T) {
	withAccountHomeRoots(t, "/home")

	findings := []alert.Finding{
		{Check: "webshell", Severity: alert.Critical, TenantID: "one"},
		{Check: "webshell", Severity: alert.Critical, TenantID: "two"},
		{Check: "phishing_php", Severity: alert.Critical, TenantID: "three"},
		{Check: "account_scan", Severity: alert.Critical, TenantID: "four"},
	}
	accounts := make(map[string]bool)
	for _, f := range findings {
		account, eligible := CorrelationInputOf(f)
		if eligible && account != "" && f.Severity == alert.Critical {
			accounts[account] = true
		}
	}
	if len(accounts) != 3 {
		t.Fatalf("CorrelationInputOf counted %d accounts, want 3", len(accounts))
	}
	res := CorrelateFindings(findings)
	var raised bool
	for _, d := range res.Derived {
		if d.Check == "coordinated_attack" {
			raised = true
		}
	}
	if !raised {
		t.Fatal("CorrelateFindings did not raise coordinated_attack for the same three accounts")
	}
}
