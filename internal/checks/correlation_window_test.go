package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func criticalAt(account, check string, at time.Time) alert.Finding {
	return alert.Finding{
		Severity:  alert.Critical,
		Check:     check,
		Message:   "finding for " + account,
		TenantID:  account,
		Timestamp: at,
	}
}

func raised(res CorrelationResult, check string) bool {
	for _, d := range res.Derived {
		if d.Check == check {
			return true
		}
	}
	return false
}

// A coordinated attack means several accounts were hit around the same time.
// The persisted active set holds months of findings, so without a bound the
// aggregate latches on the first three accounts that ever had a critical and
// never clears. On one recorded host it stayed raised for 76% of a 100-day
// recording, and for 99% of a two-day one.
func TestCorrelateFindingsIgnoresAccountsOutsideTheWindow(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	now := time.Unix(1_770_000_000, 0)

	stale := []alert.Finding{
		criticalAt("one", "webshell", now.Add(-30*24*time.Hour)),
		criticalAt("two", "phishing_php", now.Add(-20*24*time.Hour)),
		criticalAt("three", "webshell", now),
	}
	if raised(CorrelateFindings(stale), "coordinated_attack") {
		t.Fatal("accounts attacked weeks apart raised a coordinated attack")
	}

	together := []alert.Finding{
		criticalAt("one", "webshell", now.Add(-30*time.Minute)),
		criticalAt("two", "phishing_php", now.Add(-10*time.Minute)),
		criticalAt("three", "webshell", now),
	}
	if !raised(CorrelateFindings(together), "coordinated_attack") {
		t.Fatal("three accounts attacked within the window did not correlate")
	}
}

// The same bound applies to the malware aggregate: the same webshell found on
// two accounts months apart is not one campaign.
func TestCorrelateFindingsWindowsCrossAccountMalware(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	now := time.Unix(1_770_000_000, 0)

	apart := []alert.Finding{
		{Severity: alert.High, Check: "webshell", TenantID: "one", Timestamp: now.Add(-30 * 24 * time.Hour)},
		{Severity: alert.High, Check: "webshell", TenantID: "two", Timestamp: now},
	}
	if raised(CorrelateFindings(apart), "cross_account_malware") {
		t.Fatal("the same malware found a month apart raised a cross-account finding")
	}

	together := []alert.Finding{
		{Severity: alert.High, Check: "webshell", TenantID: "one", Timestamp: now.Add(-time.Minute)},
		{Severity: alert.High, Check: "webshell", TenantID: "two", Timestamp: now},
	}
	if !raised(CorrelateFindings(together), "cross_account_malware") {
		t.Fatal("the same malware on two accounts in one window did not correlate")
	}
}

// A batch carries findings stamped moments ago, so the bound is inert there:
// the realtime and scan paths must behave exactly as before.
func TestCorrelateFindingsWindowIsInertWithinOneBatch(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	now := time.Unix(1_770_000_000, 0)

	batch := []alert.Finding{
		criticalAt("one", "webshell", now),
		criticalAt("two", "phishing_php", now.Add(time.Millisecond)),
		criticalAt("three", "wp_core_integrity", now.Add(2*time.Millisecond)),
	}
	if !raised(CorrelateFindings(batch), "coordinated_attack") {
		t.Fatal("a single dispatch batch stopped correlating")
	}
}

// A finding with no timestamp predates the fix that stamps every finding.
// It must keep counting rather than silently dropping out of correlation.
func TestCorrelateFindingsCountsUnstampedFindings(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	now := time.Unix(1_770_000_000, 0)

	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", TenantID: "one"},
		criticalAt("two", "phishing_php", now),
		criticalAt("three", "webshell", now),
	}
	if !raised(CorrelateFindings(findings), "coordinated_attack") {
		t.Fatal("an unstamped finding was dropped from correlation")
	}
}
