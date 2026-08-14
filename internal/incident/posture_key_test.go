package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A known-vulnerable or outdated plugin is a standing weakness in installed
// software, not evidence that anything happened. Production opened a CRITICAL
// web_account_compromise incident for an account whose only signal was an
// unpatched plugin version.
func TestCorrelatorIgnoresPostureFindings(t *testing.T) {
	for _, check := range []string{"vulnerable_plugins", "outdated_plugins"} {
		t.Run(check, func(t *testing.T) {
			c := newTestCorrelator()
			f := alert.Finding{
				Check:     check,
				Message:   "Known-vulnerable plugin ultimate-member 2.4.1 (CVE-2023-3460) on shop.example.com",
				Severity:  alert.Critical,
				CPUser:    "example",
				Domain:    "shop.example.com",
				Timestamp: time.Unix(1_700_000_000, 0),
			}

			id, created, err := c.OnFinding(f)
			if err != nil {
				t.Fatalf("OnFinding: %v", err)
			}
			if created || id != "" {
				t.Fatalf("%s opened incident id=%q created=%v", check, id, created)
			}
			if c.OpenCount() != 0 || c.PendingCount() != 0 {
				t.Fatalf("%s changed correlator state: open=%d pending=%d", check, c.OpenCount(), c.PendingCount())
			}
		})
	}
}

// A real compromise signal on the same account must still correlate, so the
// exclusion cannot be read as "plugin-related findings are uninteresting".
func TestCorrelatorStillOpensIncidentForCompromiseOnSameAccount(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{
		Check:     "yara_match_scheduled",
		Message:   "YARA rule match [webshell_alfa]: /home/example/public_html/x.php",
		Severity:  alert.Critical,
		CPUser:    "example",
		Timestamp: time.Unix(1_700_000_000, 0),
	}

	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if c.OpenCount()+c.PendingCount() == 0 {
		t.Fatal("a webshell match on the account must still open an incident")
	}
}
