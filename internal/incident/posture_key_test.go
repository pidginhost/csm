package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A known-vulnerable or outdated plugin is a standing weakness in installed
// software, not evidence that anything happened.
func TestCorrelatorIgnoresPostureFindings(t *testing.T) {
	for _, check := range []string{"vulnerable_plugins", "outdated_plugins"} {
		t.Run(check, func(t *testing.T) {
			blockCalls := 0
			c := NewCorrelator(CorrelatorConfig{
				OpenThreshold: 1,
				AutoBlock: IncidentAutoBlockConfig{
					Enabled:         true,
					BlockAtSeverity: "critical",
				},
				OnIncidentBlock: func(_, _ string) bool {
					blockCalls++
					return true
				},
			})
			f := alert.Finding{
				Check:     check,
				Message:   "Known-vulnerable plugin ultimate-member 2.4.1 (CVE-2023-3460) on shop.example.com",
				Severity:  alert.Critical,
				CPUser:    "example",
				Domain:    "shop.example.com",
				SourceIP:  "203.0.113.7",
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
			if blockCalls != 0 {
				t.Fatalf("%s triggered %d incident block calls", check, blockCalls)
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

	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created || id == "" {
		t.Fatalf("webshell match did not open an incident: id=%q created=%v", id, created)
	}
	if c.OpenCount() != 1 || c.PendingCount() != 0 {
		t.Fatalf("correlator state after webshell: open=%d pending=%d", c.OpenCount(), c.PendingCount())
	}
	inc, ok := c.Get(id)
	if !ok {
		t.Fatalf("opened incident %q not found", id)
	}
	if inc.Kind != KindWebAccountCompromise {
		t.Fatalf("incident kind = %q, want %q", inc.Kind, KindWebAccountCompromise)
	}
}
