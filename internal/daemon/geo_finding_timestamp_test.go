package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// email_suspicious_geo findings reached the alert pipeline with a zero
// Timestamp. Eight landed in one day on a production host, all dated
// 0001-01-01 in the audit log and in every view built from it.
func TestSuspiciousGeoFindingStampsTimestamp(t *testing.T) {
	withGeoCountries(t, map[string]string{
		"203.0.113.5":  "RO",
		"198.51.100.7": "CN",
	})
	cfg := &config.Config{}

	withGlobalStore(t, func(_ *store.DB) {
		for i := 0; i < geoMinLoginCount+1; i++ {
			parseDovecotLogLine(dovecotLoginLine("carol@example.com", "203.0.113.5"), cfg)
		}

		before := time.Now()
		findings := parseDovecotLogLine(dovecotLoginLine("carol@example.com", "198.51.100.7"), cfg)
		after := time.Now()

		if len(findings) != 1 || findings[0].Check != "email_suspicious_geo" {
			t.Fatalf("findings = %+v, want one email_suspicious_geo", findings)
		}
		got := findings[0]
		if got.Timestamp.IsZero() {
			t.Fatal("Timestamp is zero; the finding would be dated 0001-01-01 everywhere it is shown")
		}
		if got.Timestamp.Before(before) || got.Timestamp.After(after) {
			t.Errorf("Timestamp = %v, want a time within [%v, %v]", got.Timestamp, before, after)
		}
	})
}
