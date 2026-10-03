package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A spray that carries its subnet only in CIDRs classifies, keys and
// correlates exactly like one with the subnet in SourceIP, so incidents opened
// before the upgrade keep matching new findings.
func TestSprayCIDRKeysLikeTheSourceIPSubnet(t *testing.T) {
	for _, check := range []string{"mail_subnet_spray", "smtp_subnet_spray"} {
		legacy := alert.Finding{Check: check, Severity: alert.Critical, SourceIP: "203.0.113.0/24", Mailbox: "alice@example.com"}
		structured := alert.Finding{Check: check, Severity: alert.Critical, CIDRs: []string{"203.0.113.0/24"}, Mailbox: "alice@example.com"}
		if ClassifyKind(structured) != ClassifyKind(legacy) || KeyFor(structured) != KeyFor(legacy) {
			t.Errorf("%s: structured kind %v key %+v, legacy kind %v key %+v", check,
				ClassifyKind(structured), KeyFor(structured), ClassifyKind(legacy), KeyFor(legacy))
		}
	}
	crawl := alert.Finding{Check: "http_asn_crawl", Severity: alert.Critical, CIDRs: []string{"192.0.2.0/24"}, Domain: "shop.example"}
	if k := KeyFor(crawl); k.RemoteIP != "" {
		t.Errorf("crawl subnets became an incident key: %+v", k)
	}
}

func TestSprayCIDRCorrelatesOnTheSubnet(t *testing.T) {
	var asked []string
	c := NewCorrelator(CorrelatorConfig{IsWhitelisted: func(ip string) bool {
		asked = append(asked, ip)
		return ip == "198.51.100.0/24"
	}})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	id, _, err := c.OnFinding(alert.Finding{Check: "mail_subnet_spray", Severity: alert.Critical, CIDRs: []string{"203.0.113.0/24"}, Message: "spray", Timestamp: now})
	if err != nil {
		t.Fatal(err)
	}
	inc, ok := c.Get(id)
	if !ok || inc.CorrelationKey == nil || inc.CorrelationKey.RemoteIP != "203.0.113.0/24" || len(inc.Timeline) != 1 || inc.Timeline[0].RemoteIP != "203.0.113.0/24" {
		t.Fatalf("incident %+v (found %v), want one keyed and timed on the subnet", inc, ok)
	}
	if id, _, _ := c.OnFinding(alert.Finding{Check: "smtp_subnet_spray", Severity: alert.Critical, CIDRs: []string{"198.51.100.0/24"}, Message: "spray", Timestamp: now}); id != "" {
		t.Fatalf("whitelisted subnet opened incident %q", id)
	}
	if len(asked) != 2 || asked[0] != "203.0.113.0/24" || asked[1] != "198.51.100.0/24" {
		t.Fatalf("whitelist asked about %v, want both subnets", asked)
	}
}
