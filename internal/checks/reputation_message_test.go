package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Recordings keep an ip_reputation finding's message but not its structured
// source address. Whatever every producer writes must give that address back.
func TestReputationMessageSourceIPMatchesProducers(t *testing.T) {
	var produced []alert.Finding
	for _, ip := range []string{"203.0.113.10", "2001:db8::10"} {
		appendReputationFinding(&produced, ip, "SMTP", "AbuseIPDB", 87, "brute force")
	}

	statePath := t.TempDir()
	restoreThreatDB := SetGlobalThreatDBForTest(statePath)
	t.Cleanup(restoreThreatDB)
	GetThreatDB().badIPs["203.0.113.11"] = "test-feed"
	forceCPanelPlatform(t)
	withMockOS(t, writeMockLog(t, reputationWHMAccessLog,
		"203.0.113.11 - - [17/Jul/2026:10:00:00 +0000] \"GET /whm HTTP/1.1\" 200 0 \"-\" \"-\"\n"))
	threat := 0
	for _, f := range CheckIPReputation(context.Background(), &config.Config{StatePath: statePath}, nil) {
		if f.Check == "ip_reputation" && f.SourceIP == "203.0.113.11" {
			produced = append(produced, f)
			threat++
		}
	}
	if threat != 1 || len(produced) != 3 {
		t.Fatalf("producers gave %d findings (%d from the threat database)", len(produced), threat)
	}
	for _, f := range produced {
		if f.SourceIP == "" {
			t.Fatalf("fixture finding without a source: %+v", f)
		}
		if got := ReputationMessageSourceIP(f); got != f.SourceIP {
			t.Errorf("message %q gives %q, source is %q", f.Message, got, f.SourceIP)
		}
		// The live fallback cannot, which is why replay needs this.
		f.SourceIP = ""
		if ExtractIPFromFinding(f) != "" {
			t.Errorf("live fallback already reads %q; the helper is not needed", f.Message)
		}
	}
	for _, f := range []alert.Finding{
		{Check: "smtp_bruteforce", Message: "Known malicious IP accessing server: 203.0.113.12 (source: x)"},
		{Check: "ip_reputation", Message: "Known malicious IP accessing server: not-an-address (source: x)"},
		{Check: "ip_reputation", Message: "Known malicious IP accessing server: 203.0.113.12"},
		{Check: "ip_reputation", Message: "something else: 203.0.113.12 (source: x)"},
		{Check: "ip_reputation", Message: "Known malicious IP accessing server: 127.0.0.1 (source: x)"},
	} {
		if got := ReputationMessageSourceIP(f); got != "" {
			t.Errorf("%s %q gave %q", f.Check, f.Message, got)
		}
	}
}
