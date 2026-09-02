package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// Blocking or challenging a Cloudflare edge address hits every visitor
// behind that edge. The central-intel firebreak and the realtime infra
// test both have to recognise the ranges the checks package tracks; the
// realtime copy had drifted and lacked the Cloudflare branch.
func TestCentralFirebreakProtectsCloudflareEdges(t *testing.T) {
	checks.SetCloudflareNets([]string{"173.245.48.0/20"})
	t.Cleanup(func() { checks.SetCloudflareNets(nil) })

	d := &Daemon{cfg: &config.Config{}}
	protected := d.centralFirebreak()
	if !protected("173.245.48.10") {
		t.Fatal("central firebreak let a Cloudflare edge through")
	}
	// Documentation ranges (RFC 5737) are protected by design, so the
	// unprotected control must be an ordinary routable address.
	if protected("37.187.100.1") {
		t.Fatal("central firebreak protected a plain public address")
	}
}

// reportEveryAddress lifts the abuse-report firebreak for a test whose
// fixtures use RFC 5737 documentation addresses, which the firebreak
// protects by design.
func reportEveryAddress(t *testing.T) {
	t.Helper()
	orig := abuseReportFirebreak
	abuseReportFirebreak = func(*Daemon) func(string) bool { return func(string) bool { return false } }
	t.Cleanup(func() { abuseReportFirebreak = orig })
}

// The abuse-report gate uses the central firebreak, so a Cloudflare edge
// seen in a Critical brute-force finding is never exported as an attacker.
func TestAbuseReportGateUsesFirebreak(t *testing.T) {
	checks.SetCloudflareNets([]string{"173.245.48.0/20"})
	t.Cleanup(func() { checks.SetCloudflareNets(nil) })
	d := &Daemon{cfg: &config.Config{}}
	if !abuseReportFirebreak(d)("173.245.48.10") {
		t.Fatal("abuse-report firebreak let a Cloudflare edge through")
	}
}

func TestDaemonInfraTestCoversCloudflare(t *testing.T) {
	checks.SetCloudflareNets([]string{"173.245.48.0/20"})
	t.Cleanup(func() { checks.SetCloudflareNets(nil) })

	if !isInfraIPDaemon("173.245.48.10", nil) {
		t.Fatal("realtime infra test does not recognise Cloudflare edges")
	}
	if !isInfraIPDaemon("198.51.100.7", []string{"198.51.100.0/24"}) || isInfraIPDaemon("203.0.113.9", nil) {
		t.Fatal("infra CIDR handling changed")
	}
}
