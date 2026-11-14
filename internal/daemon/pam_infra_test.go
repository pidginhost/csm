package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// --- parseDovecotLogLine with more line types -------------------------

func TestParseDovecotLogLinePublicIP(t *testing.T) {
	// Public IP that isn't infra — exercises past the private/infra checks
	// but still returns nil because getGeoIPDB() is nil.
	cfg := &config.Config{}
	line := `Apr 12 10:00:00 host dovecot: imap-login: Login: user=<alice@example.com>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1`
	findings := parseDovecotLogLine(line, cfg)
	// Without GeoIP DB loaded, returns nil after IP checks pass.
	if len(findings) != 0 {
		t.Errorf("no geoip DB should return nil, got %d", len(findings))
	}
}

// --- isInfraIP (daemon/pam_listener.go) with various inputs ----------

func TestPAMIsInfraIPExact(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"10.0.0.1"}}
	if !isInfraIPDaemon("10.0.0.1", cfg.InfraIPs) {
		t.Error("exact match should return true")
	}
}

func TestPAMIsInfraIPCIDR(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraIPDaemon("10.1.2.3", cfg.InfraIPs) {
		t.Error("CIDR match should return true")
	}
}

func TestPAMIsInfraIPNoMatch(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"10.0.0.1"}}
	if isInfraIPDaemon("203.0.113.5", cfg.InfraIPs) {
		t.Error("non-infra should return false")
	}
}

// --- lookupCPanelUser exercises the function -------------------------

func TestLookupCPanelUserNonexistent(t *testing.T) {
	withUserdomainsPath(t, writeUserdomains(t, "example.com: alice\nexample.org: bob\n"))
	if user := lookupCPanelUser("nonexistent.example.net"); user != "" {
		t.Fatalf("unlisted domain resolved to %q, want empty", user)
	}
	// The same file does resolve a listed domain, whatever its case.
	if user := lookupCPanelUser("EXAMPLE.org"); user != "bob" {
		t.Fatalf("listed domain resolved to %q, want bob", user)
	}
}
