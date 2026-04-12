package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// --- parseDovecotLoginFields ------------------------------------------

func TestParseDovecotLoginFieldsStandard(t *testing.T) {
	line := `Apr 12 10:00:00 host dovecot: imap-login: Login: user=<alice@example.com>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1`
	user, ip := parseDovecotLoginFields(line)
	if user != "alice@example.com" {
		t.Errorf("user = %q", user)
	}
	if ip != "203.0.113.5" {
		t.Errorf("ip = %q", ip)
	}
}

func TestParseDovecotLoginFieldsNoUser(t *testing.T) {
	user, ip := parseDovecotLoginFields("no user field")
	if user != "" || ip != "" {
		t.Errorf("got (%q, %q)", user, ip)
	}
}

func TestParseDovecotLoginFieldsNoRIP(t *testing.T) {
	line := `dovecot: imap-login: Login: user=<alice@example.com>, method=PLAIN`
	user, ip := parseDovecotLoginFields(line)
	if user != "" || ip != "" {
		t.Errorf("no rip should return empty: (%q, %q)", user, ip)
	}
}

// --- parseDovecotLogLine ----------------------------------------------

func TestParseDovecotLogLineNonLogin(t *testing.T) {
	cfg := &config.Config{}
	if got := parseDovecotLogLine("just some random log line", cfg); got != nil {
		t.Errorf("non-login should return nil, got %v", got)
	}
}

func TestParseDovecotLogLineNoDovecot(t *testing.T) {
	cfg := &config.Config{}
	if got := parseDovecotLogLine("Login: user=<a@b.com> without dovecot prefix", cfg); got != nil {
		t.Errorf("no dovecot prefix should return nil, got %v", got)
	}
}

func TestParseDovecotLogLinePrivateIP(t *testing.T) {
	cfg := &config.Config{}
	line := `dovecot: imap-login: Login: user=<alice@example.com>, rip=192.168.1.1`
	if got := parseDovecotLogLine(line, cfg); got != nil {
		t.Errorf("private IP should return nil, got %v", got)
	}
}

func TestParseDovecotLogLineInfraIP(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"203.0.113.5"}}
	line := `dovecot: imap-login: Login: user=<alice@example.com>, rip=203.0.113.5`
	if got := parseDovecotLogLine(line, cfg); got != nil {
		t.Errorf("infra IP should return nil, got %v", got)
	}
}

// --- isPrivateOrLoopback (daemon version) -----------------------------

func TestDaemonIsPrivateOrLoopback(t *testing.T) {
	if !isPrivateOrLoopback("127.0.0.1") {
		t.Error("loopback should be private")
	}
	if !isPrivateOrLoopback("10.0.0.1") {
		t.Error("10.x should be private")
	}
	if !isPrivateOrLoopback("172.16.0.1") {
		t.Error("172.16.x should be private")
	}
	if !isPrivateOrLoopback("192.168.1.1") {
		t.Error("192.168.x should be private")
	}
	if isPrivateOrLoopback("203.0.113.5") {
		t.Error("public IP should not be private")
	}
	if !isPrivateOrLoopback("invalid") {
		t.Error("invalid IP treated as private (skip)")
	}
}

// --- pruneOldCountries ------------------------------------------------

func TestPruneOldCountriesKeepsRecent(t *testing.T) {
	now := int64(1000000)
	countries := map[string]int64{
		"US": now - 100,    // recent
		"CN": now - 999999, // old
	}
	got := pruneOldCountries(countries, now, 500000)
	if _, ok := got["US"]; !ok {
		t.Error("recent country should be kept")
	}
	if _, ok := got["CN"]; ok {
		t.Error("old country should be pruned")
	}
}
