package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Additional handlers_dovecot.go tests targeting edge cases not already
// exercised by dovecot_test.go, handlers_dovecot_test.go, low_coverage_test.go,
// or deeper_coverage_test.go.

// --- parseDovecotLoginFields: RIP terminated by tab character -------------

func TestParseDovecotLoginFieldsRIPTabTerminated(t *testing.T) {
	line := "dovecot: imap-login: Login: user=<a@b.test>, rip=198.51.100.9\tlip=10.0.0.1"
	user, ip := parseDovecotLoginFields(line)
	if user != "a@b.test" {
		t.Errorf("user = %q, want a@b.test", user)
	}
	if ip != "198.51.100.9" {
		t.Errorf("ip = %q, want 198.51.100.9", ip)
	}
}

// --- parseDovecotLoginFields: RIP terminated by newline -------------------

func TestParseDovecotLoginFieldsRIPNewlineTerminated(t *testing.T) {
	line := "dovecot: imap-login: Login: user=<user@test.io>, rip=10.20.30.40\n"
	_, ip := parseDovecotLoginFields(line)
	if ip != "10.20.30.40" {
		t.Errorf("ip = %q, want 10.20.30.40", ip)
	}
}

// --- parseDovecotLoginFields: no closing angle bracket on user -----------

func TestParseDovecotLoginFieldsUserNoClose(t *testing.T) {
	line := "dovecot: imap-login: Login: user=<broken, rip=1.2.3.4"
	user, ip := parseDovecotLoginFields(line)
	if user != "" || ip != "" {
		t.Errorf("unterminated user should return empty, got (%q, %q)", user, ip)
	}
}

// --- parseDovecotLogLine: non-dovecot prefix, has Login: marker ----------

func TestParseDovecotLogLineNoDovecotPrefix(t *testing.T) {
	cfg := &config.Config{}
	line := `pop3: Login: user=<x@y.com>, rip=203.0.113.5`
	if got := parseDovecotLogLine(line, cfg); got != nil {
		t.Errorf("line without 'dovecot:' should return nil, got %v", got)
	}
}

// --- parseDovecotLogLine: empty user (user=<>) short-circuits -----------

func TestParseDovecotLogLineEmptyUserReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	line := `dovecot: imap-login: Login: user=<>, rip=203.0.113.5`
	if got := parseDovecotLogLine(line, cfg); got != nil {
		t.Errorf("empty user should return nil, got %v", got)
	}
}

// --- parseDovecotLogLine: empty IP (missing rip value) returns nil -------

func TestParseDovecotLogLineEmptyIPReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	// rip= with no value, terminated immediately: parseDovecotLoginFields
	// returns empty IP which makes parseDovecotLogLine return nil.
	line := `dovecot: imap-login: Login: user=<x@y.com>, rip=`
	if got := parseDovecotLogLine(line, cfg); got != nil {
		t.Errorf("empty IP should return nil, got %v", got)
	}
}

// --- isPrivateOrLoopback: IPv4-mapped IPv6 loopback behavior -------------

func TestIsPrivateOrLoopbackIPv4MappedIPv6(t *testing.T) {
	// ::ffff:10.0.0.1 is IPv4-mapped IPv6 to private 10.0.0.1.
	if !isPrivateOrLoopback("::ffff:10.0.0.1") {
		t.Error("::ffff:10.0.0.1 should be treated as private")
	}
}

// --- pruneOldCountries: preserves exact-cutoff entries (>= cutoff) -------

func TestPruneOldCountriesBoundaryKept(t *testing.T) {
	now := int64(1_000_000)
	maxAge := int64(1_000)
	countries := map[string]int64{
		"BOUND": now - maxAge, // ts == cutoff → kept
	}
	got := pruneOldCountries(countries, now, maxAge)
	if _, ok := got["BOUND"]; !ok {
		t.Error("entry at exact cutoff should be kept (ts >= cutoff)")
	}
}

// --- pruneOldCountries: exactly 1 second older than cutoff is pruned ----

func TestPruneOldCountriesBoundaryPruned(t *testing.T) {
	now := int64(1_000_000)
	maxAge := int64(1_000)
	countries := map[string]int64{
		"OLD": now - maxAge - 1, // 1s older than cutoff → pruned
	}
	got := pruneOldCountries(countries, now, maxAge)
	if _, ok := got["OLD"]; ok {
		t.Error("entry 1s older than cutoff should be pruned")
	}
}

// --- pruneOldCountries: nil input returns non-nil empty map --------------

func TestPruneOldCountriesNilReturnsEmpty(t *testing.T) {
	got := pruneOldCountries(nil, 1000, 500)
	if got == nil {
		t.Fatal("should return non-nil map")
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}
