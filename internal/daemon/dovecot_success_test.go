package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// REL-04: dovecot emits two success formats. Both the mailbrute compromise
// detector and the geo new-country detector share one matcher so neither goes
// silently dead on whichever format the host uses.
func TestDovecotLoginSucceeded_AcceptsBothFormats(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "production Logged in format",
			line: `Apr 14 12:00:05 host dovecot: imap-login: Logged in: user=<alice@example.com>, method=PLAIN, rip=203.0.113.5, TLS`,
			want: true,
		},
		{
			name: "production format with pid tag",
			line: `Apr 14 12:00:05 host dovecot[1234]: imap-login: Logged in: user=<alice@example.com>, method=PLAIN, rip=203.0.113.5, TLS`,
			want: true,
		},
		{
			name: "classic Login format",
			line: `Apr 14 12:00:05 host dovecot: imap-login: Login: user=<alice@example.com>, method=PLAIN, rip=203.0.113.5, lip=192.0.2.1`,
			want: true,
		},
		{
			name: "pop3 classic",
			line: `Apr 14 12:00:05 host dovecot: pop3-login: Login: user=<bob@example.com>, rip=203.0.113.6`,
			want: true,
		},
		{
			name: "managesieve logged in",
			line: `Apr 14 12:00:05 host dovecot: managesieve-login: Logged in: user=<carol@example.com>, rip=203.0.113.7`,
			want: true,
		},
		{
			name: "auth-failure aborted login is not a success",
			line: `Apr 14 12:00:08 host dovecot: imap-login: Login aborted: Logged out (auth failed, 1 attempts): user=<dave@example.com>, rip=203.0.113.7`,
			want: false,
		},
		{
			name: "auth-failure username cannot spoof success marker",
			line: `Apr 14 12:00:08 host dovecot: imap-login: Aborted login (auth failed, 1 attempts): user=<dave-login: Logged in@example.com>, rip=203.0.113.7`,
			want: false,
		},
		{
			name: "disconnect is not a success",
			line: `Apr 14 12:00:00 host dovecot: imap-login: Disconnected (no auth attempts)`,
			want: false,
		},
		{
			name: "unrelated line",
			line: `Apr 14 12:00:00 host postfix/smtpd[1]: connect from x`,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dovecotLoginSucceeded(tc.line); got != tc.want {
				t.Errorf("dovecotLoginSucceeded(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

func TestExtractMailLoginEvent_UserCannotSpoofSuccessMarker(t *testing.T) {
	line := `Apr 14 12:00:08 host dovecot: imap-login: Aborted login (auth failed, 1 attempts): user=<dave-login: Logged in@example.com>, method=PLAIN, rip=203.0.113.7, lip=192.0.2.1`
	ip, account, success := extractMailLoginEvent(line)
	if ip != "203.0.113.7" || account != "dave-login: Logged in@example.com" || success {
		t.Errorf("got (%q, %q, %v), want (203.0.113.7, dave-login: Logged in@example.com, false)", ip, account, success)
	}
}

// REL-04 (mailbrute side): the classic "Login: user=<" success format must be
// recognized as a success, or RecordSuccess-based compromise detection is dead
// on hosts that emit it. Before the shared matcher, extractMailLoginEvent keyed
// only off "Logged in" and returned success=false for this line.
func TestExtractMailLoginEvent_ClassicLoginSuccess(t *testing.T) {
	line := `Apr 14 12:00:05 host dovecot: imap-login: Login: user=<alice@example.com>, method=PLAIN, rip=203.0.113.5, lip=192.0.2.1, TLS`
	ip, account, success := extractMailLoginEvent(line)
	if ip != "203.0.113.5" || account != "alice@example.com" || !success {
		t.Errorf("got (%q, %q, %v), want (203.0.113.5, alice@example.com, true)", ip, account, success)
	}
}

// REL-04 (geo side): the geo detector's success gate must accept the production
// "Logged in" format. The gate is dovecotLoginSucceeded, which the classic
// "Login: user=<" substring the old gate used does NOT satisfy for this line,
// pinning exactly why the detector was dead on the prod format. The full geo
// finding needs a GeoIP database to fire, so here we assert the line is not
// rejected at the marker gate (no panic, gate accepts it).
func TestParseDovecotLogLine_ProdFormatPassesSuccessGate(t *testing.T) {
	prod := `Apr 14 12:00:05 host dovecot: imap-login: Logged in: user=<alice@example.com>, method=PLAIN, rip=203.0.113.5, lip=192.0.2.1, TLS`
	if !dovecotLoginSucceeded(prod) {
		t.Fatal("prod Logged in format must satisfy the shared success gate")
	}
	// GeoIP DB is nil in the unit env, so the detector returns nil after the
	// gate; the point is it does not panic and does not reject at the gate.
	cfg := &config.Config{}
	if got := parseDovecotLogLine(prod, cfg); got != nil {
		t.Errorf("expected nil (no GeoIP DB in test env), got %v", got)
	}
}
