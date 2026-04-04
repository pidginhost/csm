package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestParseDovecotUser(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantUser string
	}{
		{
			name:     "imap login",
			line:     `Apr  4 10:15:23 server dovecot: imap-login: Login: user=<john@example.com>, method=PLAIN, rip=203.0.113.42, lip=10.0.0.1, mpid=12345, TLS, session=<abc123>`,
			wantUser: "john@example.com",
		},
		{
			name:     "pop3 login",
			line:     `Apr  4 10:15:23 server dovecot: pop3-login: Login: user=<admin@test.org>, method=PLAIN, rip=198.51.100.7, lip=10.0.0.1`,
			wantUser: "admin@test.org",
		},
		{
			name:     "no user field",
			line:     `Apr  4 10:15:23 server dovecot: imap-login: Disconnected`,
			wantUser: "",
		},
		{
			name:     "empty line",
			line:     ``,
			wantUser: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, _ := parseDovecotLoginFields(tt.line)
			if user != tt.wantUser {
				t.Errorf("parseDovecotLoginFields() user = %q, want %q", user, tt.wantUser)
			}
		})
	}
}

func TestParseDovecotRIP(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		wantIP string
	}{
		{
			name:   "imap login",
			line:   `Apr  4 10:15:23 server dovecot: imap-login: Login: user=<john@example.com>, method=PLAIN, rip=203.0.113.42, lip=10.0.0.1`,
			wantIP: "203.0.113.42",
		},
		{
			name:   "pop3 login",
			line:   `Apr  4 10:15:23 server dovecot: pop3-login: Login: user=<admin@test.org>, method=PLAIN, rip=198.51.100.7, lip=10.0.0.1`,
			wantIP: "198.51.100.7",
		},
		{
			name:   "rip at end of line",
			line:   `Apr  4 10:15:23 server dovecot: imap-login: Login: user=<john@example.com>, rip=8.8.8.8`,
			wantIP: "8.8.8.8",
		},
		{
			name:   "no rip field",
			line:   `Apr  4 10:15:23 server postfix/smtp[123]: connect`,
			wantIP: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ip := parseDovecotLoginFields(tt.line)
			if ip != tt.wantIP {
				t.Errorf("parseDovecotLoginFields() ip = %q, want %q", ip, tt.wantIP)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.15.0.1", false},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"192.168.0.0", true},
		{"203.0.113.42", false},
		{"8.8.8.8", false},
		{"::1", true},
		{"", true}, // invalid = skip
	}

	for _, tt := range tests {
		got := isPrivateOrLoopback(tt.ip)
		if got != tt.private {
			t.Errorf("isPrivateOrLoopback(%q) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestParseDovecotLogLine_NonLoginLine(t *testing.T) {
	lines := []string{
		`Apr  4 10:15:23 server dovecot: imap-login: Disconnected`,
		`Apr  4 10:15:23 server postfix/smtp[123]: connect`,
		`Apr  4 10:15:23 server dovecot: auth-worker: passwd-file: unknown user`,
		``,
	}

	cfg := &config.Config{}

	for _, line := range lines {
		findings := parseDovecotLogLine(line, cfg)
		if findings != nil {
			t.Errorf("parseDovecotLogLine(%q) = %v, want nil", line, findings)
		}
	}
}

func TestParseDovecotLogLine_InfraIP(t *testing.T) {
	line := `Apr  4 10:15:23 server dovecot: imap-login: Login: user=<john@example.com>, method=PLAIN, rip=10.0.0.1, lip=10.0.0.1`

	cfg := &config.Config{}

	findings := parseDovecotLogLine(line, cfg)
	if findings != nil {
		t.Errorf("parseDovecotLogLine with private IP should return nil, got %v", findings)
	}
}

func TestPruneOldCountries(t *testing.T) {
	now := int64(1775296605) // arbitrary timestamp
	thirtyDays := int64(30 * 24 * 60 * 60)

	countries := map[string]int64{
		"RO": now - 1000,           // recent -- keep
		"US": now - thirtyDays,     // exactly 30 days -- keep (boundary)
		"CN": now - thirtyDays - 1, // 30 days + 1 second -- prune
		"DE": now - 100,            // recent -- keep
	}

	pruned := pruneOldCountries(countries, now, thirtyDays)

	if _, ok := pruned["RO"]; !ok {
		t.Error("RO should be kept")
	}
	if _, ok := pruned["US"]; !ok {
		t.Error("US should be kept (boundary)")
	}
	if _, ok := pruned["CN"]; ok {
		t.Error("CN should be pruned")
	}
	if _, ok := pruned["DE"]; !ok {
		t.Error("DE should be kept")
	}
}
