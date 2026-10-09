package antispam

import (
	"strings"
	"testing"
)

func TestValidateSocketAccepts(t *testing.T) {
	for _, p := range []string{DefaultSocket, "/var/run/rspamd/normal.sock", "/run/a_b-c.d/x1.sock"} {
		if err := ValidateSocket(p); err != nil {
			t.Errorf("ValidateSocket(%q) = %v, want nil", p, err)
		}
	}
}

func TestValidateSocketRejects(t *testing.T) {
	for _, p := range []string{
		"", "/", "run/rspamd.sock", "/run//rspamd.sock", "/run/./rspamd.sock",
		"/run/../rspamd.sock", "/run/rspamd/", "/run/rspamd.sock\n", "/run/rspamd sock",
		"/run/$spool/x.sock", "/run/x.sock:/y", "/run/x;y", "/run/{x}", `/run/x\y`,
		"/run/caf\u00e9.sock", "/" + strings.Repeat("a", maxSocketPath),
	} {
		if err := ValidateSocket(p); err == nil {
			t.Errorf("ValidateSocket(%q) = nil, want error", p)
		}
	}
}

func TestValidateScores(t *testing.T) {
	for _, c := range [][2]int{{15, 6}, {2, 1}, {1000, 999}} {
		if err := ValidateScores(c[0], c[1]); err != nil {
			t.Errorf("ValidateScores(%d, %d) = %v, want nil", c[0], c[1], err)
		}
	}
	for _, c := range [][2]int{{0, 6}, {15, 0}, {-1, -5}, {6, 6}, {6, 15}, {1001, 6}, {15, 1001}} {
		if err := ValidateScores(c[0], c[1]); err == nil {
			t.Errorf("ValidateScores(%d, %d) = nil, want error", c[0], c[1])
		}
	}
}

func TestSettingsValidate(t *testing.T) {
	s := Settings{Socket: DefaultSocket, RejectScore: DefaultRejectScore, TagScore: DefaultTagScore}
	if err := s.Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	s.Socket = "relative.sock"
	if err := s.Validate(); err == nil {
		t.Fatal("relative socket accepted")
	}
}
