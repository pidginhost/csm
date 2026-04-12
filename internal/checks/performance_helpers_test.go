package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// --- perfEnabled ------------------------------------------------------

func TestPerfEnabledDefault(t *testing.T) {
	cfg := &config.Config{}
	if !perfEnabled(cfg) {
		t.Error("nil Enabled should default to true")
	}
}

func TestPerfEnabledExplicitTrue(t *testing.T) {
	b := true
	cfg := &config.Config{}
	cfg.Performance.Enabled = &b
	if !perfEnabled(cfg) {
		t.Error("explicit true should return true")
	}
}

func TestPerfEnabledExplicitFalse(t *testing.T) {
	b := false
	cfg := &config.Config{}
	cfg.Performance.Enabled = &b
	if perfEnabled(cfg) {
		t.Error("explicit false should return false")
	}
}

// --- humanBytes -------------------------------------------------------

func TestHumanBytesGigabyte(t *testing.T) {
	if got := humanBytes(2 * 1024 * 1024 * 1024); got != "2.0G" {
		t.Errorf("got %q", got)
	}
}

func TestHumanBytesMegabyte(t *testing.T) {
	if got := humanBytes(50 * 1024 * 1024); got != "50M" {
		t.Errorf("got %q", got)
	}
}

func TestHumanBytesKilobyte(t *testing.T) {
	if got := humanBytes(512 * 1024); got != "512K" {
		t.Errorf("got %q", got)
	}
}

func TestHumanBytesZero(t *testing.T) {
	if got := humanBytes(0); got != "0B" {
		t.Errorf("got %q", got)
	}
}

// --- safeIdentifier ---------------------------------------------------

func TestSafeIdentifierValid(t *testing.T) {
	for _, s := range []string{"mysql_db", "user123", "wp_posts"} {
		if !safeIdentifier(s) {
			t.Errorf("%q should be safe", s)
		}
	}
}

func TestSafeIdentifierInvalid(t *testing.T) {
	for _, s := range []string{"", "drop; --", "user name", "$(cmd)"} {
		if safeIdentifier(s) {
			t.Errorf("%q should not be safe", s)
		}
	}
}

// --- extractPHPDefine -------------------------------------------------

func TestExtractPHPDefineSingleQuoted(t *testing.T) {
	if got := extractPHPDefine("define('WP_MEMORY_LIMIT', '256M');"); got != "256M" {
		t.Errorf("got %q, want 256M", got)
	}
}

func TestExtractPHPDefineDoubleQuoted(t *testing.T) {
	if got := extractPHPDefine(`define("WP_MEMORY_LIMIT", "512M");`); got != "512M" {
		t.Errorf("got %q, want 512M", got)
	}
}

func TestExtractPHPDefineNoComma(t *testing.T) {
	if got := extractPHPDefine("define('KEY')"); got != "" {
		t.Errorf("no comma should return empty, got %q", got)
	}
}

func TestExtractPHPDefineNoParen(t *testing.T) {
	if got := extractPHPDefine("not a define"); got != "" {
		t.Errorf("no paren should return empty, got %q", got)
	}
}

// --- parseMemoryLimit -------------------------------------------------

func TestParseMemoryLimitMegabytes(t *testing.T) {
	if got := parseMemoryLimit("256M"); got != 256 {
		t.Errorf("256M = %d, want 256", got)
	}
}

func TestParseMemoryLimitGigabytes(t *testing.T) {
	if got := parseMemoryLimit("2G"); got != 2048 {
		t.Errorf("2G = %d, want 2048", got)
	}
}

func TestParseMemoryLimitKilobytes(t *testing.T) {
	if got := parseMemoryLimit("512K"); got != 0 {
		t.Errorf("512K = %d, want 0 (512/1024=0)", got)
	}
}

// parseMemoryLimit edge cases (unlimited/empty) are in coverage_test.go.

func TestParseMemoryLimitPlainNumber(t *testing.T) {
	if got := parseMemoryLimit("128"); got != 128 {
		t.Errorf("128 = %d, want 128", got)
	}
}

// --- accountFromPath --------------------------------------------------

func TestAccountFromPathCPanel(t *testing.T) {
	if got := accountFromPath("/home/alice/public_html"); got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
}

func TestAccountFromPathGeneric(t *testing.T) {
	if got := accountFromPath("/var/www/mysite/public"); got != "mysite" {
		t.Errorf("got %q, want mysite", got)
	}
}

func TestAccountFromPathBaseOnly(t *testing.T) {
	// /srv/http/mysite → base(dir)="mysite" when no /home/ pattern
	got := accountFromPath("/srv/http/mysite")
	if got != "http" {
		t.Errorf("got %q, want http (parent of last segment)", got)
	}
}
