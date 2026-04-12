package webui

import (
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// --- parseModeString --------------------------------------------------

func TestParseModeStringStandard(t *testing.T) {
	// "-rwxr-xr-x" → 0755
	if got := parseModeString("-rwxr-xr-x"); got != 0755 {
		t.Errorf("got %04o, want 0755", got)
	}
}

func TestParseModeStringReadOnly(t *testing.T) {
	// "-r--r--r--" → 0444
	if got := parseModeString("-r--r--r--"); got != 0444 {
		t.Errorf("got %04o, want 0444", got)
	}
}

func TestParseModeStringShort(t *testing.T) {
	// Too short → default 0644
	if got := parseModeString("short"); got != 0644 {
		t.Errorf("got %04o, want default 0644", got)
	}
}

func TestParseModeStringAllDashes(t *testing.T) {
	// "----------" → fallback 0644 (all bits off → mode==0 → fallback)
	if got := parseModeString("----------"); got != 0644 {
		t.Errorf("got %04o, want fallback 0644", got)
	}
}

// --- extractAccountFromFinding ----------------------------------------

func TestExtractAccountFromFindingPath(t *testing.T) {
	f := alert.Finding{FilePath: "/home/alice/public_html/evil.php"}
	if got := extractAccountFromFinding(f); got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
}

func TestExtractAccountFromFindingDetails(t *testing.T) {
	f := alert.Finding{Details: "Account: bob\nSome info"}
	if got := extractAccountFromFinding(f); got != "bob" {
		t.Errorf("got %q, want bob", got)
	}
}

func TestExtractAccountFromFindingMessage(t *testing.T) {
	f := alert.Finding{Message: "Malware in /home/carol/public_html/file.php"}
	if got := extractAccountFromFinding(f); got != "carol" {
		t.Errorf("got %q, want carol", got)
	}
}

func TestExtractAccountFromFindingEmpty(t *testing.T) {
	f := alert.Finding{Message: "no account info"}
	if got := extractAccountFromFinding(f); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- queryInt ---------------------------------------------------------

func TestQueryIntPresent(t *testing.T) {
	req := httptest.NewRequest("GET", "/?limit=42", nil)
	if got := queryInt(req, "limit", 10); got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestQueryIntMissing(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if got := queryInt(req, "limit", 10); got != 10 {
		t.Errorf("got %d, want default 10", got)
	}
}

func TestQueryIntInvalid(t *testing.T) {
	req := httptest.NewRequest("GET", "/?limit=abc", nil)
	if got := queryInt(req, "limit", 10); got != 10 {
		t.Errorf("got %d, want default 10", got)
	}
}

func TestQueryIntNegative(t *testing.T) {
	req := httptest.NewRequest("GET", "/?limit=-5", nil)
	if got := queryInt(req, "limit", 10); got != 10 {
		t.Errorf("got %d, want default 10", got)
	}
}

// --- extractClientIP --------------------------------------------------

func TestExtractClientIPv4(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	if got := extractClientIP(req); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
}

func TestExtractClientIPv6(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:12345"
	if got := extractClientIP(req); got != "::1" {
		t.Errorf("got %q", got)
	}
}

func TestExtractClientIPNoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5"
	if got := extractClientIP(req); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
}

// formatRemaining tests are in coverage_test.go.
