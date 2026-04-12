package daemon

import (
	"testing"
	"time"
)

// --- extractEximDomain ------------------------------------------------

func TestExtractEximDomainStandard(t *testing.T) {
	line := "exim mainlog Domain example.com rate-limited"
	if got := extractEximDomain(line); got != "example.com" {
		t.Errorf("got %q, want example.com", got)
	}
}

func TestExtractEximDomainMissing(t *testing.T) {
	if got := extractEximDomain("no domain keyword"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractEximDomainEndOfLine(t *testing.T) {
	line := "exim mainlog Domain example.com"
	if got := extractEximDomain(line); got != "example.com" {
		t.Errorf("got %q", got)
	}
}

// --- extractEximSubject -----------------------------------------------

func TestExtractEximSubjectStandard(t *testing.T) {
	line := `2026-04-12 H=host T="Hello World" F=<a@b.com>`
	if got := extractEximSubject(line); got != "Hello World" {
		t.Errorf("got %q", got)
	}
}

func TestExtractEximSubjectMissing(t *testing.T) {
	if got := extractEximSubject("no subject"); got != "" {
		t.Errorf("got %q", got)
	}
}

// --- parseCpanelSessionLogin ------------------------------------------

func TestParseCpanelSessionLoginStandard(t *testing.T) {
	line := `[2026-04-12 10:00:00 +0000] info [cpaneld] 203.0.113.5 NEW alice:token address=203.0.113.5`
	ip, account := parseCpanelSessionLogin(line)
	if ip != "203.0.113.5" {
		t.Errorf("ip = %q", ip)
	}
	if account != "alice" {
		t.Errorf("account = %q", account)
	}
}

func TestParseCpanelSessionLoginNoCpaneld(t *testing.T) {
	ip, account := parseCpanelSessionLogin("no cpaneld")
	if ip != "" || account != "" {
		t.Errorf("got (%q, %q)", ip, account)
	}
}

// --- pruneSlice -------------------------------------------------------

func TestPruneSliceRemovesOld(t *testing.T) {
	now := time.Now()
	times := []time.Time{
		now.Add(-2 * time.Hour),
		now.Add(-30 * time.Minute),
		now.Add(-5 * time.Minute),
	}
	cutoff := now.Add(-1 * time.Hour)
	result := pruneSlice(times, cutoff)
	if len(result) != 2 {
		t.Errorf("got %d, want 2", len(result))
	}
}

func TestPruneSliceEmpty(t *testing.T) {
	result := pruneSlice(nil, time.Now())
	if len(result) != 0 {
		t.Errorf("nil slice should return empty, got %d", len(result))
	}
}

func TestPruneSliceAllRecent(t *testing.T) {
	now := time.Now()
	times := []time.Time{now, now.Add(-1 * time.Second)}
	result := pruneSlice(times, now.Add(-1*time.Hour))
	if len(result) != 2 {
		t.Errorf("all recent should keep all, got %d", len(result))
	}
}
