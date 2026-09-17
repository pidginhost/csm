package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

const scannerLine = "[2026-09-01 19:12:47] WEBSHELL_PARAM ip=198.51.100.44 " +
	"script=/home/example/public_html/alfacgiapi/perl.php uri=/alfacgiapi/perl.php?cmd=id " +
	"ua=Mozlila/5.0 (Linux; Android 7.0) AppleWebKit/537.36 details=cmd"

// The Shield sends the request URI, and it is the field that identifies what
// hit the site: "/alfacgiapi/perl.php" is a known webshell path, while the bare
// parameter name "cmd" says nothing an operator can act on.
func TestParsePHPShieldLineKeepsRequestURI(t *testing.T) {
	f := parsePHPShieldLine(scannerLine)
	if f == nil {
		t.Fatal("expected a finding")
	}
	if !strings.Contains(f.Details, "/alfacgiapi/perl.php?cmd=id") {
		t.Errorf("details %q dropped the request URI the Shield reported", f.Details)
	}
}

// The user agent names the scanner outright. It travels over the socket and was
// being discarded with the URI.
func TestParsePHPShieldLineKeepsUserAgent(t *testing.T) {
	f := parsePHPShieldLine(scannerLine)
	if f == nil {
		t.Fatal("expected a finding")
	}
	if !strings.Contains(f.Details, "Mozlila") {
		t.Errorf("details %q dropped the user agent the Shield reported", f.Details)
	}
}

// The IP has to land in the SourceIP field, not only in the rendered details,
// or per-IP alert dedup cannot see it.
func TestParsePHPShieldLineSetsSourceIP(t *testing.T) {
	f := parsePHPShieldLine(scannerLine)
	if f == nil {
		t.Fatal("expected a finding")
	}
	if f.SourceIP != "198.51.100.44" {
		t.Errorf("SourceIP = %q, want the reporting IP", f.SourceIP)
	}
}

// A request carrying ?cmd= is only an observation: for a document-root script
// the Shield cannot reach its deny branch, so nothing was blocked. Rating it the
// same as a block is what buries the findings that did stop something.
func TestParsePHPShieldLineObservedParamRanksBelowBlocks(t *testing.T) {
	observed := parsePHPShieldLine(scannerLine)
	if observed == nil {
		t.Fatal("expected a finding")
	}
	if observed.Severity >= alert.Critical {
		t.Errorf("observed webshell parameter -> severity %v, want below Critical", observed.Severity)
	}

	blocked := parsePHPShieldLine("[2026-09-01 19:12:47] BLOCK_WEBSHELL ip=198.51.100.44 " +
		"script=/home/example/public_html/wp-content/x.php uri=/x.php ua=curl details=sig")
	if blocked == nil {
		t.Fatal("expected a finding")
	}
	if blocked.Severity != alert.Critical {
		t.Errorf("blocked webshell -> severity %v, want Critical", blocked.Severity)
	}
	if observed.Severity >= blocked.Severity {
		t.Errorf("observation (%v) must rank below a block (%v)", observed.Severity, blocked.Severity)
	}
}

// A path block is a real denial and stays Critical.
func TestParsePHPShieldLineBlockPathStaysCritical(t *testing.T) {
	f := parsePHPShieldLine("[2026-09-01 19:12:47] BLOCK_PATH ip=1.2.3.4 " +
		"script=/home/e/public_html/wp-content/uploads/x.php uri=/wp-content/uploads/x.php ua=curl details=blocked")
	if f == nil {
		t.Fatal("expected a finding")
	}
	if f.Severity != alert.Critical {
		t.Errorf("blocked path -> severity %v, want Critical", f.Severity)
	}
}

// One scanner sweeping many accounts produced one alert per site. Findings that
// carry a source IP must collapse onto a single dedup key so a sweep is one
// alert naming the IP, not fifty.
func TestPHPShieldFindingsDedupPerSourceIP(t *testing.T) {
	first := parsePHPShieldLine(scannerLine)
	second := parsePHPShieldLine("[2026-09-01 19:12:48] WEBSHELL_PARAM ip=198.51.100.44 " +
		"script=/home/other/public_html/alfacgiapi/perl.php uri=/alfacgiapi/perl.php?cmd=id ua=Mozlila/5.0 details=cmd")
	if first == nil || second == nil {
		t.Fatal("expected findings")
	}
	if first.Key() != second.Key() {
		t.Errorf("same scanner on two sites produced two alert keys:\n %s\n %s", first.Key(), second.Key())
	}

	other := parsePHPShieldLine("[2026-09-01 19:12:48] WEBSHELL_PARAM ip=203.0.113.9 " +
		"script=/home/other/public_html/x.php uri=/x.php?cmd=id ua=curl details=cmd")
	if other == nil {
		t.Fatal("expected a finding")
	}
	if other.Key() == first.Key() {
		t.Error("different source IPs must not collapse into one alert")
	}
}
