package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A cloak has to decide per request, which means it must stop the page being
// cached. Stored code that both disables caching and looks for a crawler is
// serving one page to Google and another to visitors. Neither half alone is
// evidence: caching plugins set these constants from their own files, and
// plenty of code inspects the user agent.

func TestStoredCloakComponents_CacheDefeatWithCrawlerCheck(t *testing.T) {
	code := []byte(`<?php
		if (stripos($_SERVER['HTTP_USER_AGENT'], 'Googlebot') !== false) {
			define('DONOTCACHEPAGE', true);
			echo $payload;
		}`)

	cache, crawler := storedCloakComponents(code)
	if len(cache) == 0 || len(crawler) == 0 {
		t.Fatalf("cache=%v crawler=%v, want both halves", cache, crawler)
	}
}

// Cache defeat on its own is what every caching plugin's own helper does.
func TestStoredCloakComponents_CacheDefeatAlone(t *testing.T) {
	code := []byte(`<?php if (is_cart()) { define('DONOTCACHEPAGE', true); }`)

	if _, crawler := storedCloakComponents(code); len(crawler) != 0 {
		t.Fatalf("crawler halves found in ordinary cache handling: %v", crawler)
	}
}

// Reading the user agent is ordinary; naming a crawler is the cloak.
func TestStoredCloakComponents_UserAgentWithoutACrawlerName(t *testing.T) {
	code := []byte(`<?php $ua = $_SERVER['HTTP_USER_AGENT']; if (strpos($ua,'Mobile')) { define('DONOTCACHEPAGE', true); }`)

	if _, crawler := storedCloakComponents(code); len(crawler) != 0 {
		t.Fatalf("a mobile check was read as crawler detection: %v", crawler)
	}
}

// Several crawler names are ordinary words inside other strings. Matching them
// unanchored would turn a URL or a library name into crawler detection.
func TestStoredCloakComponents_CrawlerNamesMatchAsWholeWords(t *testing.T) {
	for name, code := range map[string]string{
		// Crawler name at the end of a longer word: only the leading boundary
		// can reject these.
		"leading": `<?php define('DONOTCACHEPAGE', true); $m = 'mailslurp'; $f = 'reddotbot';`,
		// Crawler name at the start of a longer word: only the trailing
		// boundary can reject these.
		"trailing": `<?php define('DONOTCACHEPAGE', true); $m = 'slurpee'; $f = 'dotbotanicals';`,
	} {
		if _, crawler := storedCloakComponents([]byte(code)); len(crawler) != 0 {
			t.Errorf("%s boundary: crawler names matched inside longer words: %v", name, crawler)
		}
	}
}

func TestStoredCloakComponents_RecognisesTheUsualCrawlers(t *testing.T) {
	for _, bot := range []string{"Googlebot", "bingbot", "YandexBot", "Baiduspider", "DuckDuckBot"} {
		code := []byte(`<?php if (strpos($_SERVER['HTTP_USER_AGENT'], '` + bot + `')) { define('DONOTCACHEPAGE', 1); }`)
		if _, crawler := storedCloakComponents(code); len(crawler) == 0 {
			t.Errorf("%s not recognised as a crawler", bot)
		}
	}
}

func TestStoredCloakComponents_RecognisesEveryCacheConstant(t *testing.T) {
	for _, form := range []string{
		`define('DONOTCACHEPAGE', true);`,
		`define("DONOTCACHEOBJECT", true);`,
		`define('DONOTCACHEDB', true);`,
		`define('WP_CACHE', false);`,
	} {
		code := []byte(`<?php ` + form + ` $x = $_SERVER['HTTP_USER_AGENT']; if (stripos($x,'googlebot')) {}`)
		if cache, _ := storedCloakComponents(code); len(cache) == 0 {
			t.Errorf("cache-defeat form not recognised: %s", form)
		}
	}
}

// WP_CACHE set to true is a site enabling caching, not defeating it.
func TestStoredCloakComponents_WPCacheEnabledIsNotDefeat(t *testing.T) {
	code := []byte(`<?php define('WP_CACHE', true); if (stripos($_SERVER['HTTP_USER_AGENT'],'googlebot')) {}`)

	if cache, _ := storedCloakComponents(code); len(cache) != 0 {
		t.Fatalf("enabling caching reported as cache defeat: %v", cache)
	}
}

// --- finding construction -------------------------------------------------

func TestStoredCloakFinding_ReportsPublishedSnippetHigher(t *testing.T) {
	code := []byte(`<?php if (stripos($_SERVER['HTTP_USER_AGENT'],'googlebot')) { define('DONOTCACHEPAGE', true); }`)

	published := storedCloakFinding("alice", wpDBCreds{dbName: "wp"}, "wp_", storedCodeRow{id: "4052", status: "publish", code: code})
	draft := storedCloakFinding("alice", wpDBCreds{dbName: "wp"}, "wp_", storedCodeRow{id: "4053", status: "draft", code: code})

	if published == nil || draft == nil {
		t.Fatalf("both snippets must report: published=%v draft=%v", published, draft)
	}
	if published.Check != "db_stored_cloak_logic" {
		t.Errorf("check = %q", published.Check)
	}
	if published.Severity != alert.High || draft.Severity != alert.Warning {
		t.Errorf("severities = %v/%v, want High/Warning", published.Severity, draft.Severity)
	}
	if !strings.Contains(published.Details, "DONOTCACHEPAGE") || !strings.Contains(published.Details, "googlebot") {
		t.Errorf("details must name both halves, got:\n%s", published.Details)
	}
}

func TestStoredCloakFinding_SilentWithoutBothHalves(t *testing.T) {
	code := []byte(`<?php define('DONOTCACHEPAGE', true);`)

	if got := storedCloakFinding("alice", wpDBCreds{dbName: "wp"}, "wp_", storedCodeRow{id: "1", status: "publish", code: code}); got != nil {
		t.Fatalf("half a cloak reported: %+v", got)
	}
}

// --- wiring ---------------------------------------------------------------

func storedCloakScanFindings(t *testing.T, rows [][3]string) []alert.Finding {
	t.Helper()
	withRepoScanner(t)
	storedCodeRows(t, rows)
	return checkWPStoredCode("alice", wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}, "wp_")
}

// The scan itself must raise the cloak finding; a snippet that matches no
// malware signature is exactly the case the signature scan cannot cover.
func TestCheckWPStoredCode_ReportsCloakWithoutASignatureHit(t *testing.T) {
	code := `<?php add_action('init', function () {
		if (stripos($_SERVER['HTTP_USER_AGENT'], 'Googlebot') !== false) {
			define('DONOTCACHEPAGE', true);
		}
	});`

	got := storedCloakScanFindings(t, [][3]string{{"4052", "publish", code}})

	var cloak *alert.Finding
	for i := range got {
		if got[i].Check == "db_stored_cloak_logic" {
			cloak = &got[i]
		}
		if got[i].Check == "db_stored_code_execution" {
			t.Errorf("benign-looking cloak matched a malware signature: %s", got[i].Message)
		}
	}
	if cloak == nil {
		t.Fatalf("cloak snippet produced no finding: %+v", got)
	}
}

// A snippet that already matched a signature must not also raise a second
// finding about the same row; the cloak becomes part of what that one says.
func TestCheckWPStoredCode_CloakAnnotatesRatherThanDuplicates(t *testing.T) {
	code := `<?php eval(base64_decode($_POST['x']));
		if (stripos($_SERVER['HTTP_USER_AGENT'], 'Googlebot') !== false) {
			define('DONOTCACHEPAGE', true);
		}`

	got := storedCloakScanFindings(t, [][3]string{{"4052", "publish", code}})

	signatureHits, cloakFindings := 0, 0
	for _, f := range got {
		switch f.Check {
		case "db_stored_code_execution":
			signatureHits++
			if !strings.Contains(f.Details, "It also cloaks") {
				t.Errorf("signature finding did not carry the cloak note:\n%s", f.Details)
			}
		case "db_stored_cloak_logic":
			cloakFindings++
		}
	}
	if signatureHits != 1 || cloakFindings != 0 {
		t.Fatalf("signature=%d cloak=%d, want one annotated signature finding", signatureHits, cloakFindings)
	}
}
