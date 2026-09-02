package checks

import (
	"encoding/base64"
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

	cache, crawler := storedCloakComponents(code)
	if len(cache) == 0 || len(crawler) != 0 {
		t.Fatalf("ordinary cache handling parsed as cache=%v crawler=%v", cache, crawler)
	}
}

func TestStoredCloakComponents_RequiresAnEffectiveCacheDefeat(t *testing.T) {
	for name, code := range map[string]string{
		"false constant":      `define('DONOTCACHEPAGE', false);`,
		"zero constant":       `define('DONOTCACHEOBJECT', 0);`,
		"null constant":       `define('DONOTCACHEDB', null);`,
		"object cache only":   `define('DONOTCACHEOBJECT', true);`,
		"database cache only": `define('DONOTCACHEDB', true);`,
		"missing value":       `define('DONOTCACHEPAGE');`,
		"true WP_CACHE":       `define('WP_CACHE', true);`,
		"true variable":       `$enabled = true; define('WP_CACHE', $enabled);`,
		"interpolated value": `$enabled = false;
			define('DONOTCACHEPAGE', "$enabled");`,
		"global variable":  `$GLOBALS['DONOTCACHEPAGE'] = true;`,
		"commented define": `// define('DONOTCACHEPAGE', true);`,
		"quoted define":    `$example = "define('DONOTCACHEPAGE', true)";`,
		"quoted function":  `$example = 'nocache_headers();';`,
		"header near miss": `header('X-LiteSpeed-Cache-Control: no-cacheable');`,
		"method call":      `$cache -> header('X-LiteSpeed-Cache-Control: no-cache');`,
		"static call":      `Cache :: nocache_headers();`,
		"function declaration": `function nocache_headers() {
			return true;
		}`,
	} {
		t.Run(name, func(t *testing.T) {
			cache, _ := storedCloakComponents([]byte(`<?php ` + code +
				` if (stripos($_SERVER['HTTP_USER_AGENT'], 'Googlebot')) {}`))
			if len(cache) != 0 {
				t.Fatalf("non-defeating cache form reported: %v", cache)
			}
		})
	}
}

func TestStoredCloakComponents_RecognisesRequestNoCacheForms(t *testing.T) {
	for name, code := range map[string]string{
		"litespeed":    `header('X-LiteSpeed-Cache-Control: no-cache, esi=on');`,
		"core headers": `nocache_headers();`,
		"false variable": `$cache = false;
			define('WP_CACHE', $cache);`,
	} {
		t.Run(name, func(t *testing.T) {
			cache, crawler := storedCloakComponents([]byte(`<?php ` + code +
				` if (stripos($_SERVER['HTTP_USER_AGENT'], 'Googlebot')) {}`))
			if len(cache) == 0 || len(crawler) == 0 {
				t.Fatalf("cache=%v crawler=%v, want both halves", cache, crawler)
			}
		})
	}
}

// Reading the user agent is ordinary; naming a crawler is the cloak.
func TestStoredCloakComponents_UserAgentWithoutACrawlerName(t *testing.T) {
	code := []byte(`<?php $ua = $_SERVER['HTTP_USER_AGENT']; if (strpos($ua,'Mobile')) { define('DONOTCACHEPAGE', true); }`)

	if _, crawler := storedCloakComponents(code); len(crawler) != 0 {
		t.Fatalf("a mobile check was read as crawler detection: %v", crawler)
	}
}

func TestStoredCloakComponents_CrawlerNameWithoutUserAgentInspection(t *testing.T) {
	code := []byte(`<?php define('DONOTCACHEPAGE', true); echo 'HTTP_USER_AGENT Googlebot documentation';`)

	if _, crawler := storedCloakComponents(code); len(crawler) != 0 {
		t.Fatalf("crawler literal without a user-agent check reported: %v", crawler)
	}
}

func TestStoredCloakComponents_RecognisesConstantUserAgentKey(t *testing.T) {
	code := []byte(`<?php define('DONOTCACHEPAGE', true);
		$ua = $_SERVER['HTTP_' . 'USER_AGENT']; if (stripos($ua, 'Googlebot')) {}`)

	cache, crawler := storedCloakComponents(code)
	if len(cache) == 0 || len(crawler) == 0 {
		t.Fatalf("constant user-agent key missed: cache=%v crawler=%v", cache, crawler)
	}
}

func TestStoredCloakComponents_CommentsDoNotSupplyCrawlerEvidence(t *testing.T) {
	code := []byte(`<?php define('DONOTCACHEPAGE', true);
		$ua = $_SERVER['HTTP_USER_AGENT']; // Googlebot gets another page.
	`)

	if _, crawler := storedCloakComponents(code); len(crawler) != 0 {
		t.Fatalf("comment supplied crawler evidence: %v", crawler)
	}
}

func TestStoredCloakComponents_HeredocCallsAreNotExecutable(t *testing.T) {
	code := []byte(`<?php $example = <<<'PHP'
		define('DONOTCACHEPAGE', true);
		$_SERVER['HTTP_USER_AGENT'];
		Googlebot
		PHP;`)

	cache, crawler := storedCloakComponents(code)
	if len(cache) != 0 || len(crawler) != 0 {
		t.Fatalf("heredoc example executed as cache=%v crawler=%v", cache, crawler)
	}
}

func TestStoredCloakComponents_HeredocCrawlerListRemainsVisible(t *testing.T) {
	code := []byte(`<?php define('DONOTCACHEPAGE', true);
		$ua = $_SERVER['HTTP_USER_AGENT'];
		$bots = <<<'BOTS'
		Googlebot
		BOTS;`)

	cache, crawler := storedCloakComponents(code)
	if len(cache) == 0 || len(crawler) == 0 {
		t.Fatalf("real code with heredoc bot list missed: cache=%v crawler=%v", cache, crawler)
	}
}

func TestStoredCloakComponents_HeredocCodeIsNotDerived(t *testing.T) {
	code := []byte(`<?php define('DONOTCACHEPAGE', true);
		$ua = $_SERVER['HTTP_USER_AGENT'];
		$example = <<<'PHP'
		$bot = 'Goo' . 'glebot';
		PHP;`)

	if _, crawler := storedCloakComponents(code); len(crawler) != 0 {
		t.Fatalf("heredoc example derived as executable crawler logic: %v", crawler)
	}
}

func TestStoredCloakComponents_HeredocMarkerInsideStringDoesNotHideCode(t *testing.T) {
	code := []byte(`<?php $example = "<<<TEXT
		not a real heredoc";
		define('DONOTCACHEPAGE', true);
		$ua = $_SERVER['HTTP_USER_AGENT'];
		if (stripos($ua, 'Googlebot')) {}`)

	cache, crawler := storedCloakComponents(code)
	if len(cache) == 0 || len(crawler) == 0 {
		t.Fatalf("heredoc-like string hid executable code: cache=%v crawler=%v", cache, crawler)
	}
}

// Several crawler names are ordinary words inside other strings. Matching them
// unanchored would turn a URL or a library name into crawler detection.
func TestStoredCloakComponents_CrawlerNamesMatchAsWholeWords(t *testing.T) {
	for name, code := range map[string]string{
		// Crawler name at the end of a longer word: only the leading boundary
		// can reject these.
		"leading": `<?php define('DONOTCACHEPAGE', true); $ua = $_SERVER['HTTP_USER_AGENT']; $m = 'mailslurp'; $f = 'reddotbot';`,
		// Crawler name at the start of a longer word: only the trailing
		// boundary can reject these.
		"trailing": `<?php define('DONOTCACHEPAGE', true); $ua = $_SERVER['HTTP_USER_AGENT']; $m = 'slurpee'; $f = 'dotbotanicals';`,
	} {
		if _, crawler := storedCloakComponents([]byte(code)); len(crawler) != 0 {
			t.Errorf("%s boundary: crawler names matched inside longer words: %v", name, crawler)
		}
	}
}

func TestStoredCloakComponents_RecognisesTheUsualCrawlers(t *testing.T) {
	for _, bot := range []string{
		"Googlebot", "Googlebot-Image", "Googlebot-News", "bingbot", "YandexBot",
		"Baiduspider", "DuckDuckBot", "PetalBot", "OAI-SearchBot", "Claude-SearchBot",
	} {
		code := []byte(`<?php if (strpos($_SERVER['HTTP_USER_AGENT'], '` + bot + `')) { define('DONOTCACHEPAGE', 1); }`)
		if _, crawler := storedCloakComponents(code); len(crawler) == 0 {
			t.Errorf("%s not recognised as a crawler", bot)
		}
	}
}

func TestStoredCloakComponents_NonRankingCrawlersStayQuiet(t *testing.T) {
	for _, bot := range []string{
		"AdsBot-Google", "Google-InspectionTool", "Bytespider", "GPTBot", "ClaudeBot",
	} {
		code := []byte(`<?php if (strpos($_SERVER['HTTP_USER_AGENT'], '` + bot + `')) { define('DONOTCACHEPAGE', 1); }`)
		if _, crawler := storedCloakComponents(code); len(crawler) != 0 {
			t.Errorf("%s added noisy crawler evidence: %v", bot, crawler)
		}
	}
}

func TestStoredCloakComponents_RecognisesConstantStringObfuscation(t *testing.T) {
	for name, crawlerExpr := range map[string]string{
		"concatenation": `'Goo' . 'gle' . 'bot'`,
		"rot13":         `str_rot13('Tbbtyrobg')`,
	} {
		t.Run(name, func(t *testing.T) {
			code := []byte(`<?php $ua = $_SERVER['HTTP_USER_AGENT']; $crawler = ` + crawlerExpr + `;
				if (stripos($ua, $crawler)) { define('DONOTCACHEPAGE', true); }`)
			cache, crawler := storedCloakComponents(code)
			if len(cache) == 0 || len(crawler) == 0 {
				t.Fatalf("cache=%v crawler=%v, want obfuscated crawler detected", cache, crawler)
			}
		})
	}
}

func TestStoredCloakComponents_DoesNotEvaluateROT13Methods(t *testing.T) {
	for name, expression := range map[string]string{
		"method": `$decoder -> str_rot13('Tbbtyrobg');`,
		"static": `Decoder :: str_rot13('Tbbtyrobg');`,
	} {
		t.Run(name, func(t *testing.T) {
			code := []byte(`<?php define('DONOTCACHEPAGE', true);
				$ua = $_SERVER['HTTP_USER_AGENT']; ` + expression)
			if _, crawler := storedCloakComponents(code); len(crawler) != 0 {
				t.Fatalf("non-global ROT13 call supplied crawler evidence: %v", crawler)
			}
		})
	}
}

func TestStoredConstantStringExpression_RejectsUnterminatedEscapedQuote(t *testing.T) {
	if value, ok := storedConstantStringExpression(`"Googlebot\"`); ok {
		t.Fatalf("unterminated PHP string parsed as %q", value)
	}
}

func TestStoredCloakComponents_RecognisesPageCacheConstants(t *testing.T) {
	for _, form := range []string{
		`define('DONOTCACHEPAGE', true);`,
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

// signedFixture decodes a fixture that carries a real malware signature. These
// are stored base64-encoded so the plaintext never lands on disk: endpoint
// antivirus quarantines files containing these patterns, which silently removes
// the test from the working copy, from every fresh clone, and from the editor's
// own file-history snapshots. internal/phptaint stores all 57 of its fixtures
// this way for the same reason, and that is what makes it the one package here
// unaffected by a scanner.
func signedFixture(t *testing.T, encoded string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("fixture does not decode: %v", err)
	}
	return string(decoded)
}

// An eval/base64 backdoor followed by the cloak pair, so the snippet matches a
// shipped signature and also carries cloak components.
const evalBackdoorWithCloak = "PD9waHAgZXZhbChiYXNlNjRfZGVjb2RlKCRfUE9TVFsneCddKSk7CgkJaWYgKHN0cmlwb3MoJF9TRVJWRVJbJ0hUVFBfVVNFUl9BR0VOVCddLCAnR29vZ2xlYm90JykgIT09IGZhbHNlKSB7CgkJCWRlZmluZSgnRE9OT1RDQUNIRVBBR0UnLCB0cnVlKTsKCQl9"

// The same backdoor opening, followed by a user-agent read and the start of a
// long crawler-name list the caller appends to.
const evalBackdoorWithManyBots = "PD9waHAgZXZhbChiYXNlNjRfZGVjb2RlKCRfUE9TVFsneCddKSk7CgkJJHVhID0gJF9TRVJWRVJbJ0hUVFBfVVNFUl9BR0VOVCddOwoJCWRlZmluZSgnRE9OT1RDQUNIRVBBR0UnLCB0cnVlKTsKCQkkYm90cyA9ICc="

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
	code := signedFixture(t, evalBackdoorWithCloak)

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

func TestCheckWPStoredCode_CloakAnnotationIdentityIsStableAndBounded(t *testing.T) {
	bots := "googlebot bingbot msnbot yandexbot baiduspider duckduckbot slurp " +
		"applebot sogou exabot facebot ia_archiver ahrefsbot semrushbot mj12bot dotbot petalbot"
	code := signedFixture(t, evalBackdoorWithManyBots) +
		strings.Repeat(bots+" ", 100) + `';`

	first := storedCloakScanFindings(t, [][3]string{{"4052", "publish", code}})
	second := storedCloakScanFindings(t, [][3]string{{"4052", "publish", code}})
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("findings = %d/%d, want one annotated finding per scan", len(first), len(second))
	}
	if first[0].Key() != second[0].Key() || first[0].Fingerprint() != second[0].Fingerprint() {
		t.Fatalf("unchanged annotation changed identity: key %q/%q, fingerprint %q/%q",
			first[0].Key(), second[0].Key(), first[0].Fingerprint(), second[0].Fingerprint())
	}
	if len(first[0].Details) > 1024 {
		t.Fatalf("crawler annotation grew with repeated names: %d bytes", len(first[0].Details))
	}
}

func BenchmarkStoredCloakComponents_MaximumSnippet(b *testing.B) {
	prefix := `define('DONOTCACHEPAGE', true); `
	unit := `if (stripos($_SERVER['HTTP_USER_AGENT'], 'not-a-crawler')) { $x = "define"; } `
	code := []byte((prefix + strings.Repeat(unit, maxStoredCodeBytes/len(unit)+1))[:maxStoredCodeBytes])
	b.SetBytes(int64(len(code)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		storedCloakComponents(code)
	}
}

func BenchmarkStoredCloakComponents_NestedServerBrackets(b *testing.B) {
	prefix := `define('DONOTCACHEPAGE', true); `
	unit := `$_SERVER[$_SERVER[`
	code := []byte((prefix + strings.Repeat(unit, maxStoredCodeBytes/len(unit)+1))[:maxStoredCodeBytes])
	b.SetBytes(int64(len(code)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		storedCloakComponents(code)
	}
}
