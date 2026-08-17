package signatures

import (
	"os"
	"path/filepath"
	"testing"
)

// Shape taken from real samples: a copied mailer library with one line appended
// deep inside it, and a file-manager webshell under a double extension. Neither
// carries a URL or a fetch -- the payload is rebuilt through an indirect call,
// which is what the rule keys on.
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

func TestBackdoorHtmlmodeEval_DecoderVariants(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Renaming the payload variable, or swapping one decoder for another, must
	// not shake the rule off: it keys on the rebuild, not on names.
	variants := map[string]string{
		"base64":          `<?php eval('?>' . base64_decode($zz));`,
		"gzinflate":       `<?php eval('?>' . gzinflate($q));`,
		"str_rot13":       `<?php eval('?>' . str_rot13($whatever));`,
		"strrev":          `<?php eval('?>' . strrev($k));`,
		"hex2bin":         `<?php eval('?>' . hex2bin($h));`,
		"error_suppress":  `<?php eval('?>' . @gzuncompress($p));`,
		"variable_var":    `<?php eval('?>' . $$fn($p));`,
		"dynamic_call":    `<?php eval('?>' . $decoder($p));`,
		"nested_decoders": `<?php eval('?>' . gzinflate(base64_decode($x)));`,
	}

	for name, sample := range variants {
		t.Run(name, func(t *testing.T) {
			if !hasRule(scanner.ScanContent([]byte(sample), ".php"), "backdoor_htmlmode_eval") {
				t.Errorf("backdoor_htmlmode_eval miss: %s rebuild evaded the rule", name)
			}
		})
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

// A staged payload keeps the same content under an extension a stock handler
// renders as source. Content scanning must not go blind on the extension alone.
func TestBackdoorHtmlmodeEval_UnderPhpsExtension(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
eval('?>' . gzinflate(base64_decode($p)));
`)

	if !hasRule(scanner.ScanContent(malicious, ".phps"), "backdoor_htmlmode_eval") {
		t.Error("backdoor_htmlmode_eval miss: staged .phps payload was not scanned as PHP")
	}
}

// Twig's Environment.php is the most common carrier of this idiom in the wild:
// it ships inside Elementor, WPML, MailPoet and Breakdance, so it sits on most
// WordPress hosts many times over. It concatenates a template it just compiled,
// with no decode step, which is the whole distinction the rule rests on.
func TestBackdoorHtmlmodeEval_TwigStyleLocalTemplate(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
final class Environment {
    public function render($name, array $context = [])
    {
        $source = $this->getLoader()->getSourceContext($name)->getCode();
        return eval('?>' . $source);
    }
}
`)

	if hasRule(scanner.ScanContent(legit, ".php"), "backdoor_htmlmode_eval") {
		t.Error("backdoor_htmlmode_eval FP: a local template evaluator is not a backdoor")
	}
}

// A remote fetch in the same file must not carry the rule on its own. Provenance
// by proximity is what an attacker defeats by splitting the URL or moving it,
// so the rule does not use it; this pins that decision down.
func TestBackdoorHtmlmodeEval_RemoteFetchAloneIsNotEnough(t *testing.T) {
	scanner := loadRepoScanner(t)

	samples := map[string]string{
		"url near a local template eval": `<?php
$url = 'https://api.example.test/data';
$response = curl_exec($client);
$template = file_get_contents(__DIR__ . '/views/page.tpl');
eval('?>' . $template);`,
		"http client beside a compiler": `<?php
function request($url) { return curl_exec(curl_init($url)); }
$response = request('https://api.example.test/data');
function render($path) { return eval('?>' . file_get_contents($path)); }`,
	}

	for name, sample := range samples {
		t.Run(name, func(t *testing.T) {
			if hasRule(scanner.ScanContent([]byte(sample), ".php"), "backdoor_htmlmode_eval") {
				t.Errorf("backdoor_htmlmode_eval FP: %s has no runtime rebuild", name)
			}
		})
	}
}
