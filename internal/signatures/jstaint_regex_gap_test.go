package signatures

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/jstaint"
)

// variableIndirectionKeyloggers are keylogger shapes whose captured keystroke
// reaches a network sink only through variable, buffer, callback, or helper
// indirection. A fixed byte-window regex cannot correlate the source and sink
// across that indirection, which needs backreferences that neither RE2 nor
// YARA-X provides; the data-flow analyzer resolves it. This map is duplicated in
// internal/yara so each regex engine is proven against the same shapes; keep the
// two copies identical.
var variableIndirectionKeyloggers = map[string]string{
	// One variable, two scalar hops, decoded through String.fromCharCode.
	"two_scalar_hops": `document.addEventListener("keydown",function(e){var c=e.which;` +
		`var ch=String.fromCharCode(c);var out="";out+=ch;fetch("/c?k="+out);});`,
	// An outer-scope buffer filled by a key handler and shipped by a separate
	// timer callback, each through a local hop.
	"outer_scope_buffer": `var buf="";document.addEventListener("keydown",function(e){var k=e.key;buf+=k;});` +
		`setInterval(function(){var d=buf;navigator.sendBeacon("/c",d);},1000);`,
	// A key pushed onto an array and later joined into the sent string.
	"array_push_join": `document.onkeydown=function(e){var k=e.key;var a=[];a.push(k);` +
		`var s=a.join("");fetch("/c?u="+s);};`,
	// A key stored in an object field and serialized into the beacon body.
	"object_field_stringify": `document.onkeydown=function(e){var s={};s.k=e.key;` +
		`navigator.sendBeacon("/c",JSON.stringify(s));};`,
	// A key passed into a same-file helper that contains the sink.
	"depth1_helper_sinks": `document.onkeydown=function(e){ship(e.key);};` +
		`function ship(v){fetch("/c?k="+v);}`,
	// A key laundered through a same-file helper that returns the tainted value.
	"depth1_helper_returns": `document.onkeydown=function(e){var x=enc(e.key);fetch("/c?k="+x);};` +
		`function enc(v){return btoa(v);}`,
}

// TestExfilKeyloggerRegexGap_YAML is the justification for the data-flow
// analyzer: each variable-indirection keylogger is missed by the YAML
// exfil_keylogger_js rule yet detected by the analyzer. If the rule ever starts
// matching one of these, the fixture no longer proves the gap and must be
// revisited rather than silently passing.
func TestExfilKeyloggerRegexGap_YAML(t *testing.T) {
	scanner := loadRepoScanner(t)
	for name, src := range variableIndirectionKeyloggers {
		t.Run(name, func(t *testing.T) {
			if hasRule(scanner.ScanContent([]byte(src), ".js"), "exfil_keylogger_js") {
				t.Errorf("YAML exfil_keylogger_js matched %s; fixture no longer proves the regex gap", name)
			}
			rep := jstaint.Analyze(context.Background(), []byte(src))
			if rep.Status != jstaint.StatusAnalyzed || len(rep.Results) == 0 {
				t.Errorf("analyzer missed %s: status=%v results=%d", name, rep.Status, len(rep.Results))
			}
		})
	}
}
