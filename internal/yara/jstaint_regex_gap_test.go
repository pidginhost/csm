//go:build yara

package yara

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/jstaint"
)

// variableIndirectionKeyloggers are keylogger shapes whose captured keystroke
// reaches a network sink only through variable, buffer, callback, or helper
// indirection. A YARA-X byte-window rule cannot correlate the source and sink
// across that indirection, which needs backreferences YARA-X does not provide;
// the data-flow analyzer resolves it. This map is duplicated in
// internal/signatures so each regex engine is proven against the same shapes;
// keep the two copies identical.
var variableIndirectionKeyloggers = map[string]string{
	"two_scalar_hops": `document.addEventListener("keydown",function(e){var c=e.which;` +
		`var ch=String.fromCharCode(c);var out="";out+=ch;fetch("/c?k="+out);});`,
	"outer_scope_buffer": `var buf="";document.addEventListener("keydown",function(e){var k=e.key;buf+=k;});` +
		`setInterval(function(){var d=buf;navigator.sendBeacon("/c",d);},1000);`,
	"array_push_join": `document.onkeydown=function(e){var k=e.key;var a=[];a.push(k);` +
		`var s=a.join("");fetch("/c?u="+s);};`,
	"object_field_stringify": `document.onkeydown=function(e){var s={};s.k=e.key;` +
		`navigator.sendBeacon("/c",JSON.stringify(s));};`,
	"depth1_helper_sinks": `document.onkeydown=function(e){ship(e.key);};` +
		`function ship(v){fetch("/c?k="+v);}`,
	"depth1_helper_returns": `document.onkeydown=function(e){var x=enc(e.key);fetch("/c?k="+x);};` +
		`function enc(v){return btoa(v);}`,
}

// TestExfilKeyloggerRegexGap_YARA is the YARA half of the analyzer's
// justification: each variable-indirection keylogger is missed by the YARA
// exfil_keylogger_js rule yet detected by the analyzer. Together with the YAML
// half in internal/signatures it proves each shape is missed by both regex
// engines.
func TestExfilKeyloggerRegexGap_YARA(t *testing.T) {
	scanner := loadRepoYaraScanner(t)
	for name, src := range variableIndirectionKeyloggers {
		t.Run(name, func(t *testing.T) {
			if hasYaraRule(scanner.ScanBytes([]byte(src)), "exfil_keylogger_js") {
				t.Errorf("YARA exfil_keylogger_js matched %s; fixture no longer proves the regex gap", name)
			}
			rep := jstaint.Analyze(context.Background(), []byte(src))
			if rep.Status != jstaint.StatusAnalyzed || len(rep.Results) == 0 {
				t.Errorf("analyzer missed %s: status=%v results=%d", name, rep.Status, len(rep.Results))
			}
		})
	}
}
