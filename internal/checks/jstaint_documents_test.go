package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestJSTaintDeepClassifiesContentWithoutTrustingExtensions(t *testing.T) {
	useRollingStore(t)
	useNilYARABackend(t)
	root := t.TempDir()
	for name, src := range map[string]string{
		"template.php": `<html><?php $src = 1; ?><script>onkeydown=()=>fetch('/')</script></html>`,
		"bundle.map":   `{"sourcesContent":["document.onkeydown=e=>fetch(e.key)"]}`,
		"style.css":    `.onkeydown { background: url('/src/image.png'); }`,
		"locale.po":    "msgid \"keydown\"\nmsgstr \"send\"\n",
	} {
		writeYARADeepFile(t, root, name, src)
	}
	// A data extension cannot hide real JavaScript, including a PHP marker
	// inside a comment. Only the malformed script should create a coverage gap.
	malicious := writeYARADeepFile(t, root, "payload.json", "/* <?php */\n"+jsKeyloggerFixture)
	broken := writeYARADeepFile(t, root, "broken.js", `document.onkeydown=e=>fetch(e.key`)
	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)
	flows := jsFindingsByCheck(findings, "js_keylogger_dataflow")
	if len(flows) != 1 || flows[0].FilePath != malicious {
		t.Fatalf("flows = %+v, want one at %s", flows, malicious)
	}
	gaps := jsFindingsByCheck(findings, "js_taint_scan_incomplete")
	if len(gaps) != 1 || gaps[0].Message != "JavaScript taint deep scan could not analyze 1 file(s)" ||
		gaps[0].Details != "parse_error=1 (example: "+broken+")" {
		t.Fatalf("gaps = %+v, want only the malformed script", gaps)
	}
}
