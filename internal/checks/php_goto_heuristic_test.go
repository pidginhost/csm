package checks

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
	"gopkg.in/yaml.v3"
)

func hasGotoIndicator(res phpAnalysisResult) bool {
	for _, ind := range res.indicators {
		if strings.Contains(ind, "goto") {
			return true
		}
	}
	return false
}

func TestGotoEvidenceMatchesShippedSignature(t *testing.T) {
	data, err := os.ReadFile("../../configs/malware.yml")
	if err != nil {
		t.Fatal(err)
	}
	var rules signatures.RuleFile
	if err := yaml.Unmarshal(data, &rules); err != nil {
		t.Fatal(err)
	}
	var evidence *regexp.Regexp
	for _, rule := range rules.Rules {
		if rule.Name == "php_goto_obfuscation" {
			if len(rule.Regexes) != 3 {
				t.Fatal("expected PHP context, density and evidence expressions")
			}
			evidence = regexp.MustCompile("(?i)" + rule.Regexes[2])
		}
	}
	if evidence == nil {
		t.Fatal("missing goto signature")
	}
	if reGotoExecSink.String() != evidence.String() {
		t.Error("Go goto evidence expression drifted from the shipped signature")
	}
	for _, tc := range []struct {
		payload string
		want    bool
	}{
		{`eval /* dispatch */ ($x);`, true},
		{"eval // dispatch\n($x);", true},
		{"eval # dispatch\n($x);", true},
		{`($f)('probe');`, true},
		{`$f[0]('probe');`, true},
		{`$f /* dispatch */ ('probe');`, true},
		{`require_once /* payload */ ($file);`, true},
		{`$x = $_POST['x'];`, true},
		{`$x = $_post['x'];`, false},
		{`$x = $_Post['x'];`, false},
		{`call_user_func($cfg['bootstrap']);`, false},
		{`CALL_USER_FUNC /* dispatch */ ($cfg['bootstrap']);`, false},
		{`call_user_func_array($cfg['bootstrap'], []);`, false},
	} {
		t.Run(tc.payload, func(t *testing.T) {
			if got := evidence.MatchString(tc.payload); got != tc.want {
				t.Fatalf("signature evidence = %t, want %t", got, tc.want)
			}
			for _, label := range []string{"x0A9k", "stage_alpha"} {
				content := "<?php " + strings.Repeat("goto "+label+"; ", 14) + tc.payload
				if got := hasGotoIndicator(analyzePHPCode("/sample.php", content, true)); got != tc.want {
					t.Errorf("label %s: goto indicator = %t, want %t", label, got, tc.want)
				}
			}
		})
	}
}

// WordPress core's HTML API implements the HTML5 spec's insertion modes as a
// state machine driven by goto, with labels named after the spec sections.
// Counting goto statements alone therefore flags authentic WordPress core on
// every site on the server: nine accounts on one host, each reporting the same
// unmodified file.
//
// Descriptive labels are evidence against obfuscation, not for it. An
// obfuscator emits machine-generated labels precisely because they carry no
// meaning. The YARA rule covering this same behaviour already makes that
// distinction; the Go heuristic did not.
func TestAnalyzePHPCodeIgnoresStateMachineGotos(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php\n")
	for _, label := range []string{
		"initial", "before_html", "before_head", "in_head", "after_head",
		"in_body", "after_body", "after_after_body", "in_table", "in_caption",
		"in_column_group", "in_table_body", "in_row", "in_cell", "in_select",
		"in_template", "in_frameset", "after_frameset", "anything_else",
	} {
		fmt.Fprintf(&b, "  goto %s_anything_else;\n", label)
	}

	res := analyzePHPCode("/var/www/wp-includes/html-api/class-wp-html-processor.php", b.String(), true)
	if hasGotoIndicator(res) {
		t.Errorf("descriptive state-machine labels reported as obfuscation: %v", res.indicators)
	}
}

// Machine-generated labels plus a sink are the actual obfuscator signature.
//
// Label shape alone is not, which is the correction this test carries:
// commercial obfuscators sold to plugin vendors emit exactly these labels
// and ship no payload, so a plugin bought off a marketplace looked the same
// as a dropper. The sink is what separates them.
func TestAnalyzePHPCodeFlagsGeneratedGotoLabels(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php\n")
	for i := 0; i < 14; i++ {
		fmt.Fprintf(&b, "  goto x%dA9k;\n", i)
	}
	b.WriteString("  eval($_POST['x']);\n")

	res := analyzePHPCode("/home/acct/public_html/shell.php", b.String(), true)
	if !hasGotoIndicator(res) {
		t.Errorf("machine-generated goto labels not reported: %v", res.indicators)
	}
}

// A vendor loader scrambled by a commercial obfuscator: generated labels,
// its own callables, nothing to decode or execute.
func TestAnalyzePHPCodeIgnoresGeneratedGotosWithoutSink(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php\n")
	for i := 0; i < 14; i++ {
		fmt.Fprintf(&b, "  goto x%dA9k; x%dA9k: $this->step();\n", i, i)
	}
	b.WriteString("  $boot = call_user_func($cfg['bootstrap']);\n")

	res := analyzePHPCode("/home/acct/public_html/wp-content/plugins/vendor/loader.php", b.String(), true)
	if hasGotoIndicator(res) {
		t.Errorf("vendor-obfuscated loader reported as obfuscation: %v", res.indicators)
	}
}

// Descriptive labels plus an execution sink is the other real arm: obfuscators
// that bother to pick word-like labels still have to reach a sink.
func TestAnalyzePHPCodeFlagsDescriptiveGotosWithExecSink(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php\n")
	for i := 0; i < 14; i++ {
		fmt.Fprintf(&b, "  goto stage_%s;\n", strings.Repeat("a", i%5+3))
	}
	b.WriteString("  eval(base64_decode($payload));\n")

	res := analyzePHPCode("/home/acct/public_html/loader.php", b.String(), true)
	if !hasGotoIndicator(res) {
		t.Errorf("descriptive gotos reaching an execution sink not reported: %v", res.indicators)
	}
}
