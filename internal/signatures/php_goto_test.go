package signatures

import (
	"fmt"
	"strings"
	"testing"
)

type phpGotoCase struct {
	name    string
	content string
	want    bool
}

func phpGotoCases() []phpGotoCase {
	numeric := []string{"kZV1Kx", "KjJ0Ox", "OYs2Sx", "xE0Vh", "uM3nr", "HJ9Pd", "SN1Yf", "v4G86", "Qd12X", "Bn77p", "Tr4Kq", "Lm90z"}
	alpha := []string{"kZVIK", "KjJOO", "OYsSS", "xEVVh", "uMMnr", "HJPPd", "SNlYf", "vGGGG", "QdIIX", "BnTTp", "TrKKq", "LmOOz"}
	program := func(open string, labels []string, separator, payload string) string {
		var b strings.Builder
		b.WriteString(open)
		for _, label := range labels {
			fmt.Fprintf(&b, "goto %s;%s%s: ", label, separator, label)
		}
		b.WriteString(payload)
		return b.String()
	}
	var cases []phpGotoCase
	add := func(name, content string, want bool) {
		cases = append(cases, phpGotoCase{name, content, want})
	}
	for _, shape := range []struct {
		name   string
		labels []string
	}{
		{"numeric", numeric}, {"alphabetic", alpha},
	} {
		for _, layout := range []struct{ name, separator string }{{"minified", " "}, {"multiline", "\n"}} {
			prefix := shape.name + "/" + layout.name + "/"
			for _, sample := range []struct{ name, payload string }{
				{"no sink", `$this->register();`},
				{"data URI", `$icon = 'data:image/png;base64,` + strings.Repeat("QUJD", 40) + `'; echo $icon;`},
				{"asset string", `$asset = '/assets/` + strings.Repeat("abcdef0123456789", 10) + `.svg'; echo $asset;`},
				{"lowercase non superglobal", `$value = $_post['setting'];`},
				{"static include", `require_once __DIR__ . '/bootstrap.php';`},
				{"include option", `$options = ['include' => ['module'], 'require' => true];`},
			} {
				add(prefix+sample.name, program("<?php ", shape.labels, layout.separator, sample.payload), false)
			}
			for _, sample := range []struct{ name, payload string }{
				// The split-name examples must not depend on request input,
				// a named decoder, or a long encoded string to pass the gate.
				{"indirect variable argument", `$f = 'sys' . 'tem'; $x = 'printf probe'; $f($x);`},
				{"indirect literal argument", `$f = 'sys' . 'tem'; $f('printf probe');`},
				{"indirect grouped call", `$f = 'sys' . 'tem'; ($f)('printf probe');`},
				{"indirect array call", `$f = ['sys' . 'tem']; $f[0]('printf probe');`},
				{"indirect dispatcher", `$f = 'sys' . 'tem'; call_user_func($f, 'printf probe');`},
				{"include payload", `include $payload;`},
				{"commented direct call", `eval /* dispatch */ ($x);`},
				{"commented indirect call", `$f = 'sys' . 'tem'; $f /* dispatch */ ('printf probe');`},
				{"line commented call", "eval // dispatch\n($x);"},
				{"hash commented call", "eval # dispatch\n($x);"},
				{"payload alongside asset", `$icon = 'data:image/png;base64,` + strings.Repeat("QUJD", 40) + `'; $f = 'sys' . 'tem'; $f('printf probe');`},
			} {
				add(prefix+sample.name, program("<?php ", shape.labels, layout.separator, sample.payload), true)
			}
		}
	}
	for _, sink := range []string{"eval", "assert", "create_function", "system", "exec", "passthru", "shell_exec", "proc_open", "popen", "pcntl_exec", "base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "hex2bin", "convert_uudecode", "call_user_func", "call_user_func_array"} {
		add("named sink/"+sink, program("<?php ", numeric, " ", sink+"($x);"), true)
	}
	for _, input := range []string{"GET", "POST", "REQUEST", "COOKIE", "FILES"} {
		add("request/"+input, program("<?php ", numeric, " ", "$x = $_"+input+"['x'];"), true)
	}
	for _, open := range []string{"<?php ", "<? ", "<?= "} {
		// The echo tag needs an expression before the first goto statement.
		prefix := open
		if open == "<?= " {
			prefix += "0; "
		}
		add("PHP tag/"+open, program(prefix, numeric, " ", "eval($x);"), true)
	}
	for _, open := range []string{"", "<?phpunit "} {
		add("no PHP tag/"+open, program(open, numeric, " ", "eval($x);"), false)
	}
	add("numeric below threshold", program("<?php ", numeric[:8], " ", "eval($x);"), false)
	add("numeric threshold", program("<?php ", numeric[:9], " ", "eval($x);"), true)
	add("alphabetic below threshold", program("<?php ", alpha[:10], " ", "eval($x);"), false)
	add("alphabetic threshold", program("<?php ", alpha[:11], " ", "eval($x);"), true)
	mixed := append(append([]string{}, numeric[:5]...), alpha[:6]...)
	add("independent label thresholds", program("<?php ", mixed, " ", "eval($x);"), false)
	add("readable labels", program("<?php ", []string{"process_one", "process_two", "process_three", "process_four", "process_five", "process_six", "process_seven", "process_eight", "process_nine", "process_ten", "process_eleven"}, " ", "$value = $_POST['option'];"), false)
	add("mixed case keywords", strings.ReplaceAll(program("<?php ", numeric, " ", "EvAl($x);"), "goto ", "GoTo "), true)
	add("whitespace before semicolon", strings.ReplaceAll(program("<?php ", numeric, "\n", "eval($x);"), ";", " ;"), true)
	add("goto identifier suffix", strings.ReplaceAll(program("<?php ", numeric, " ", "eval($x);"), "goto ", "notgoto "), false)
	add("sink without gotos", "<?php eval($x);", false)
	return cases
}

func TestPHPGotoYAML(t *testing.T) {
	s := loadRepoScanner(t)
	if err := s.LoadError(); err != nil {
		t.Fatal(err)
	}
	for _, sample := range phpGotoCases() {
		t.Run(sample.name, func(t *testing.T) {
			got := hasRule(s.ScanContent([]byte(sample.content), ".php"), "php_goto_obfuscation")
			if got != sample.want {
				t.Errorf("php_goto_obfuscation match = %t, want %t", got, sample.want)
			}
		})
	}
}
