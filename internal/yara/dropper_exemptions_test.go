//go:build yara

package yara

import (
	"strings"
	"testing"
)

const conditionalStaticUploader = `<?php
if (false) if (!defined('_FW_VERSION_')) { exit; }
class ImportMap {
    public static function save() {
        $dest = __DIR__ . '/out/' . basename($_FILES['f']['name']);
        move_uploaded_file($_FILES['f']['tmp_name'], $dest /* $this->path */);
    }
}
ImportMap::save();
`

func TestUploaderClassExemptionRejectsExecutableFiles(t *testing.T) {
	s := loadRepoYaraScanner(t)
	guard := "if (!defined('_FW_VERSION_')) { exit; }\n"
	// Deserialization creates the object without a 'new' expression.
	invoke := "$u = unserialize('O:9:\"ImportMap\":0:{}'); $u->save('x');\n"
	for name, sample := range map[string]string{
		"conditional guard and static invocation": conditionalStaticUploader,
		"commented guard":                         "<?php /* " + guard + " */ " + guardedImportClass + invoke,
		"line comment guard":                      "<?php // if (!defined('_FW_VERSION_')) { exit; }\n" + guardedImportClass + invoke,
		"conditional guard":                       "<?php if (false) " + guard + guardedImportClass + invoke,
		"late guard":                              "<?php define('_FW_VERSION_', 1); " + guard + guardedImportClass + invoke,
		"guard with expression and invocation":    "<?php defined('_FW_VERSION_') or die && false;\n" + guardedImportClass + invoke,
		"include invokes existing object":         guardedImportHeader + guard + guardedImportClass + "$importer->save('x');\n",
		"include deserializes object":             guardedImportHeader + guard + guardedImportClass + invoke,
		"closure invokes object":                  guardedImportHeader + guard + guardedImportClass + "(function () { global $importer; $importer->save('x'); })();\n",
		"registered hook":                         guardedImportHeader + guard + guardedImportClass + "add_action('init', [$importer, 'save']);\n",
		"PHP after closing tag":                   guardedImportHeader + guard + guardedImportClass + "?><?PHP " + invoke,
		"short tag after class":                   guardedImportHeader + guard + guardedImportClass + "?><? " + invoke,
		"class in comment, upload outside":        guardedImportHeader + guard + "/* class Decoy {} */\nmove_uploaded_file($_FILES['f']['tmp_name'], $this->path($_POST['name']));\n",
		"static method called after class": guardedImportHeader + guard + `class ImportMap {
    public static function save() {
        $dest = $_POST['name'];
        move_uploaded_file($_FILES['f']['tmp_name'], $dest /* $this->path */);
    }
}

ImportMap::save();`,
		"comment brace cannot hide class end": guardedImportHeader + guard + strings.Replace(guardedImportClass, "private $errors", "/* { */ private $errors", 1) + invoke + "// }\n",
		"comment quote cannot hide class end": guardedImportHeader + guard + strings.Replace(guardedImportClass, "private $errors", "/* ' */ private $errors", 1) + invoke + "// '\n",
	} {
		t.Run(name, func(t *testing.T) {
			matches, err := s.ScanBytesChecked([]byte(sample))
			if err != nil {
				t.Fatal(err)
			}
			if !hasYaraRule(matches, "dropper_uploader_no_auth") {
				t.Fatal("executable uploader hidden by class exemption")
			}
		})
	}
}

// PHP 5 can leave PHP mode at an ASP closer, including in a line comment.
// These tokens must not be consumed as ordinary class-body text or trivia.
func TestUploaderClassExemptionRejectsLegacyClosers(t *testing.T) {
	s := loadRepoYaraScanner(t)
	for _, token := range []string{"%>", "// %>text\n", "# %>text\n"} {
		sample := guardedImportHeader + "defined('_FW_VERSION_') or die;\n" +
			strings.Replace(guardedImportClass, "return true;", "return true; "+token, 1)
		matches, err := s.ScanBytesChecked([]byte(sample))
		if err != nil {
			t.Fatal(err)
		}
		if !hasYaraRule(matches, "dropper_uploader_no_auth") {
			t.Errorf("legacy closer %q accepted inside class exemption", token)
		}
	}
}

func TestUploaderClassExemptionRequiresInstanceDestination(t *testing.T) {
	s := loadRepoYaraScanner(t)
	for _, destination := range []string{
		"$dest /* $this->path */",
		"'/tmp/$this->path'",
		"$dest . '$this->path'",
	} {
		sample := guardedImportHeader + "defined('_FW_VERSION_') or die;\n" +
			strings.Replace(guardedImportClass, "$this->path($name)", destination, 1)
		matches, err := s.ScanBytesChecked([]byte(sample))
		if err != nil {
			t.Fatal(err)
		}
		if !hasYaraRule(matches, "dropper_uploader_no_auth") {
			t.Errorf("non-instance destination %q was exempted", destination)
		}
	}
}

func TestUploaderClassExemptionTrivia(t *testing.T) {
	s := loadRepoYaraScanner(t)
	for _, prefix := range []string{"<?php\n", "<?PHP\n", "\xef\xbb\xbf \t\r\n<?php\n"} {
		for _, comment := range []string{"", "/* braces { } and quotes '\" */\n", "// { \"\n", "# } '\n"} {
			for _, guard := range []string{"if (!defined('_FW_VERSION_')) { exit; }", "defined('_FW_VERSION_') or die('Restricted access');"} {
				body := strings.Replace(guardedImportClass, "private $errors", comment+"private $errors", 1)
				sample := prefix + comment + guard + "\n" + body + comment
				matches, err := s.ScanBytesChecked([]byte(sample))
				if err != nil {
					t.Fatal(err)
				}
				if hasYaraRule(matches, "dropper_uploader_no_auth") {
					t.Errorf("declaration-only class rejected: prefix %q, comment %q", prefix, comment)
				}
			}
		}
	}
}

// Comparison, ternary and null-coalescing operators are ordinary class code,
// but no operator may consume a PHP opener or closer next to it.
func TestUploaderClassExemptionOperators(t *testing.T) {
	s := loadRepoYaraScanner(t)
	guard := "defined('_FW_VERSION_') or die;\n"
	for name, tc := range map[string]struct {
		code string
		want bool
	}{
		"less than":          {code: "$ok = $a < $b;"},
		"less or equal":      {code: "$ok = $a <= $b;"},
		"spaceship":          {code: "$ok = $a <=> $b;"},
		"ternary":            {code: "$ok = $a ? 1 : 2;"},
		"null coalescing":    {code: "$ok = $a ?? $b;"},
		"nullsafe call":      {code: "$ok = $a?->b();"},
		"closer after ?":     {code: "$ok = $a ?>x<?php ;", want: true},
		"closer after ??":    {code: "$ok = $a ??>x<?php ;", want: true},
		"opener after <":     {code: "$ok = $a <<?php ;", want: true},
		"short echo after <": {code: "$ok = $a <<?= 1 ?>;", want: true},
		"heredoc":            {code: "$ok = <<<EOT\nx\nEOT;", want: true},
	} {
		t.Run(name, func(t *testing.T) {
			sample := guardedImportHeader + guard + strings.Replace(guardedImportClass, "return true;", tc.code+"\n        return true;", 1)
			matches, err := s.ScanBytesChecked([]byte(sample))
			if err != nil {
				t.Fatal(err)
			}
			if got := hasYaraRule(matches, "dropper_uploader_no_auth"); got != tc.want {
				t.Errorf("dropper_uploader_no_auth matched = %t, want %t", got, tc.want)
			}
		})
	}
}
