package phptaint

import (
	"strings"
	"testing"

	"github.com/VKCOM/php-parser/pkg/ast"
)

func firstCall(t *testing.T, src string) *ast.ExprFunctionCall {
	t.Helper()
	root, status, reason := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	f := collectScope(root)
	if len(f.callNodes) == 0 {
		t.Fatal("no call collected")
	}
	return f.callNodes[0]
}

func TestAlwaysRemoteSourcesAreHighConfidence(t *testing.T) {
	for _, src := range []string{
		"<?php curl_exec($c);",
		"<?php curl_multi_getcontent($c);",
		"<?php wp_remote_retrieve_body($r);",
	} {
		conf, ok := sourceConfidence(firstCall(t, src))
		if !ok {
			t.Fatalf("%s: not recognised as a source", src)
		}
		if conf != ConfidenceHigh {
			t.Errorf("%s: confidence = %v, want High", src, conf)
		}
	}
}

func TestProvablyLocalPathIsNotASource(t *testing.T) {
	for _, src := range []string{
		"<?php file_get_contents('/etc/hosts');",
		"<?php file_get_contents(__DIR__ . '/config.php');",
		"<?php readfile(dirname(__FILE__) . '/x.html');",
		"<?php file_get_contents(ABSPATH . 'wp-config.php');",
	} {
		if _, ok := sourceConfidence(firstCall(t, src)); ok {
			t.Errorf("%s: treated as a remote source, want not a source", src)
		}
	}
}

func TestProvablyRemoteSchemeIsHighConfidence(t *testing.T) {
	for _, src := range []string{
		"<?php file_get_contents('http://host/x');",
		"<?php file_get_contents('https://host/x');",
		"<?php file_get_contents('php://input');",
		"<?php file_get_contents('ht' . 'tp://host/x');",
	} {
		conf, ok := sourceConfidence(firstCall(t, src))
		if !ok {
			t.Fatalf("%s: not recognised as a source", src)
		}
		if conf != ConfidenceHigh {
			t.Errorf("%s: confidence = %v, want High", src, conf)
		}
	}
}

func TestStaticTextDepthBoundDoesNotOverflow(t *testing.T) {
	// A Go stack overflow is fatal and unrecoverable, so deeply nested
	// concatenation must degrade to "undecidable", not crash the process.
	src := "<?php file_get_contents('a'" + strings.Repeat(" . 'a'", 100000) + ");"
	root, status, _ := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Skip("generator produced unparseable source")
	}
	f := collectScope(root)
	if len(f.callNodes) == 0 {
		t.Fatal("no call collected")
	}
	if _, ok := sourceConfidence(f.callNodes[0]); !ok {
		t.Error("want an undecidable argument to remain a reduced-confidence source")
	}
}

func TestUnknownLocalityIsLowConfidenceSource(t *testing.T) {
	conf, ok := sourceConfidence(firstCall(t, "<?php file_get_contents($u);"))
	if !ok {
		t.Fatal("variable argument: want a source at reduced confidence")
	}
	if conf != ConfidenceLow {
		t.Errorf("confidence = %v, want Low", conf)
	}
}
