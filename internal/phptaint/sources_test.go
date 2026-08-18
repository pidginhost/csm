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
		"<?php wp_remote_get($url);",
		"<?php wp_remote_retrieve_body($r);",
		"<?php fsockopen($host);",
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
		"<?php file_get_contents((__DIR__ . '/config.php'));",
		"<?php file_get_contents(__DIR__ . '/config.php');",
		"<?php fopen(dirname(__FILE__) . '/x.html', 'r');",
		"<?php file_get_contents(ABSPATH . 'wp-config.php');",
	} {
		if _, ok := sourceConfidence(firstCall(t, src)); ok {
			t.Errorf("%s: treated as a remote source, want not a source", src)
		}
	}
}

func TestUnknownConstantsAndPathInputsRemainSources(t *testing.T) {
	for _, src := range []string{
		"<?php file_get_contents(REMOTE_URL);",
		"<?php file_get_contents(dirname($base) . '/payload');",
		`<?php file_get_contents("htt\x70://host/payload");`,
	} {
		conf, ok := sourceConfidence(firstCall(t, src))
		if !ok {
			t.Errorf("%s: undecidable argument was misclassified as local", src)
			continue
		}
		if conf != ConfidenceLow {
			t.Errorf("%s: confidence = %v, want Low", src, conf)
		}
	}
}

func TestRemoteLiteralFragmentSurvivesDynamicConcat(t *testing.T) {
	conf, ok := sourceConfidence(firstCall(t, "<?php file_get_contents('http://' . $host . '/payload');"))
	if !ok || conf != ConfidenceHigh {
		t.Errorf("confidence = %v source=%t, want High source", conf, ok)
	}
}

func TestUnknownConcatPieceDoesNotInventRemoteScheme(t *testing.T) {
	conf, ok := sourceConfidence(firstCall(t, "<?php file_get_contents('http' . $separator . '://host/payload');"))
	if !ok || conf != ConfidenceLow {
		t.Errorf("confidence = %v source=%t, want Low source", conf, ok)
	}
}

func TestPathTransformPreservesRemoteScheme(t *testing.T) {
	conf, ok := sourceConfidence(firstCall(t, "<?php file_get_contents(dirname('http://host/a') . '/payload');"))
	if !ok || conf != ConfidenceHigh {
		t.Errorf("confidence = %v source=%t, want High source", conf, ok)
	}
}

func TestOnlyRequestControlledPHPWrapperIsRemote(t *testing.T) {
	conf, ok := sourceConfidence(firstCall(t, "<?php file_get_contents('php://input');"))
	if !ok || conf != ConfidenceHigh {
		t.Errorf("php://input confidence = %v source=%t, want High source", conf, ok)
	}
	if _, memorySource := sourceConfidence(firstCall(t, "<?php file_get_contents('php://memory');")); memorySource {
		t.Error("php://memory was treated as remotely supplied content")
	}
	conf, ok = sourceConfidence(firstCall(t,
		"<?php file_get_contents('php://filter/convert.base64-decode/resource=https://host/payload');"))
	if !ok || conf != ConfidenceHigh {
		t.Errorf("remote php://filter confidence = %v source=%t, want High source", conf, ok)
	}
}

func TestProvablyRemoteSchemeIsHighConfidence(t *testing.T) {
	for _, src := range []string{
		"<?php file_get_contents('http://host/x');",
		"<?php file_get_contents('https://host/x');",
		"<?php file_get_contents('php://input');",
		"<?php file_get_contents('ht' . 'tp://host/x');",
		"<?php file_get_contents(('https://host/x'));",
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

func TestStreamReadersAreNotSourcesOnTheirOwn(t *testing.T) {
	// fread, fgets and stream_get_contents take a stream resource, never a
	// path, so their argument carries no locality signal. The acquiring
	// call (e.g. fopen) is the source; the handle stays tainted through the
	// variable, so these readers need no source status of their own.
	for _, src := range []string{
		"<?php fread($fh, 999);",
		"<?php fgets($fh);",
		"<?php stream_get_contents($fh);",
	} {
		if _, ok := sourceConfidence(firstCall(t, src)); ok {
			t.Errorf("%s: treated as a source, want not a source", src)
		}
	}
}

func TestReadfileByteCountIsNotAContentSource(t *testing.T) {
	if _, ok := sourceConfidence(firstCall(t, "<?php readfile('https://host/payload');")); ok {
		t.Error("readfile return value is a byte count, not remotely fetched content")
	}
}

func TestFopenRemoteURLIsHighConfidenceSource(t *testing.T) {
	// The intended pairing: fopen() on a remote URL is the source, and a
	// later fread($fh) detects via the tainted variable, not via its own
	// source status.
	conf, ok := sourceConfidence(firstCall(t, "<?php fopen('http://host/x', 'r');"))
	if !ok {
		t.Fatal("remote URL: want a source")
	}
	if conf != ConfidenceHigh {
		t.Errorf("confidence = %v, want High", conf)
	}
}
