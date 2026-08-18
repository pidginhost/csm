package phptaint

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// hostileSeeds are hostile inputs designed to exercise the parser and panic
// boundary, base64-encoded so no plaintext dropper is written to disk.
// Each seed combines a hostile syntax shape with both a sink (eval, include,
// etc.) and source (curl_exec, file_get_contents, etc.) keyword so it passes
// the pre-filter and reaches the parser.
var hostileSeeds = []string{
	// Deeply nested parens: eval(curl_exec( + 50000 parens + ))
	base64.StdEncoding.EncodeToString([]byte("<?php eval(curl_exec(" + strings.Repeat("(", 50000) + "));")),
	// Truncated mid-call: eval(file_get_contents( with no closing paren
	base64.StdEncoding.EncodeToString([]byte("<?php eval(file_get_contents(")),
	// Null bytes and invalid UTF-8: eval(curl_exec($c)); + null bytes + invalid UTF-8
	base64.StdEncoding.EncodeToString([]byte("<?php eval(curl_exec($c));\x00\x00\xff\xfe\xfd")),
	// Long repetitive code after the call: eval(curl_exec($c)); + 20000 statements
	base64.StdEncoding.EncodeToString([]byte("<?php eval(curl_exec($c));" + strings.Repeat("$a=1;", 20000))),
	// Huge single token: eval(curl_exec($ident) where ident is ~100K
	base64.StdEncoding.EncodeToString([]byte("<?php eval(curl_exec($" + strings.Repeat("a", 100000) + "));")),
	// Unterminated string: eval(file_get_contents('abc
	base64.StdEncoding.EncodeToString([]byte("<?php eval(file_get_contents('abc")),
	// Unterminated comment: eval(curl_exec(/*comment
	base64.StdEncoding.EncodeToString([]byte("<?php eval(curl_exec(/*comment")),
	// Multiple sources and sinks: include(fopen(fgets(curl_exec(...
	base64.StdEncoding.EncodeToString([]byte("<?php include(fopen(fgets(curl_exec(")),
	// require with wp_remote_get: require(wp_remote_get(
	base64.StdEncoding.EncodeToString([]byte("<?php require(wp_remote_get(")),
	// assert with stream_get_contents: assert(stream_get_contents(
	base64.StdEncoding.EncodeToString([]byte("<?php assert(stream_get_contents(")),
	// Non-candidate seeds (pre-filter rejection path): keep coverage
	base64.StdEncoding.EncodeToString([]byte("")),
	base64.StdEncoding.EncodeToString([]byte("<?php")),
	base64.StdEncoding.EncodeToString([]byte("?>")),
}

func TestAnalyzeSurvivesHostileInput(t *testing.T) {
	reachedParser := false
	for i, seed := range hostileSeeds {
		src, err := base64.StdEncoding.DecodeString(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		rep := Analyze(context.Background(), src)
		if rep.Status == StatusAnalyzed && len(rep.Results) > 0 {
			t.Errorf("seed %d reported a flow in non-flow input", i)
		}
		if rep.Status != StatusAnalyzed && len(rep.Results) != 0 {
			t.Errorf("seed %d: coverage gap carried %d results", i, len(rep.Results))
		}
		// Track whether any seed passed the pre-filter and reached parseSource.
		if rep.Status != StatusNotCandidate {
			reachedParser = true
		}
	}
	if !reachedParser {
		t.Fatalf("no seed reached the parser; all rejected by pre-filter")
	}
}

func TestRecoveredCatchesPanic(t *testing.T) {
	rep := recovered(func() Report {
		panic("test panic value")
	})
	if rep.Status != StatusPanic {
		t.Errorf("recovered panic produced status %v, want StatusPanic", rep.Status)
	}
	if len(rep.Results) != 0 {
		t.Errorf("recovered panic report carried %d results, want 0", len(rep.Results))
	}
	if len(rep.Reason) == 0 {
		t.Errorf("recovered panic report has empty Reason, want non-empty")
	}
	if len(rep.Reason) > MaxReasonBytes {
		t.Errorf("recovered panic Reason %d bytes exceeds MaxReasonBytes %d", len(rep.Reason), MaxReasonBytes)
	}
	if !strings.Contains(rep.Reason, "test panic value") {
		t.Errorf("recovered panic Reason %q does not contain panic value", rep.Reason)
	}
}

func FuzzAnalyze(f *testing.F) {
	for _, seed := range hostileSeeds {
		src, err := base64.StdEncoding.DecodeString(seed)
		if err != nil {
			continue
		}
		f.Add(src)
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		rep := Analyze(context.Background(), src)
		if rep.Status != StatusAnalyzed && len(rep.Results) != 0 {
			t.Fatalf("status %v carried %d results", rep.Status, len(rep.Results))
		}
		if len(rep.Reason) > MaxReasonBytes {
			t.Fatalf("reason %d bytes exceeds cap", len(rep.Reason))
		}
	})
}
