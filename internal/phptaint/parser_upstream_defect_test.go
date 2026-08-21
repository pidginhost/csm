package phptaint

import (
	"context"
	"strings"
	"testing"
)

// TestUnbalancedCloseBracePanicsUpstream pins a defect in
// github.com/VKCOM/php-parser v0.8.2: a PHP open tag followed anywhere by an
// unmatched "}" makes the lexer pop an empty state stack and panic with
// "index out of range [0] with length 0" (internal/php8/lexer.go:214, reached
// from scanner.go Lex).
//
// v0.8.2 is the newest published version, so there is no upgrade to take. The
// analyzer contains the panic and reports the file as a coverage gap rather
// than crashing, which is why this is a correctness limit and not an outage.
//
// Two consequences worth keeping visible:
//
//   - It is NOT limited to binary input. "<?php }" panics, so any PHP file
//     carrying a stray closing brace is never analyzed. That is an evasion
//     vector: appending one byte to a payload defeats this analyzer, though the
//     file still reaches the YARA consumer and is still reported as a gap.
//   - It was found on translation catalogues, whose binary string tables happen
//     to contain "<?" followed later by "}".
//
// If this test starts failing, the upstream defect is fixed: drop the
// workaround discussion in the plan and re-evaluate the gap volume.
func TestUnbalancedCloseBracePanicsUpstream(t *testing.T) {
	panics := func(src string) (p bool) {
		defer func() {
			if r := recover(); r != nil {
				p = true
			}
		}()
		_, _, _ = parseSource([]byte(src))
		return false
	}

	// The minimal trigger, reduced from a 931 KB WooCommerce .mo catalogue.
	if !panics("<?}") {
		t.Error(`upstream parser no longer panics on "<?}" -- see the doc comment`)
	}
	for _, src := range []string{"<?php}", "<?=}", "<? }", "<?\n}", "<?php echo 1; }"} {
		if !panics(src) {
			t.Errorf("upstream parser no longer panics on %q -- see the doc comment", src)
		}
	}
	// Other unbalanced closers are handled cleanly; only "}" pops the state
	// stack. This bounds the defect so a future fix can be recognised.
	for _, src := range []string{"<?{", "<?)", "<?]"} {
		if panics(src) {
			t.Errorf("upstream parser now panics on %q, widening the known defect", src)
		}
	}
}

// TestAnalyzeContainsTheUpstreamPanic proves the package boundary degrades the
// upstream defect to a reported coverage gap instead of propagating it.
func TestAnalyzeContainsTheUpstreamPanic(t *testing.T) {
	src := []byte("<?php $x = curl_exec($c); eval($x); }")
	report := Analyze(context.Background(), src)
	if report.Status != StatusPanic {
		t.Fatalf("status = %s, want %s", report.Status, StatusPanic)
	}
	if len(report.Results) != 0 {
		t.Errorf("a contained panic must carry no findings, got %d", len(report.Results))
	}
	// The panic value can quote source text, so it must not reach the report.
	if strings.Contains(report.Reason, "curl_exec") || strings.Contains(report.Reason, "index out of range") {
		t.Errorf("report reason leaks panic or source detail: %q", report.Reason)
	}
}
