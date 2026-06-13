package checks

import (
	"strings"
	"testing"
	"time"
)

// A file can wrap an assert() argument in tens of thousands of parentheses.
// The classifier must not spend quadratic time (or unbounded stack) peeling
// them: it terminates promptly and leaves a bare request read flagged.
func TestHasCodeEvalPrimitiveDeepParensTerminatesFast(t *testing.T) {
	const depth = 100000
	code := "assert(" + strings.Repeat("(", depth) + "$_GET['x']" + strings.Repeat(")", depth) + ");"

	flagged := runCodeEvalPrimitiveWithTimeout(t, code)
	if !flagged {
		t.Error("deeply paren-wrapped assert($_GET) must stay flagged (fail closed)")
	}
}

func TestHasCodeEvalPrimitiveDeepParensPreservesBoolClassification(t *testing.T) {
	const depth = 100000
	code := "assert(" + strings.Repeat("(", depth) + "is_file($_GET['x'])" + strings.Repeat(")", depth) + ");"

	flagged := runCodeEvalPrimitiveWithTimeout(t, code)
	if flagged {
		t.Error("deeply paren-wrapped assert(is_file($_GET)) wrongly flagged")
	}
}

func runCodeEvalPrimitiveWithTimeout(t *testing.T, code string) bool {
	t.Helper()
	done := make(chan bool, 1)
	go func() {
		done <- hasCodeEvalPrimitiveWithRequest(code)
	}()

	select {
	case flagged := <-done:
		return flagged
	case <-time.After(5 * time.Second):
		t.Fatal("hasCodeEvalPrimitiveWithRequest did not finish within 5s on deeply nested parens (quadratic scan / unbounded recursion)")
	}
	return false
}
