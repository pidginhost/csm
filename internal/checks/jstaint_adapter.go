package checks

import (
	"context"
	"time"

	"github.com/pidginhost/csm/internal/jstaint"
)

// jsTaintAnalyze is indirected so tests can substitute the analyzer at the
// adapter boundary: forcing a panic or a specific status proves each owner's
// containment without crafting pathological JavaScript.
var jsTaintAnalyze = jstaint.Analyze

// jsTaintReverifyTimeout is the per-file safety net for a re-verification
// analysis. The analyzer checks its context between AST nodes, and its node,
// depth, and fact caps bound normal work far below this; the deadline only
// stops a defect from stalling an operator-triggered re-check.
const jsTaintReverifyTimeout = 15 * time.Second

// runJSTaintAnalysis is the adapter recovery boundary around the analyzer
// call. The analyzer converts its own internal panics to StatusPanic, but a
// panic in adapter-side code around the call must have the same contained
// outcome instead of escaping through the owning check.
func runJSTaintAnalysis(ctx context.Context, data []byte) (report jstaint.Report) {
	defer func() {
		if r := recover(); r != nil {
			report = jstaint.Report{Status: jstaint.StatusPanic, Reason: "panic"}
		}
	}()
	return jsTaintAnalyze(ctx, data)
}
