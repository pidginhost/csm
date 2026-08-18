package phptaint

import (
	"sort"

	"github.com/VKCOM/php-parser/pkg/ast"
)

// precisionLossMarkers name calls that defeat static variable identity.
// extract() and compact() move values between named variables and an array
// at runtime; call_user_func(_array) dispatches through a value rather than
// a lexical name. Their presence is recorded so a caller knows coverage was
// reduced, rather than the loss passing silently.
var precisionLossMarkers = map[string]string{
	"extract":              "extract",
	"compact":              "compact",
	"call_user_func":       "dynamic-call",
	"call_user_func_array": "dynamic-call",
}

// funcBody pairs a summarizable function or method with its collected facts.
// Facts are collected once up front: they do not change across fixpoint
// rounds, only the summaries map consulted while interpreting them does.
type funcBody struct {
	name  string
	facts *scopeFacts
}

// functionSummaries reports which user-defined functions and methods return
// remotely-sourced data, computed to a fixpoint over the call graph, plus any
// precision-loss markers observed while collecting their bodies.
//
// This is what lets the analyzer see the motivating shape: a fetch in one
// function and a sink in another, joined only by a call. Without a summary
// for the fetching function, that flow is invisible to a single-scope pass.
func functionSummaries(f *scopeFacts) (map[string]Confidence, []string) {
	bodies := make([]funcBody, 0, len(f.funcs)+len(f.methods))
	for _, fn := range f.funcs {
		if len(bodies) >= maxSummarizedFuncs {
			break
		}
		bodies = append(bodies, funcBody{name: calleeName(fn.Name), facts: collectAll(fn.Stmts)})
	}
	for _, m := range f.methods {
		if len(bodies) >= maxSummarizedFuncs {
			break
		}
		// StmtClassMethod carries ONE Stmt vertex (normally a StmtStmtList),
		// unlike StmtFunction which carries a Stmts slice.
		bodies = append(bodies, funcBody{name: calleeName(m.Name), facts: collectAll([]ast.Vertex{m.Stmt})})
	}

	loss := map[string]bool{}
	for _, b := range bodies {
		recordPrecisionLoss(b.facts, loss)
	}

	// Summaries only ever move from absent to present, or to a higher
	// confidence, so this is a monotone fixpoint over a finite lattice and
	// terminates on its own merit. The round cap below exists only to bound
	// worst-case work, not to decide correctness - so it must be sized to the
	// input rather than fixed. A chain of N summarized functions can need up
	// to N rounds to propagate taint from the deepest callee back to the
	// outermost caller (one hop converges per round in the worst discovery
	// order), so a cap smaller than len(bodies) can stop before a long enough
	// chain converges and silently miss the flow. This mirrors the fix
	// already applied to the intraprocedural fixpoint in taintedLocalsFallback.
	summaries := map[string]Confidence{}
	maxRounds := len(bodies) + 1
	for round := 0; round < maxRounds; round++ {
		changed := false
		for _, b := range bodies {
			if b.name == "" {
				continue
			}
			st := taintedLocals(b.facts, summaries)
			for _, ret := range b.facts.returns {
				if ret.Expr == nil {
					continue
				}
				c, tainted := exprTaint(ret.Expr, st, summaries)
				if !tainted {
					continue
				}
				if cur, ok := summaries[b.name]; !ok || c > cur {
					summaries[b.name] = c
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	names := make([]string, 0, len(loss))
	for name := range loss {
		names = append(names, name)
	}
	sort.Strings(names)
	return summaries, names
}

// recordPrecisionLoss folds one body's precision-loss facts into the running
// set. Variable-variables and dynamic calls are already flagged during
// collection (facts.go); this adds the calls whose names are known but whose
// effect on variable identity is not visible to the collector, such as
// extract() writing into caller-invisible names.
func recordPrecisionLoss(f *scopeFacts, loss map[string]bool) {
	for marker := range f.precisionLoss {
		loss[marker] = true
	}
	for name := range f.calls {
		if marker, ok := precisionLossMarkers[name]; ok {
			loss[marker] = true
		}
	}
}
