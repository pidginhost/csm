package phptaint

import (
	"sort"
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

type bodyKind uint8

const (
	bodyFunction bodyKind = iota
	bodyMethod
)

// funcBody pairs a summarizable function or method with its collected facts
// and which summary namespace its name belongs to. Facts are collected once
// up front: they do not change across fixpoint rounds, only the summary
// tables consulted while interpreting them do.
type funcBody struct {
	name  string
	kind  bodyKind
	facts *scopeFacts
}

// functionSummaries reports which user-defined functions and methods return
// remotely-sourced data, computed to a fixpoint over the call graph, plus any
// precision-loss markers observed while collecting their bodies.
//
// Functions and methods are kept in separate namespaces (summaryTables): PHP
// allows a function and a method, or methods on unrelated classes, to share
// a bare name, and a single shared table would let a tainted method
// anywhere in the file poison every same-named plain function call site. A
// method name declared by more than one class is dropped from the method
// table entirely rather than resolved to any one class's definition - a
// deliberate false-negative trade recorded as "ambiguous-method" precision
// loss, because this analyzer's zero-false-positive bar makes guessing
// wrong more expensive than a visible gap.
//
// This is what lets the analyzer see the motivating shape: a fetch in one
// function and a sink in another, joined only by a call. Without a summary
// for the fetching function, that flow is invisible to a single-scope pass.
func functionSummaries(f *scopeFacts) (summaryTables, []string) {
	loss := map[string]bool{}
	// The enclosing facts already cover every declaration body. Record loss
	// from them before applying the summary-body cap or omitting ambiguous
	// methods, because either filter can exclude the only body containing a
	// precision-loss construct.
	recordPrecisionLoss(f, loss)

	bodies := make([]funcBody, 0, len(f.funcs)+len(f.methods))
	for _, fn := range f.funcs {
		if len(bodies) >= maxSummarizedFuncs {
			break
		}
		bodies = append(bodies, funcBody{name: calleeName(fn.Name), kind: bodyFunction, facts: collectOwnStmts(fn.Stmts)})
	}

	// A single class cannot legally declare the same method name twice, so
	// any name appearing more than once in this flat, whole-file list was
	// declared by more than one class - ambiguous, without needing to track
	// which class owns which method.
	methodCounts := make(map[string]int, len(f.methods))
	for _, m := range f.methods {
		methodCounts[calleeName(m.Name)]++
	}
	for _, count := range methodCounts {
		if count > 1 {
			loss["ambiguous-method"] = true
		}
	}
	for _, m := range f.methods {
		if len(bodies) >= maxSummarizedFuncs {
			break
		}
		name := calleeName(m.Name)
		if methodCounts[name] > 1 {
			continue
		}
		// StmtClassMethod carries ONE Stmt vertex (normally a StmtStmtList),
		// unlike StmtFunction which carries a Stmts slice.
		bodies = append(bodies, funcBody{name: name, kind: bodyMethod, facts: collectOwnStmts(methodStmts(m.Stmt))})
	}
	// Recheck every included body using its independently collected facts.
	// The enclosing collection has one aggregate node budget, so it can stop
	// recording inside a declaration that was already discovered; the fresh
	// per-body budget can still preserve that declaration's loss markers.
	for _, b := range bodies {
		recordPrecisionLoss(b.facts, loss)
	}

	// Summaries only ever move from absent to present, or to a higher
	// confidence, so this is a monotone fixpoint over a finite lattice and
	// terminates on its own merit. The round cap below exists only to bound
	// worst-case work, not to decide correctness - so it must be sized to the
	// input rather than fixed. A chain of N summarized functions/methods can
	// need up to N rounds to propagate taint from the deepest callee back to
	// the outermost caller (one hop converges per round in the worst
	// discovery order), so a cap smaller than len(bodies) can stop before a
	// long enough chain converges and silently miss the flow. This mirrors
	// the fix already applied to the intraprocedural fixpoint in
	// taintedLocalsFallback.
	tables := summaryTables{funcs: map[string]Confidence{}, methods: map[string]Confidence{}}
	maxRounds := len(bodies) + 1
	for round := 0; round < maxRounds; round++ {
		changed := false
		for _, b := range bodies {
			if b.name == "" {
				continue
			}
			target := tables.funcs
			if b.kind == bodyMethod {
				target = tables.methods
			}
			st := taintedLocals(b.facts, tables)
			for _, ret := range b.facts.returns {
				if ret.Expr == nil {
					continue
				}
				c, tainted := exprTaint(ret.Expr, st, tables)
				if !tainted {
					continue
				}
				if cur, ok := target[b.name]; !ok || c > cur {
					target[b.name] = c
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
	return tables, names
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
