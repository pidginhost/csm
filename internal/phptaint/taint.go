package phptaint

import "github.com/VKCOM/php-parser/pkg/ast"

// decoders preserve taint and raise confidence: fetching plaintext and
// executing it has a small benign population, but fetching, decoding, then
// executing has effectively none.
var decoders = map[string]bool{
	"base64_decode": true, "gzinflate": true, "gzuncompress": true,
	"gzdecode": true, "str_rot13": true, "hex2bin": true,
	"convert_uudecode": true, "unserialize": true, "pack": true,
}

// There is no passthrough allowlist: taint propagation is structural, not
// name-based. exprTaint marks any expression tainted if it references a
// tainted variable anywhere in its subtree, so trim($a), sprintf($a), and an
// unlisted some_helper($a) are all already covered without naming a single
// one of them. A name list here could only ever be narrower than that rule.

// taintState maps a variable name to the strongest confidence with which it
// carries remote content.
type taintState map[string]Confidence

func (s taintState) raise(name string, c Confidence) bool {
	if name == "" {
		return false
	}
	if cur, ok := s[name]; ok && cur >= c {
		return false
	}
	s[name] = c
	return true
}

// taintedLocals computes the tainted variables of one scope to a fixpoint.
// It is flow-insensitive: assignment order within the scope is not modelled.
func taintedLocals(f *scopeFacts, summaries map[string]Confidence) taintState {
	st := taintState{}
	for round := 0; round < maxFixpointRounds; round++ {
		changed := false
		for _, a := range f.assigns {
			target, ok := a.Var.(*ast.ExprVariable)
			if !ok {
				continue
			}
			if c, tainted := exprTaint(a.Expr, st, summaries); tainted {
				changed = st.raise(varName(target.Name), c) || changed
			}
		}
		for _, a := range f.concats {
			target, ok := a.Var.(*ast.ExprVariable)
			if !ok {
				continue
			}
			if c, tainted := exprTaint(a.Expr, st, summaries); tainted {
				changed = st.raise(varName(target.Name), c) || changed
			}
		}
		if !changed {
			break
		}
	}
	return st
}

// exprTaint reports whether an expression carries remote content, and with
// what confidence. It reads the already-collected facts of the subtree, so
// this package's own recursion stays in call-chain resolution.
func exprTaint(e ast.Vertex, st taintState, summaries map[string]Confidence) (Confidence, bool) {
	if e == nil {
		return ConfidenceLow, false
	}
	sub := collectScope(e)
	best, found := taintOf(sub, st, summaries)
	if !found {
		return ConfidenceLow, false
	}
	// A decoder raises confidence to Certain only when the tainted value
	// passed through THAT decoder's own argument, not merely somewhere else
	// in the same expression: f(base64_decode($clean), $tainted) must stay
	// at the source's own grade, because the decode never touched $tainted.
	// subtreeTaint, not exprTaint, checks the argument so this does not
	// repeat the decoder scan at every nesting level of a decoder chain.
	for _, call := range sub.callNodes {
		if !decoders[calleeName(call.Function)] {
			continue
		}
		for _, argN := range call.Args {
			arg, ok := argN.(*ast.Argument)
			if !ok {
				continue
			}
			if _, tainted := subtreeTaint(arg.Expr, st, summaries); tainted {
				return ConfidenceCertain, true
			}
		}
	}
	return best, true
}

// subtreeTaint reports an expression's taint without the decoder upgrade.
// exprTaint uses it to test a decoder's own argument in isolation, instead
// of recursing into exprTaint itself, which would re-run the decoder scan
// at every nesting level and blow up combinatorially on a deep decoder chain.
func subtreeTaint(e ast.Vertex, st taintState, summaries map[string]Confidence) (Confidence, bool) {
	if e == nil {
		return ConfidenceLow, false
	}
	return taintOf(collectScope(e), st, summaries)
}

// taintOf finds the strongest confidence among an already-collected scope's
// source calls, summarized user-function calls, and references to variables
// already known tainted.
func taintOf(sub *scopeFacts, st taintState, summaries map[string]Confidence) (Confidence, bool) {
	best := ConfidenceLow
	found := false
	for _, call := range sub.callNodes {
		if c, ok := sourceConfidence(call); ok {
			found = true
			if c > best {
				best = c
			}
		}
	}
	for name := range sub.calls {
		if c, ok := summaries[name]; ok {
			found = true
			if c > best {
				best = c
			}
		}
	}
	for name := range sub.vars {
		if c, ok := st[name]; ok {
			found = true
			if c > best {
				best = c
			}
		}
	}
	return best, found
}
