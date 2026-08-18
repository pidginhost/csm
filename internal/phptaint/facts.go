package phptaint

import (
	"strings"

	"github.com/VKCOM/php-parser/pkg/ast"
	"github.com/VKCOM/php-parser/pkg/visitor"
	"github.com/VKCOM/php-parser/pkg/visitor/traverser"
)

// callSinks are code-execution sinks that appear as ordinary function calls,
// mapped to the index of the argument that gets executed. assert() evaluates
// its first argument on PHP 7, which hosts still run; create_function()
// evaluates the code in its second argument.
var callSinks = map[string]int{"assert": 0, "create_function": 1}

// sinkSite is one code-execution construct and the expression it executes.
type sinkSite struct {
	kind string
	expr ast.Vertex
}

// scopeFacts is everything the taint pass needs from one lexical scope.
// Collection is one pass; the analysis reads it repeatedly.
type scopeFacts struct {
	assigns        []*ast.ExprAssign
	concats        []*ast.ExprAssignConcat
	returns        []*ast.StmtReturn
	funcs          []*ast.StmtFunction
	methods        []*ast.StmtClassMethod
	sinks          []sinkSite
	callNodes      []*ast.ExprFunctionCall
	calls          map[string]bool
	vars           map[string]bool
	precisionLoss  map[string]bool
	visited        int
	budgetExceeded bool
}

func newScopeFacts() *scopeFacts {
	return &scopeFacts{
		calls:         map[string]bool{},
		vars:          map[string]bool{},
		precisionLoss: map[string]bool{},
	}
}

// count enforces the collection budget. Once exceeded, collection stops
// recording so a hostile file cannot grow analysis state without bound.
func (f *scopeFacts) count() bool {
	if f.budgetExceeded {
		return false
	}
	f.visited++
	if f.visited > maxCollectedNodes {
		f.budgetExceeded = true
		return false
	}
	return true
}

// factVisitor implements only the node types the analysis needs; every other
// node type is a no-op inherited from visitor.Null.
type factVisitor struct {
	visitor.Null
	f *scopeFacts
}

func (v *factVisitor) ExprVariable(n *ast.ExprVariable) {
	if v.f.count() {
		v.f.vars[varName(n.Name)] = true
	}
}

func (v *factVisitor) ExprFunctionCall(n *ast.ExprFunctionCall) {
	if !v.f.count() {
		return
	}
	name := calleeName(n.Function)
	v.f.calls[name] = true
	v.f.callNodes = append(v.f.callNodes, n)
	// assert() and create_function() are ordinary calls in the grammar, not
	// dedicated nodes, so they are recognised here rather than by node type.
	// The executed argument differs per sink (assert's is first,
	// create_function's is second), so the index is looked up rather than
	// assumed to be the last argument.
	if idx, ok := callSinks[name]; ok && len(n.Args) > idx {
		if arg, ok := n.Args[idx].(*ast.Argument); ok {
			v.f.sinks = append(v.f.sinks, sinkSite{kind: name, expr: arg.Expr})
		}
	}
}

func (v *factVisitor) ExprAssign(n *ast.ExprAssign) {
	if v.f.count() {
		v.f.assigns = append(v.f.assigns, n)
	}
}

func (v *factVisitor) ExprAssignConcat(n *ast.ExprAssignConcat) {
	if v.f.count() {
		v.f.concats = append(v.f.concats, n)
	}
}

func (v *factVisitor) StmtReturn(n *ast.StmtReturn) {
	if v.f.count() {
		v.f.returns = append(v.f.returns, n)
	}
}

func (v *factVisitor) StmtFunction(n *ast.StmtFunction) {
	if v.f.count() {
		v.f.funcs = append(v.f.funcs, n)
	}
}

func (v *factVisitor) StmtClassMethod(n *ast.StmtClassMethod) {
	if v.f.count() {
		v.f.methods = append(v.f.methods, n)
	}
}

func (v *factVisitor) ExprEval(n *ast.ExprEval) { v.sink("eval", n.Expr) }

func (v *factVisitor) ExprInclude(n *ast.ExprInclude) { v.sink("include", n.Expr) }

func (v *factVisitor) ExprIncludeOnce(n *ast.ExprIncludeOnce) { v.sink("include_once", n.Expr) }

func (v *factVisitor) ExprRequire(n *ast.ExprRequire) { v.sink("require", n.Expr) }

func (v *factVisitor) ExprRequireOnce(n *ast.ExprRequireOnce) { v.sink("require_once", n.Expr) }

func (v *factVisitor) sink(kind string, expr ast.Vertex) {
	if v.f.count() {
		v.f.sinks = append(v.f.sinks, sinkSite{kind: kind, expr: expr})
	}
}

// collectScope gathers facts from one subtree.
func collectScope(n ast.Vertex) *scopeFacts {
	f := newScopeFacts()
	if n == nil {
		return f
	}
	traverser.NewTraverser(&factVisitor{f: f}).Traverse(n)
	return f
}

// collectAll gathers facts from a statement list, such as a function body.
func collectAll(ns []ast.Vertex) *scopeFacts {
	f := newScopeFacts()
	v := &factVisitor{f: f}
	t := traverser.NewTraverser(v)
	for _, n := range ns {
		if n != nil {
			t.Traverse(n)
		}
	}
	return f
}

// calleeName renders a call target as a lowercase name. PHP function names
// are case-insensitive; variable and dynamic targets yield "".
//
// Multi-part names, including *ast.NameRelative (a "namespace\name" call),
// are never collapsed onto their last segment: PHP resolves an unqualified
// call in the current namespace before falling back to the global one, so
// treating "Foo\curl_exec" as global curl_exec would invent false
// positives. *ast.NameRelative is therefore left unhandled and yields "";
// missing an explicitly namespaced wrapper is the accepted trade.
func calleeName(n ast.Vertex) string {
	switch v := n.(type) {
	case *ast.Name:
		return joinNameParts(v.Parts)
	case *ast.NameFullyQualified:
		return joinNameParts(v.Parts)
	case *ast.Identifier:
		return strings.ToLower(string(v.Value))
	}
	return ""
}

func joinNameParts(parts []ast.Vertex) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if np, ok := p.(*ast.NamePart); ok {
			out = append(out, string(np.Value))
		}
	}
	return strings.ToLower(strings.Join(out, "\\"))
}

// varName renders a variable's name. The parser's T_VARIABLE token includes
// the leading '$' in Identifier.Value, so it is trimmed here to yield the
// bare name. Variable variables yield "" because their identity is not
// statically known.
func varName(n ast.Vertex) string {
	if id, ok := n.(*ast.Identifier); ok {
		return strings.TrimPrefix(string(id.Value), "$")
	}
	return ""
}
