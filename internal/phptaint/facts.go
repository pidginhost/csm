package phptaint

import (
	"strings"

	"github.com/VKCOM/php-parser/pkg/ast"
	"github.com/VKCOM/php-parser/pkg/visitor"
	"github.com/VKCOM/php-parser/pkg/visitor/traverser"
)

// callSinks are code-execution sinks that appear as ordinary function calls.
// create_function evaluates its body; assert evaluates a string argument on
// PHP 7, which hosts still run.
var callSinks = map[string]bool{"assert": true, "create_function": true}

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
	if callSinks[name] && len(n.Args) > 0 {
		if arg, ok := n.Args[len(n.Args)-1].(*ast.Argument); ok {
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
func calleeName(n ast.Vertex) string {
	switch v := n.(type) {
	case *ast.Name:
		parts := make([]string, 0, len(v.Parts))
		for _, p := range v.Parts {
			if np, ok := p.(*ast.NamePart); ok {
				parts = append(parts, string(np.Value))
			}
		}
		return strings.ToLower(strings.Join(parts, "\\"))
	case *ast.Identifier:
		return strings.ToLower(string(v.Value))
	}
	return ""
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
