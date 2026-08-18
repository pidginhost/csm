package phptaint

import (
	"sort"
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

type callSite struct {
	name string
	node ast.Vertex
}

// scopeFacts is everything the taint pass needs from one lexical scope.
// Collection is one pass; the analysis reads it repeatedly.
type scopeFacts struct {
	assigns        []*ast.ExprAssign
	references     []*ast.ExprAssignReference
	concats        []*ast.ExprAssignConcat
	returns        []*ast.StmtReturn
	funcs          []*ast.StmtFunction
	methods        []*ast.StmtClassMethod
	sinks          []sinkSite
	callNodes      []*ast.ExprFunctionCall
	callSites      []callSite
	calls          map[string]bool
	vars           map[string]bool
	varNodes       []*ast.ExprVariable
	writes         []ast.Vertex
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
	f               *scopeFacts
	functionAliases map[string]string
}

func (v *factVisitor) StmtNamespace(*ast.StmtNamespace) {
	v.functionAliases = nil
}

func (v *factVisitor) StmtUse(n *ast.StmtUseList) {
	for _, useNode := range n.Uses {
		use, ok := useNode.(*ast.StmtUse)
		if ok {
			v.addFunctionAlias(n.Type, nil, use)
		}
	}
}

func (v *factVisitor) StmtGroupUse(n *ast.StmtGroupUseList) {
	prefix, _ := n.Prefix.(*ast.Name)
	for _, useNode := range n.Uses {
		use, ok := useNode.(*ast.StmtUse)
		if ok {
			v.addFunctionAlias(n.Type, prefix, use)
		}
	}
}

func (v *factVisitor) addFunctionAlias(listType ast.Vertex, prefix *ast.Name, use *ast.StmtUse) {
	useType := listType
	if use.Type != nil {
		useType = use.Type
	}
	id, ok := useType.(*ast.Identifier)
	if !ok || !strings.EqualFold(string(id.Value), "function") {
		return
	}
	name, ok := use.Use.(*ast.Name)
	if !ok || len(name.Parts) == 0 {
		return
	}
	parts := make([]ast.Vertex, 0, len(name.Parts)+4)
	if prefix != nil {
		parts = append(parts, prefix.Parts...)
	}
	parts = append(parts, name.Parts...)
	target := joinNameParts(parts)
	alias := ""
	if use.Alias != nil {
		alias = calleeName(use.Alias)
	} else if last, ok := name.Parts[len(name.Parts)-1].(*ast.NamePart); ok {
		alias = strings.ToLower(string(last.Value))
	}
	if alias == "" || target == "" {
		return
	}
	if v.functionAliases == nil {
		v.functionAliases = map[string]string{}
	}
	v.functionAliases[alias] = target
}

func (v *factVisitor) ExprVariable(n *ast.ExprVariable) {
	if v.f.count() {
		name := varName(n.Name)
		v.f.vars[name] = true
		v.f.varNodes = append(v.f.varNodes, n)
		if name == "" {
			v.f.precisionLoss["variable-variable"] = true
		}
	}
}

func (v *factVisitor) ExprFunctionCall(n *ast.ExprFunctionCall) {
	if !v.f.count() {
		return
	}
	name, resolved := v.resolveFunctionAlias(n)
	v.f.calls[name] = true
	v.f.callNodes = append(v.f.callNodes, resolved)
	v.f.callSites = append(v.f.callSites, callSite{name: name, node: n})
	if name == "" {
		v.f.precisionLoss["dynamic-call"] = true
	}
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

// resolveFunctionAlias resolves a call target through this scope's
// function-alias table (populated from `use function` imports) and reports
// the canonical name. When the call is aliased, it returns a detached copy
// of the call node whose Function names the canonical target, so downstream
// name lookups (sourceConfidence, decoder checks) see the resolved name
// without the parsed tree itself ever being rewritten mid-traversal: the
// traverser reads call.Function right after visiting call, so mutating it in
// place would orphan the original alias-name subtree from the walk in
// progress. The copy shares Args and Position with the original node, so
// argument inspection and source-span correlation are unaffected.
func (v *factVisitor) resolveFunctionAlias(call *ast.ExprFunctionCall) (string, *ast.ExprFunctionCall) {
	name := calleeName(call.Function)
	plain, ok := call.Function.(*ast.Name)
	if !ok || len(plain.Parts) != 1 {
		return name, call
	}
	target, ok := v.functionAliases[name]
	if !ok {
		return name, call
	}
	parts := strings.Split(target, "\\")
	canonical := make([]ast.Vertex, 0, len(parts))
	for _, part := range parts {
		canonical = append(canonical, &ast.NamePart{Value: []byte(part)})
	}
	resolved := *call
	resolved.Function = &ast.NameFullyQualified{Parts: canonical}
	return target, &resolved
}

func (v *factVisitor) ExprMethodCall(n *ast.ExprMethodCall) {
	v.call(calleeName(n.Method), n)
}

func (v *factVisitor) ExprNullsafeMethodCall(n *ast.ExprNullsafeMethodCall) {
	v.call(calleeName(n.Method), n)
}

func (v *factVisitor) ExprStaticCall(n *ast.ExprStaticCall) {
	v.call(calleeName(n.Call), n)
}

func (v *factVisitor) call(name string, node ast.Vertex) {
	if !v.f.count() {
		return
	}
	v.f.calls[name] = true
	v.f.callSites = append(v.f.callSites, callSite{name: name, node: node})
	if name == "" {
		v.f.precisionLoss["dynamic-call"] = true
	}
}

func (v *factVisitor) ExprAssign(n *ast.ExprAssign) {
	if v.f.count() {
		v.f.assigns = append(v.f.assigns, n)
		v.f.writes = append(v.f.writes, n.Var)
	}
}

func (v *factVisitor) ExprAssignReference(n *ast.ExprAssignReference) {
	if v.f.count() {
		v.f.references = append(v.f.references, n)
		v.f.writes = append(v.f.writes, n.Var)
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

// collectScope gathers facts from one subtree using the parser library's own
// traverser. The library traverser cannot be stopped mid-walk, so it visits
// every node in the subtree regardless of budget; scopeFacts.count() bounds
// the actual cost by making every visitor method a no-op once the budget is
// exceeded, so an over-budget file does no further per-node work beyond the
// traversal dispatch itself. That traverser was measured surviving 2,000,000
// levels of nesting without a Go stack overflow, so a hand-rolled iterative
// walker is not needed to protect against attacker-controlled AST depth.
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

// collectTopLevel gathers facts from the file's top-level statements only,
// skipping declarations whose bodies are analysed separately with their own
// taint state. Folding every scope into one flat map keyed by bare variable
// name lets a function-local variable taint an unrelated top-level variable
// that merely shares its name, which reports clean code as malicious: names
// like $data, $content and $tmp recur constantly in real PHP.
func collectTopLevel(root ast.Vertex) *scopeFacts {
	r, ok := root.(*ast.Root)
	if !ok {
		return collectScope(root)
	}
	return collectOwnStmts(r.Stmts)
}

// collectOwnStmts gathers facts from a statement list, skipping any nested
// function, class, interface, trait, or enum declaration. This is the same
// cross-scope leak collectTopLevel guards against, one level deeper: a
// function can declare another function (or an anonymous class) in its own
// body, and that nested declaration gets its own entry in the whole-file
// funcs/methods inventory, analysed separately with its own taint state.
// Folding it into this scope's flat map too would let its local variables
// taint an identically-named local in the enclosing body.
func collectOwnStmts(stmts []ast.Vertex) *scopeFacts {
	f := newScopeFacts()
	t := traverser.NewTraverser(&factVisitor{f: f})
	for _, stmt := range stmts {
		if stmt == nil {
			continue
		}
		switch stmt.(type) {
		case *ast.StmtFunction, *ast.StmtClass, *ast.StmtInterface, *ast.StmtTrait, *ast.StmtEnum:
			continue
		}
		t.Traverse(stmt)
	}
	return f
}

// methodStmts unwraps a class method's single body vertex into a statement
// list, the shape collectOwnStmts and collectAll both expect. A braced
// method body is *ast.StmtStmtList; an abstract or interface method has a
// nil Stmt.
func methodStmts(stmt ast.Vertex) []ast.Vertex {
	switch v := stmt.(type) {
	case nil:
		return nil
	case *ast.StmtStmtList:
		return v.Stmts
	default:
		return []ast.Vertex{stmt}
	}
}

type nodeSpan struct {
	start int
	end   int
}

type namedNodeSpan struct {
	nodeSpan
	name string
	node ast.Vertex
}

// readVars returns variables whose value is read in this subtree. The parser
// visitor also visits assignment targets; those are writes, not inputs to the
// assignment expression, and must not borrow taint from an earlier assignment.
func (f *scopeFacts) readVars() map[string]bool {
	reads := make(map[string]bool, len(f.varNodes))
	for _, variable := range f.readVarNodes() {
		reads[variable.name] = true
	}
	return reads
}

func (f *scopeFacts) readVarNodes() []namedNodeSpan {
	writes := make([]nodeSpan, 0, len(f.writes))
	for _, n := range f.writes {
		if span, ok := spanOf(n); ok {
			writes = append(writes, span)
		}
	}
	sort.Slice(writes, func(i, j int) bool { return writes[i].start < writes[j].start })

	vars := make([]namedNodeSpan, 0, len(f.varNodes))
	reads := make([]namedNodeSpan, 0, len(f.varNodes))
	for _, n := range f.varNodes {
		name := varName(n.Name)
		if name == "" {
			continue
		}
		if span, ok := spanOf(n); ok {
			vars = append(vars, namedNodeSpan{nodeSpan: span, name: name, node: n})
		} else {
			// Parsed nodes normally always have positions. If a future parser
			// omits one, retain the conservative taint dependency.
			reads = append(reads, namedNodeSpan{name: name, node: n})
		}
	}
	sort.Slice(vars, func(i, j int) bool { return vars[i].start < vars[j].start })

	writeIndex := 0
	maxWriteEnd := -1
	for _, variable := range vars {
		for writeIndex < len(writes) && writes[writeIndex].start <= variable.start {
			if writes[writeIndex].end > maxWriteEnd {
				maxWriteEnd = writes[writeIndex].end
			}
			writeIndex++
		}
		if maxWriteEnd >= variable.end {
			continue
		}
		reads = append(reads, variable)
	}
	return reads
}

func spanOf(n ast.Vertex) (nodeSpan, bool) {
	if n == nil || n.GetPosition() == nil {
		return nodeSpan{}, false
	}
	pos := n.GetPosition()
	if pos.StartPos < 0 || pos.EndPos < pos.StartPos {
		return nodeSpan{}, false
	}
	return nodeSpan{start: pos.StartPos, end: pos.EndPos}, true
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
