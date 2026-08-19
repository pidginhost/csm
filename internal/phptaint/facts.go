package phptaint

import (
	"sort"
	"strings"
	"sync/atomic"

	"github.com/VKCOM/php-parser/pkg/ast"
	"github.com/VKCOM/php-parser/pkg/visitor"
	"github.com/VKCOM/php-parser/pkg/visitor/traverser"
)

// callSinks are code-execution sinks that appear as ordinary function calls,
// mapped to the index of the argument that gets executed. assert() evaluates
// its first argument on PHP 7, which hosts still run; create_function()
// evaluates the code in its second argument.
var callSinks = map[string]int{"assert": 0, "create_function": 1}

// assertArgumentCouldBeString reports whether e's top-level shape permits a
// string value. This is exactly what decides whether assert(e) can execute
// code on any PHP version this analyzer targets: PHP 7 only ever evaluated a
// *string* argument as code, and PHP 8 removed the eval form entirely. A
// logical, comparison, identity, or instanceof expression can only ever
// produce a bool (or, for <=>, an int) -- never a string -- so it is not a
// code-execution sink regardless of what it compares.
//
// The check is shallow by design: only e's own node type is inspected, not
// its operands. assert($a && fetchCode()) must still be excluded, because
// the value actually passed to assert() is the bool && produces, not the
// string one of its operands would have produced on its own.
func assertArgumentCouldBeString(e ast.Vertex) bool {
	switch e.(type) {
	case *ast.ExprBinaryBooleanAnd, *ast.ExprBinaryBooleanOr,
		*ast.ExprBinaryLogicalAnd, *ast.ExprBinaryLogicalOr, *ast.ExprBinaryLogicalXor,
		*ast.ExprBooleanNot,
		*ast.ExprBinaryEqual, *ast.ExprBinaryNotEqual,
		*ast.ExprBinaryIdentical, *ast.ExprBinaryNotIdentical,
		*ast.ExprBinaryGreater, *ast.ExprBinaryGreaterOrEqual,
		*ast.ExprBinarySmaller, *ast.ExprBinarySmallerOrEqual,
		*ast.ExprBinarySpaceship,
		*ast.ExprInstanceOf:
		return false
	}
	return true
}

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
	assigns    []*ast.ExprAssign
	references []*ast.ExprAssignReference
	concats    []*ast.ExprAssignConcat
	returns    []*ast.StmtReturn
	funcs      []*ast.StmtFunction
	methods    []*ast.StmtClassMethod
	// closures and arrowFuncs hold every closure and arrow function found in
	// this scope. Both are declarations in the same sense funcs and methods
	// are: each gets its own entry in declarationTree (so its span is
	// excluded from the enclosing scope) and its own per-scope analysis in
	// analyze, exactly like a named function's body. Without both halves, a
	// closure parameter or local reassignment that merely shares a name with
	// an outer variable would either borrow that outer variable's taint (if
	// only excluded, never analysed) or stop being examined for its own
	// sinks (if only analysed, never excluded) -- see analyze's closure and
	// arrow-function loops for the second half.
	closures   []*ast.ExprClosure
	arrowFuncs []*ast.ExprArrowFunction
	// classLikes holds every class, interface, trait, and enum declaration
	// (named or anonymous) found in this scope. Their own contents are
	// never read from here directly -- methods are already tracked in
	// methods above -- this list exists only to supply declarationTree
	// with the position span of the class body itself.
	classLikes []ast.Vertex
	sinks      []sinkSite
	callNodes  []*ast.ExprFunctionCall
	callSites  []callSite
	calls      map[string]bool
	vars       map[string]bool
	varNodes   []*ast.ExprVariable
	// propNodes holds every property-fetch node (both "->" and "?->") found
	// in this scope, whether it appears as a read or as an assignment
	// target. readVarNodes keys each one to the specific property it fetches
	// (see assignedTargetKey) so a write to one property never taints a read
	// of a different one or of the bare base object.
	propNodes      []ast.Vertex
	writes         []ast.Vertex
	precisionLoss  map[string]bool
	visited        int
	budgetExceeded bool
	// declTreeCache memoizes declarationTree's result for this scopeFacts
	// instance. Safe to cache: a scopeFacts is fully populated by the
	// traversal in collectScope/collectAll/collectOwnStmts before any
	// caller can reach it and is never mutated afterward, and each
	// instance is freshly allocated per collection call, so nothing here
	// carries state across separate Analyze invocations. This is what lets
	// functionSummaries call f.declarationTree() again on the same f
	// analyze already indexed without repeating the O(D log D) build.
	declTreeCache *declTree
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
	// exclude, when set, marks the position spans of nested declarations
	// this scope must not absorb facts from. The library traverser recurses
	// unconditionally through control-flow wrappers (if/while/switch/try/
	// foreach/...), so a declaration nested inside one of those -- the
	// WordPress `if (!function_exists(...))` guard is the common case -- is
	// still reached by this same traversal even though it belongs to a
	// separately analysed scope. Position-based exclusion catches it
	// regardless of which wrapper (or how many, nested how deep) sits
	// between this scope and the declaration; a filter keyed on the direct
	// statement type of the top of the list cannot, because it only ever
	// sees the wrapper, never what the wrapper contains.
	exclude *spanIndex
}

// excluded reports whether n's position falls inside a nested declaration
// this scope must not record facts from. A node without a determinable
// position is not excluded: parsed nodes normally always have positions,
// and failing open (keep, don't drop) matches the conservative choice
// already made in readVarNodes for the same edge case -- an unrecordable
// position must never cost the enclosing scope one of its own facts.
func (v *factVisitor) excluded(n ast.Vertex) bool {
	if v.exclude == nil {
		return false
	}
	span, ok := spanOf(n)
	if !ok {
		return false
	}
	return v.exclude.contains(span)
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
	if !v.f.count() || v.excluded(n) {
		return
	}
	name := varName(n.Name)
	v.f.vars[name] = true
	v.f.varNodes = append(v.f.varNodes, n)
	if name == "" {
		v.f.precisionLoss["variable-variable"] = true
	}
}

// ExprPropertyFetch and ExprNullsafePropertyFetch record every "->"/"?->"
// property fetch this scope contains, whether it is a read or (for the
// non-nullsafe form; nullsafe cannot appear as a write target in valid PHP)
// an assignment target. The traverser still visits the embedded base
// variable (e.g. $this inside $this->body) as an ordinary ExprVariable
// regardless of this hook, which is what lets a genuinely whole-object
// taint keep reaching a property read -- see readVarNodes.
func (v *factVisitor) ExprPropertyFetch(n *ast.ExprPropertyFetch) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.propNodes = append(v.f.propNodes, n)
}

func (v *factVisitor) ExprNullsafePropertyFetch(n *ast.ExprNullsafePropertyFetch) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.propNodes = append(v.f.propNodes, n)
}

func (v *factVisitor) ExprFunctionCall(n *ast.ExprFunctionCall) {
	if !v.f.count() || v.excluded(n) {
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
	// assumed to be the last argument. assert() additionally requires its
	// argument to be capable of holding a string: see
	// assertArgumentCouldBeString for why a boolean-shaped argument (a
	// comparison, a logical operator, instanceof, ...) is not a
	// code-execution sink on any PHP version this analyzer targets.
	if sink, ok := callSinkSite(name, n); ok {
		v.f.sinks = append(v.f.sinks, sink)
	}
}

func callSinkSite(name string, node ast.Vertex) (sinkSite, bool) {
	call, ok := node.(*ast.ExprFunctionCall)
	if !ok {
		return sinkSite{}, false
	}
	idx, ok := callSinks[name]
	if !ok || len(call.Args) <= idx {
		return sinkSite{}, false
	}
	arg, ok := call.Args[idx].(*ast.Argument)
	if !ok || (name == "assert" && !assertArgumentCouldBeString(arg.Expr)) {
		return sinkSite{}, false
	}
	return sinkSite{kind: name, expr: arg.Expr}, true
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
	if !v.f.count() || v.excluded(node) {
		return
	}
	v.f.calls[name] = true
	v.f.callSites = append(v.f.callSites, callSite{name: name, node: node})
	if name == "" {
		v.f.precisionLoss["dynamic-call"] = true
	}
}

func (v *factVisitor) ExprAssign(n *ast.ExprAssign) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.assigns = append(v.f.assigns, n)
	v.f.writes = append(v.f.writes, n.Var)
}

func (v *factVisitor) ExprAssignReference(n *ast.ExprAssignReference) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.references = append(v.f.references, n)
	v.f.writes = append(v.f.writes, n.Var)
}

func (v *factVisitor) ExprAssignConcat(n *ast.ExprAssignConcat) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.concats = append(v.f.concats, n)
}

func (v *factVisitor) StmtReturn(n *ast.StmtReturn) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.returns = append(v.f.returns, n)
}

func (v *factVisitor) StmtFunction(n *ast.StmtFunction) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.funcs = append(v.f.funcs, n)
}

func (v *factVisitor) StmtClassMethod(n *ast.StmtClassMethod) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.methods = append(v.f.methods, n)
}

func (v *factVisitor) ExprClosure(n *ast.ExprClosure) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.closures = append(v.f.closures, n)
}

func (v *factVisitor) ExprArrowFunction(n *ast.ExprArrowFunction) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.arrowFuncs = append(v.f.arrowFuncs, n)
}

func (v *factVisitor) StmtClass(n *ast.StmtClass) { v.classLike(n) }

func (v *factVisitor) StmtInterface(n *ast.StmtInterface) { v.classLike(n) }

func (v *factVisitor) StmtTrait(n *ast.StmtTrait) { v.classLike(n) }

func (v *factVisitor) StmtEnum(n *ast.StmtEnum) { v.classLike(n) }

// classLike records a class, interface, trait, or enum declaration's span.
// n's Name is nil for an anonymous class (`new class { ... }`); the node
// itself still carries a real position, so anonymous classes are covered by
// the same declaration-span exclusion as named ones, with no separate case.
func (v *factVisitor) classLike(n ast.Vertex) {
	if !v.f.count() || v.excluded(n) {
		return
	}
	v.f.classLikes = append(v.f.classLikes, n)
}

func (v *factVisitor) ExprEval(n *ast.ExprEval) { v.sink("eval", n.Expr) }

func (v *factVisitor) ExprInclude(n *ast.ExprInclude) { v.sink("include", n.Expr) }

func (v *factVisitor) ExprIncludeOnce(n *ast.ExprIncludeOnce) { v.sink("include_once", n.Expr) }

func (v *factVisitor) ExprRequire(n *ast.ExprRequire) { v.sink("require", n.Expr) }

func (v *factVisitor) ExprRequireOnce(n *ast.ExprRequireOnce) { v.sink("require_once", n.Expr) }

func (v *factVisitor) sink(kind string, expr ast.Vertex) {
	if !v.f.count() || v.excluded(expr) {
		return
	}
	v.f.sinks = append(v.f.sinks, sinkSite{kind: kind, expr: expr})
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

// collectTopLevel gathers facts from the whole file, excluding anything
// positioned inside a declaration named in exclude. Folding a declaration's
// body into the flat top-level map lets a variable local to it taint an
// unrelated top-level variable that merely shares its name, which reports
// clean code as malicious: names like $data, $content and $tmp recur
// constantly in real PHP. exclude is normally built by
// declarationTree(...).exclusionFor(nil) over the whole file, so every
// declaration in the file is excluded (there is no declaration whose own
// statements this call needs to keep).
func collectTopLevel(root ast.Vertex, exclude *spanIndex) *scopeFacts {
	r, ok := root.(*ast.Root)
	if !ok {
		return collectScope(root)
	}
	return collectOwnStmts(r.Stmts, exclude)
}

// collectOwnStmts gathers facts from a statement list -- a function body, a
// method body, or the file's top-level statements -- excluding anything
// positioned inside a nested declaration named in exclude. This is the same
// cross-scope leak collectTopLevel guards against, one level deeper: a
// function can declare another function (or a class, including an
// anonymous one) in its own body, and that nested declaration gets its own
// entry in the whole-file funcs/methods inventory, analysed separately with
// its own taint state. Folding it into this scope's flat map too would let
// its local variables taint an identically-named local in the enclosing
// body.
//
// Filtering happens by position, not by skipping statements of a
// declaration type at the top of stmts, because the library traverser
// recurses unconditionally through control-flow wrappers: a function
// declared inside `if (!function_exists('f')) { function f() {...} }` --
// the standard WordPress conditional-declaration guard -- is not a direct
// member of stmts, so a type-based filter on stmts itself would miss it
// (and miss it again for every layer of if/while/switch/try/foreach it is
// wrapped in). Every statement is traversed unconditionally here; exclude,
// consulted per node inside factVisitor, is what actually drops facts whose
// position falls inside one of those nested declarations, regardless of
// how they are reached.
func collectOwnStmts(stmts []ast.Vertex, exclude *spanIndex) *scopeFacts {
	f := newScopeFacts()
	t := traverser.NewTraverser(&factVisitor{f: f, exclude: exclude})
	for _, stmt := range stmts {
		if stmt != nil {
			t.Traverse(stmt)
		}
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

// arrowFunctionBody wraps an arrow function's single implicit-return
// expression into the one-element statement list collectOwnStmts expects,
// the same shape methodStmts gives a method body. Unlike a closure (whose
// Stmts is already a real statement list), `fn($x) => expr` has no braces or
// statements to unwrap -- expr itself is both the body and the return value.
func arrowFunctionBody(n *ast.ExprArrowFunction) []ast.Vertex {
	if n.Expr == nil {
		return nil
	}
	return []ast.Vertex{n.Expr}
}

// closureCaptureNames names the outer bindings a closure's use() clause
// receives. Only Uses is consulted, never Params: a parameter that happens to
// share an outer variable's name is the closure's own binding and receives
// nothing from the enclosing scope, which is the shadowing case that scoping a
// closure's body exists to keep clean.
func closureCaptureNames(cl *ast.ExprClosure) map[string]bool {
	names := make(map[string]bool, len(cl.Uses))
	for _, u := range cl.Uses {
		use, ok := u.(*ast.ExprClosureUse)
		if !ok {
			continue
		}
		v, ok := use.Var.(*ast.ExprVariable)
		if !ok {
			continue
		}
		if name := varName(v.Name); name != "" {
			names[name] = true
		}
	}
	return names
}

// paramNames names the plain-variable parameters of a parameter list. A
// parameter with any other shape is skipped rather than guessed at.
func paramNames(params []ast.Vertex) map[string]bool {
	names := make(map[string]bool, len(params))
	for _, p := range params {
		param, ok := p.(*ast.Parameter)
		if !ok {
			continue
		}
		v, ok := param.Var.(*ast.ExprVariable)
		if !ok {
			continue
		}
		if name := varName(v.Name); name != "" {
			names[name] = true
		}
	}
	return names
}

// arrowCaptureNames names the outer bindings an arrow function receives.
// Unlike a closure, which lists them in a use() clause, fn(...) => expr
// captures by value every enclosing variable its body mentions. body.vars
// already lists every variable name the body reads, so subtracting the arrow
// function's own parameters leaves exactly the names that must have come from
// outside. Static arrows are the one exception: they still capture ordinary
// variables, but PHP deliberately does not bind $this to them. Over-inclusive
// by design: a name that is not in fact tainted in the enclosing scope simply
// produces no marker.
func arrowCaptureNames(af *ast.ExprArrowFunction, body *scopeFacts) map[string]bool {
	params := paramNames(af.Params)
	names := make(map[string]bool, len(body.vars))
	for name := range body.vars {
		if name != "" && !params[name] && (name != "this" || af.StaticTkn == nil) {
			names[name] = true
		}
	}
	return names
}

type nodeSpan struct {
	start int
	end   int
}

type declarationSpan struct {
	nodeSpan
	node ast.Vertex
}

type namedNodeSpan struct {
	nodeSpan
	name string
	node ast.Vertex
}

// resolvedCallIndex restores the canonical call names from a whole-file
// collection to independently collected lexical scopes. Namespace-level
// `use function` imports are outside a function or method body, so collecting
// that body alone cannot resolve its aliases. Exact source spans join the two
// views without importing variables, assignments, or calls from another
// scope.
type resolvedCallIndex struct {
	functions map[nodeSpan]*ast.ExprFunctionCall
	sites     map[nodeSpan]callSite
}

func newResolvedCallIndex(f *scopeFacts) resolvedCallIndex {
	index := resolvedCallIndex{
		functions: make(map[nodeSpan]*ast.ExprFunctionCall, len(f.callNodes)),
		sites:     make(map[nodeSpan]callSite, len(f.callSites)),
	}
	for _, call := range f.callNodes {
		if span, ok := spanOf(call); ok {
			index.functions[span] = call
		}
	}
	for _, call := range f.callSites {
		if span, ok := spanOf(call.node); ok {
			index.sites[span] = call
		}
	}
	return index
}

func (index resolvedCallIndex) apply(f *scopeFacts) *scopeFacts {
	out := *f
	out.callNodes = append([]*ast.ExprFunctionCall(nil), f.callNodes...)
	for i, call := range out.callNodes {
		if span, ok := spanOf(call); ok {
			if resolved, found := index.functions[span]; found {
				out.callNodes[i] = resolved
			}
		}
	}
	out.callSites = append([]callSite(nil), f.callSites...)
	for i, call := range out.callSites {
		if span, ok := spanOf(call.node); ok {
			if resolved, found := index.sites[span]; found {
				out.callSites[i] = resolved
			}
		}
	}
	out.calls = make(map[string]bool, len(out.callSites))
	for _, call := range out.callSites {
		out.calls[call.name] = true
	}
	out.sinks = make([]sinkSite, 0, len(f.sinks))
	for _, sink := range f.sinks {
		if _, callSink := callSinks[sink.kind]; !callSink {
			out.sinks = append(out.sinks, sink)
		}
	}
	for _, call := range out.callSites {
		if sink, ok := callSinkSite(call.name, call.node); ok {
			out.sinks = append(out.sinks, sink)
		}
	}
	return &out
}

// declTree links each declaration in a whole-file collection to the
// position spans of its IMMEDIATE child declarations only, plus the total
// declaration count. Built once per file by declarationTree, it lets every
// scope's exclusion index be produced by a map lookup instead of scanning
// and re-sorting the whole file's declaration list once per declaration.
type declTree struct {
	// children maps a declaration node -- or nil, for the top-level scope --
	// to the spans of its immediate child declarations.
	children map[ast.Vertex][]nodeSpan
	// parent is the reverse: each indexed declaration to the declaration
	// immediately enclosing it, or the nil interface when the top-level
	// scope encloses it. Captured during the same sweep that builds
	// children, since the sweep already knows both ends of the edge. It
	// answers the question children cannot: given a closure, which scope did
	// it capture its outer bindings FROM.
	parent map[ast.Vertex]ast.Vertex
	// ordered holds the same declarations in source nesting order. Retaining
	// the already-sorted sweep input lets capture analysis walk lexical scopes
	// without rebuilding or re-sorting the attacker-controlled declaration
	// list.
	ordered []declarationSpan
	// count is the total number of declarations indexed, checked against
	// maxDeclarations before any per-scope work begins.
	count int
}

// declTreeBuilds counts how many times declarationTree has actually
// performed the O(D log D) sort-and-sweep build, as opposed to returning an
// already-cached result. It exists solely so a same-package white-box test
// can observe that this count stays a small constant as declaration count
// grows -- the structural invariant this whole file's design establishes --
// rather than asserting elapsed wall-clock time, which is flaky under
// shared CI load and, worse, would not fail reliably if a per-declaration
// rebuild were reintroduced at a scale too small to visibly stall a test
// run. It is read-only from every caller's perspective (nothing in this
// package branches on its value, and it never influences a Report), so it
// is test-only observation of internal behaviour, not the kind of mutable
// process-global configuration or cross-call state this package's purity
// contract forbids.
var declTreeBuilds atomic.Int64

// declarationTree indexes every declaration recorded in f: functions,
// methods, classes/interfaces/traits/enums (anonymous classes included, via
// classLikes), closures, and arrow functions. f must come from an
// unfiltered, whole-file collection (collectScope(root)) so every
// declaration in the file is present, regardless of how deeply any of them
// is nested inside another or wrapped in control flow. The result is cached
// on f (see scopeFacts.declTreeCache), so calling this more than once on the
// same f -- analyze and functionSummaries both do, independently -- costs
// one build, not two.
//
// Sorting happens ONCE, over all D declarations together, rather than once
// per declaration: a per-declaration rebuild-and-sort of the whole span
// list costs O(D) work times D declarations, O(D^2 log D) overall, which is
// a real CPU-exhaustion surface against attacker-controlled PHP source (a
// file of trivial one-line function declarations reaches tens of thousands
// of them well within MaxSourceBytes and maxCollectedNodes). Declarations in
// a legitimately parsed file nest properly -- one is either fully disjoint
// from another or fully contained inside it, never a partial overlap -- so
// a single stack sweep over the sorted spans (the same interval-stack
// technique distributeOrigins already uses in taint.go) assigns each
// declaration to its immediate parent in one pass: pop any open declaration
// that has already closed before this one starts, and whatever remains on
// top of the stack (if anything) is the immediate parent.
//
// Indexing only immediate children, not every descendant, is what keeps the
// total cost linearithmic in D: a fact positioned inside a deeper
// descendant is already covered by its immediate parent's span, so nothing
// beyond direct children is ever needed to exclude an arbitrarily deep
// nested declaration (see exclusionFor). Each declaration contributes to
// exactly one parent's child list, so those lists sum to D across the whole
// file, and sorting each of them once, at exclusionFor time, costs at most
// D log D in total across every scope in the file.
func (f *scopeFacts) declarationTree() declTree {
	if f.declTreeCache != nil {
		return *f.declTreeCache
	}
	declTreeBuilds.Add(1)

	nodes := make([]declarationSpan, 0, len(f.funcs)+len(f.methods)+len(f.classLikes)+len(f.closures)+len(f.arrowFuncs))
	add := func(n ast.Vertex) {
		if span, ok := spanOf(n); ok {
			nodes = append(nodes, declarationSpan{nodeSpan: span, node: n})
		}
	}
	for _, fn := range f.funcs {
		add(fn)
	}
	for _, m := range f.methods {
		add(m)
	}
	for _, c := range f.classLikes {
		add(c)
	}
	for _, cl := range f.closures {
		add(cl)
	}
	for _, af := range f.arrowFuncs {
		add(af)
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].start != nodes[j].start {
			return nodes[i].start < nodes[j].start
		}
		return nodes[i].end > nodes[j].end
	})

	tree := declTree{
		children: make(map[ast.Vertex][]nodeSpan, len(nodes)+1),
		parent:   make(map[ast.Vertex]ast.Vertex, len(nodes)),
		ordered:  nodes,
		count:    len(nodes),
	}
	stack := make([]int, 0, len(nodes))
	for i, n := range nodes {
		// A declaration's end position is EXCLUSIVE, so a declaration
		// starting exactly where the previous one ends is its sibling, not
		// its child. PHP allows `}function` with nothing between, and
		// minifiers emit it, so `<` here would silently reparent every such
		// pair and leak the second one's locals into the enclosing scope.
		for len(stack) > 0 && nodes[stack[len(stack)-1]].end <= n.start {
			stack = stack[:len(stack)-1]
		}
		var parent ast.Vertex // nil selects the top-level scope's own children
		if len(stack) > 0 {
			parent = nodes[stack[len(stack)-1]].node
		}
		tree.children[parent] = append(tree.children[parent], n.nodeSpan)
		tree.parent[n.node] = parent
		stack = append(stack, i)
	}
	f.declTreeCache = &tree
	return tree
}

// exclusionFor builds the spanIndex scope self must exclude from its own
// collection: the spans of self's immediate child declarations only (self
// nil selects the top-level scope's own children). See declarationTree for
// why immediate children alone are sufficient regardless of nesting depth.
func (t declTree) exclusionFor(self ast.Vertex) spanIndex {
	return newSpanIndex(t.children[self])
}

// readVarNodes returns variables whose value is read in this subtree. The
// parser visitor also visits assignment targets; those are writes, not
// inputs to the assignment expression, and must not borrow taint from an
// earlier assignment.
func (f *scopeFacts) readVarNodes() []namedNodeSpan {
	writes := make([]nodeSpan, 0, len(f.writes))
	for _, n := range f.writes {
		if span, ok := spanOf(n); ok {
			writes = append(writes, span)
		}
	}
	sort.Slice(writes, func(i, j int) bool { return writes[i].start < writes[j].start })

	vars := make([]namedNodeSpan, 0, len(f.varNodes)+len(f.propNodes))
	reads := make([]namedNodeSpan, 0, len(f.varNodes)+len(f.propNodes))
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
	// Property-fetch reads are keyed to the specific property chain (see
	// assignedTargetKey), not the bare base variable, so a write to one
	// property cannot leak into a read of a different one. A property whose
	// name is not statically known is skipped here entirely rather than
	// keyed to "": the embedded base variable visited above already carries
	// the conservative base-variable dependency for that case, via
	// assignedTargetKey's own fallback at write time.
	for _, n := range f.propNodes {
		key := assignedTargetKey(n)
		if key == "" {
			continue
		}
		if span, ok := spanOf(n); ok {
			vars = append(vars, namedNodeSpan{nodeSpan: span, name: key, node: n})
		} else {
			reads = append(reads, namedNodeSpan{name: key, node: n})
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
