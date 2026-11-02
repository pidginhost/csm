package mcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestQueryKeyGuardRejectsNonQueryReads(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "handlers.go", `package webui
import ("net/http"; "net/url")
func handler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()
    alias := q
    _ = alias.Get("filter")
    _ = alias.Has("present")
    _ = alias["multiple"]
    _ = r.Header.Get("limit")
    response := map[string]string{}
    _ = response["offset"]
    {
        q := r.Header
        _ = q.Get("shadowed")
    }
    {
        q := q.Get("nested")
        _ = q
    }
    {
        var q = q.Get("declared")
        _ = q
    }
    helper(w, r, q)
    queryIgnored(r, "unused")
    _ = queryInt(r, "page", 1)
}
func helper(w http.ResponseWriter, r *http.Request, values url.Values) {
    _ = w.Header().Get("total")
    _ = values.Get("from")
}
func queryIgnored(r *http.Request, name string) {}
func queryInt(r *http.Request, key string, fallback int) int {
    _ = r.URL.Query().Get(key)
    return fallback
}
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string][]*ast.FuncDecl{}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			funcs[fn.Name.Name] = append(funcs[fn.Name.Name], fn)
		}
	}
	keys := map[string]bool{}
	collectQueryKeys(funcs, "handler", keys, map[string]bool{})
	want := map[string]bool{"filter": true, "present": true, "multiple": true, "from": true, "page": true, "nested": true, "declared": true}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("query reads = %v, want %v", keys, want)
	}
}

// TestRouteToolParamsAreReadByTheRoute fails when a tool declares an
// argument its route never reads. The route would ignore the filter and the
// agent would present the unfiltered answer as filtered. It parses the Web
// UI handlers and collects every query key each one, or a helper it hands
// the request or query to, reads.
func TestRouteToolParamsAreReadByTheRoute(t *testing.T) {
	funcs, handlers := parseWebUIHandlers(t)
	for _, tl := range routeTools {
		handler, ok := handlers[tl.route]
		if !ok {
			t.Errorf("%s: route %s is not in the read-only table", tl.name, tl.route)
			continue
		}
		read := map[string]bool{}
		collectQueryKeys(funcs, handler, read, map[string]bool{})
		for _, p := range tl.params {
			if p.name == "id" && strings.Contains(tl.route, "{id}") {
				continue
			}
			if !read[p.name] {
				t.Errorf("%s declares %q, which %s never reads", tl.name, p.name, handler)
			}
		}
	}
}

// parseWebUIHandlers returns the webui package's functions by name and the
// read-only table as route pattern -> handler name.
func parseWebUIHandlers(t *testing.T) (map[string][]*ast.FuncDecl, map[string]string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "webui", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("webui sources: %v", err)
	}
	fset := token.NewFileSet()
	funcs := map[string][]*ast.FuncDecl{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs[fn.Name.Name] = append(funcs[fn.Name.Name], fn)
			}
		}
	}
	table := funcs["readOnlyRoutes"]
	if len(table) != 1 {
		t.Fatalf("readOnlyRoutes: %d declarations", len(table))
	}
	handlers := map[string]string{}
	ast.Inspect(table[0].Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || len(lit.Elts) != 2 {
			return true
		}
		pattern, isLit := lit.Elts[0].(*ast.BasicLit)
		handler, isSel := lit.Elts[1].(*ast.SelectorExpr)
		if isLit && isSel && pattern.Kind == token.STRING {
			if p, unquoteErr := strconv.Unquote(pattern.Value); unquoteErr == nil {
				handlers[p] = handler.Sel.Name
			}
		}
		return true
	})
	if len(handlers) == 0 {
		t.Fatal("no routes parsed from readOnlyRoutes")
	}
	return funcs, handlers
}

// collectQueryKeys follows request and query aliases, excluding headers
// and response maps: their keys do not make a tool argument effective.
func collectQueryKeys(funcs map[string][]*ast.FuncDecl, name string, keys, seen map[string]bool) {
	if seen[name] {
		return
	}
	seen[name] = true
	for _, fn := range funcs[name] {
		bindings := map[string]string{}
		for _, field := range fn.Type.Params.List {
			for _, id := range field.Names {
				bindings[id.Name] = queryTypeKind(field.Type)
			}
		}
		ast.Walk(queryKeyVisitor{funcs, keys, seen, bindings}, fn.Body)
	}
}

type queryKeyVisitor struct {
	funcs    map[string][]*ast.FuncDecl
	keys     map[string]bool
	seen     map[string]bool
	bindings map[string]string
}

func (v queryKeyVisitor) Visit(n ast.Node) ast.Visitor {
	switch node := n.(type) {
	case *ast.BlockStmt, *ast.IfStmt, *ast.ForStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.CaseClause:
		v.bindings = maps.Clone(v.bindings)
	case *ast.RangeStmt:
		v.bindings = maps.Clone(v.bindings)
		for _, expr := range []ast.Expr{node.Key, node.Value} {
			if id, ok := expr.(*ast.Ident); ok {
				v.bindings[id.Name] = ""
			}
		}
	case *ast.FuncLit:
		v.bindings = maps.Clone(v.bindings)
		for _, field := range node.Type.Params.List {
			for _, id := range field.Names {
				v.bindings[id.Name] = ""
			}
		}
	case *ast.AssignStmt:
		// Initializers use the old binding, even when := shadows it.
		for _, rhs := range node.Rhs {
			ast.Walk(v, rhs)
		}
		kinds := make([]string, len(node.Lhs))
		if len(node.Lhs) == len(node.Rhs) {
			for i, rhs := range node.Rhs {
				kinds[i] = queryExprKind(rhs, v.bindings)
			}
		}
		for i, lhs := range node.Lhs {
			if id, ok := lhs.(*ast.Ident); ok {
				v.bindings[id.Name] = kinds[i]
			}
		}
		return nil
	case *ast.ValueSpec:
		for _, rhs := range node.Values {
			ast.Walk(v, rhs)
		}
		kinds := make([]string, len(node.Names))
		if len(node.Names) == len(node.Values) {
			for i, rhs := range node.Values {
				kinds[i] = queryExprKind(rhs, v.bindings)
			}
		}
		for i, id := range node.Names {
			v.bindings[id.Name] = kinds[i]
		}
		return nil
	case *ast.IndexExpr:
		if queryExprKind(node.X, v.bindings) == "values" {
			addStringLit(node.Index, v.keys)
		}
	case *ast.CallExpr:
		callee := calleeName(node.Fun)
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok && len(node.Args) == 1 {
			kind := queryExprKind(sel.X, v.bindings)
			if (kind == "values" && (callee == "Get" || callee == "Has")) || (kind == "request" && callee == "PathValue") {
				addStringLit(node.Args[0], v.keys)
			}
		}
		// queryInt is the route helper whose key is an argument.
		if _, local := node.Fun.(*ast.Ident); local && callee == "queryInt" && len(node.Args) == 3 && queryExprKind(node.Args[0], v.bindings) == "request" {
			addStringLit(node.Args[1], v.keys)
		}
		if _, local := v.funcs[callee]; local && passesRequest(node.Args, v.bindings) {
			collectQueryKeys(v.funcs, callee, v.keys, v.seen)
		}
	}
	return v
}

func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

func passesRequest(args []ast.Expr, bindings map[string]string) bool {
	for _, arg := range args {
		if kind := queryExprKind(arg, bindings); kind == "request" || kind == "values" {
			return true
		}
	}
	return false
}

// queryExprKind uses lexical bindings, so a shadowed q or a header alias
// cannot be mistaken for URL query values. Unknown expressions fail closed.
func queryExprKind(expr ast.Expr, bindings map[string]string) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return bindings[e.Name]
	case *ast.SelectorExpr:
		if e.Sel.Name == "URL" && queryExprKind(e.X, bindings) == "request" {
			return "url"
		}
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Query" && len(e.Args) == 0 && queryExprKind(sel.X, bindings) == "url" {
			return "values"
		}
	}
	return ""
}

func queryTypeKind(expr ast.Expr) string {
	if ptr, ok := expr.(*ast.StarExpr); ok {
		if sel, ok := ptr.X.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" && sel.Sel.Name == "Request" {
				return "request"
			}
		}
	}
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "url" && sel.Sel.Name == "Values" {
			return "values"
		}
	}
	return ""
}

func addStringLit(e ast.Expr, keys map[string]bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return
	}
	if v, err := strconv.Unquote(lit.Value); err == nil {
		keys[v] = true
	}
}
