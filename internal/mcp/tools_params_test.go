package mcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

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

// collectQueryKeys adds the string keys name reads with Get, PathValue,
// Has, an index or a query* helper, and follows calls into package
// functions that receive the request or the query values.
func collectQueryKeys(funcs map[string][]*ast.FuncDecl, name string, keys, seen map[string]bool) {
	if seen[name] {
		return
	}
	seen[name] = true
	for _, fn := range funcs[name] {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.IndexExpr:
				addStringLit(node.Index, keys)
			case *ast.CallExpr:
				callee := calleeName(node.Fun)
				if callee == "Get" || callee == "PathValue" || callee == "Has" || strings.HasPrefix(callee, "query") {
					for _, arg := range node.Args {
						addStringLit(arg, keys)
					}
				}
				if _, local := funcs[callee]; local && passesRequest(node.Args) {
					collectQueryKeys(funcs, callee, keys, seen)
				}
			}
			return true
		})
	}
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

// passesRequest reports whether a call hands on the request or query
// values: an argument named r, q or query, or an X.Query() call.
func passesRequest(args []ast.Expr) bool {
	for _, arg := range args {
		switch a := arg.(type) {
		case *ast.Ident:
			if a.Name == "r" || a.Name == "q" || a.Name == "query" {
				return true
			}
		case *ast.CallExpr:
			if calleeName(a.Fun) == "Query" {
				return true
			}
		}
	}
	return false
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
