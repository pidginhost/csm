package webui

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type apiRouteContract struct {
	Path   string
	Method string
	Scope  string
	Source string
}

type openAPIDocument struct {
	OpenAPI    string `yaml:"openapi"`
	Components struct {
		SecuritySchemes map[string]openAPISecurityScheme `yaml:"securitySchemes"`
	} `yaml:"components"`
	Security []map[string][]string                  `yaml:"security"`
	Paths    map[string]map[string]openAPIOperation `yaml:"paths"`
}

type openAPISecurityScheme struct {
	Type   string `yaml:"type"`
	Scheme string `yaml:"scheme"`
}

type openAPIOperation struct {
	Scope    string                `yaml:"x-csm-scope"`
	Security []map[string][]string `yaml:"security"`
}

var openAPIMethods = map[string]struct{}{
	"delete": {},
	"get":    {},
	"patch":  {},
	"post":   {},
	"put":    {},
}

var openAPIPrimaryMethodOverrides = map[string]string{
	// These CSRF-wrapped handlers use PUT for writes. Documenting POST points
	// API clients at a method the handlers reject.
	"/api/v1/prefs/user":  "put",
	"/api/v1/prefs/views": "put",
}

// registeredAPIRoutes scans every non-test Go source in this package for
// mux.Handle("/api/v1/...") registrations and derives the method/scope from
// the same route convention used to generate docs/src/openapi.yaml.
func registeredAPIRoutes(t *testing.T) map[string]apiRouteContract {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	routes := map[string]apiRouteContract{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name) // #nosec G304 -- package-local source file
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, data, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isMuxHandleCall(call) || len(call.Args) < 2 {
				return true
			}
			raw, ok := stringLiteral(call.Args[0])
			if !ok {
				return true
			}

			// Go 1.22+ supports method-qualified patterns: "POST /api/v1/..."
			// Split off an optional leading HTTP method word.
			path := raw
			methodOverride := ""
			if i := strings.IndexByte(raw, ' '); i > 0 {
				word := raw[:i]
				rest := raw[i+1:]
				if isHTTPMethod(word) {
					path = rest
					methodOverride = strings.ToLower(word)
				}
			}

			if !strings.HasPrefix(path, "/api/v1/") {
				return true
			}

			source := fset.Position(call.Pos()).String()
			route := apiRouteContract{
				Path:   path,
				Method: "get",
				Scope:  "admin",
				Source: source,
			}

			// Method: explicit override beats CSRF-derived inference.
			if methodOverride != "" {
				route.Method = methodOverride
			} else if exprContainsCall(call.Args[1], "requireCSRF") {
				route.Method = "post"
			}
			if m, ok := openAPIPrimaryMethodOverrides[path]; ok {
				route.Method = m
			}

			switch {
			case exprContainsCall(call.Args[1], "requireRead"):
				route.Scope = "read"
			case exprContainsCall(call.Args[1], "requireAuth"):
				route.Scope = "admin"
			default:
				t.Errorf("%s has no requireRead/requireAuth wrapper", route.Source)
			}

			// Method-qualified patterns for the same path are allowed to
			// co-exist with an unqualified registration (e.g. GET reads and
			// POST writes sharing a path prefix). Use "METHOD:path" as the
			// dedup key so both are tracked independently.
			key := path
			if methodOverride != "" {
				key = methodOverride + ":" + path
			}
			if prev, exists := routes[key]; exists {
				t.Errorf("%s duplicates %s registered at %s", source, key, prev.Source)
				return true
			}
			routes[key] = route
			return true
		})
	}
	return routes
}

// isHTTPMethod reports whether word is one of the standard HTTP methods
// that Go 1.22's ServeMux accepts as a pattern prefix.
func isHTTPMethod(word string) bool {
	switch word {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return true
	}
	return false
}

func isMuxHandleCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Handle" {
		return false
	}
	recv, ok := sel.X.(*ast.Ident)
	return ok && recv.Name == "mux"
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

func exprContainsCall(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			found = fun.Name == name
		case *ast.SelectorExpr:
			found = fun.Sel.Name == name
		}
		return !found
	})
	return found
}

func loadOpenAPIDocument(t *testing.T) openAPIDocument {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "src", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc openAPIDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Fatalf("openapi version = %q, want 3.1.0", doc.OpenAPI)
	}
	if len(doc.Paths) == 0 {
		t.Fatal("openapi.yaml has no paths")
	}
	return doc
}

// documentedAPIRoutes parses the committed OpenAPI spec structurally so YAML
// formatting changes cannot hide path, method, or scope drift.
//
// The key scheme matches registeredAPIRoutes:
//   - Single-method paths use the plain path as the key (regardless of
//     method), so unqualified mux.Handle registrations match them.
//   - Multi-method paths (e.g. GET + POST on the same path, arising from
//     Go 1.22 method-qualified registrations) emit one entry per method
//     keyed as "method:path" for non-GET methods and plain path for GET.
func documentedAPIRoutes(t *testing.T) map[string]apiRouteContract {
	t.Helper()
	doc := loadOpenAPIDocument(t)
	routes := map[string]apiRouteContract{}
	for path, item := range doc.Paths {
		if !strings.HasPrefix(path, "/api/v1/") {
			t.Errorf("non-/api/v1 path documented in openapi.yaml: %s", path)
			continue
		}
		methods := documentedMethods(item)
		if len(methods) == 0 {
			t.Errorf("%s has no HTTP operation", path)
			continue
		}
		multiMethod := len(methods) > 1
		for _, method := range methods {
			op := item[method]
			if op.Scope != "read" && op.Scope != "admin" {
				t.Errorf("%s %s has x-csm-scope = %q, want read or admin", method, path, op.Scope)
			}
			// Multi-method paths have both a plain-path GET entry and a
			// "method:path" key for non-GET so they match the method-qualified
			// mux registrations ("POST /api/v1/...") detected by the scanner.
			// Single-method paths always use the plain path regardless of method
			// to match unqualified mux.Handle registrations.
			key := path
			if multiMethod && method != "get" {
				key = method + ":" + path
			}
			routes[key] = apiRouteContract{
				Path:   path,
				Method: method,
				Scope:  op.Scope,
				Source: "docs/src/openapi.yaml",
			}
		}
	}
	return routes
}

func documentedMethods(item map[string]openAPIOperation) []string {
	methods := make([]string, 0, len(item))
	for key := range item {
		if _, ok := openAPIMethods[key]; ok {
			methods = append(methods, key)
		}
	}
	sort.Strings(methods)
	return methods
}

// TestOpenAPISpecCoversAllRoutes is the drift guard: every registered
// /api/v1/* route must appear in docs/src/openapi.yaml with the method and
// auth scope derived from its wrapper, and every documented path must map to a
// real registered route. Adding or changing a route without updating the spec
// fails here.
func TestOpenAPISpecCoversAllRoutes(t *testing.T) {
	registered := registeredAPIRoutes(t)
	documented := documentedAPIRoutes(t)

	if len(registered) == 0 {
		t.Fatal("found no registered /api/v1 routes -- scanner likely broke")
	}

	var missing []string
	var methodMismatches []string
	var scopeMismatches []string
	for key, route := range registered {
		doc, ok := documented[key]
		if !ok {
			missing = append(missing, key)
			continue
		}
		if route.Method != doc.Method {
			methodMismatches = append(methodMismatches, fmt.Sprintf("%s: registered %s at %s, documented %s", key, route.Method, route.Source, doc.Method))
		}
		if route.Scope != doc.Scope {
			scopeMismatches = append(scopeMismatches, fmt.Sprintf("%s: registered %s at %s, documented %s", key, route.Scope, route.Source, doc.Scope))
		}
	}
	var extra []string
	for key := range documented {
		if _, ok := registered[key]; !ok {
			extra = append(extra, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(methodMismatches)
	sort.Strings(scopeMismatches)
	if len(missing) > 0 {
		t.Errorf("routes registered but missing from docs/src/openapi.yaml: %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("paths documented in openapi.yaml with no registered route: %v", extra)
	}
	if len(methodMismatches) > 0 {
		t.Errorf("OpenAPI method drift: %v", methodMismatches)
	}
	if len(scopeMismatches) > 0 {
		t.Errorf("OpenAPI auth scope drift: %v", scopeMismatches)
	}
}

func TestOpenAPISpecSecuritySchemeMatchesWebUIAuth(t *testing.T) {
	doc := loadOpenAPIDocument(t)
	bearer, ok := doc.Components.SecuritySchemes["bearerAuth"]
	if !ok {
		t.Fatal("openapi.yaml missing bearerAuth security scheme")
	}
	if bearer.Type != "http" || bearer.Scheme != "bearer" {
		t.Fatalf("bearerAuth = type %q scheme %q, want http bearer", bearer.Type, bearer.Scheme)
	}
	if !securityIncludesBearer(doc.Security) {
		t.Fatal("openapi.yaml top-level security must require bearerAuth")
	}

	documented := documentedAPIRoutes(t)
	for _, route := range documented {
		op := doc.Paths[route.Path][route.Method]
		if !securityIncludesBearer(op.Security) {
			t.Errorf("%s %s must require bearerAuth", route.Method, route.Path)
		}
	}
}

func securityIncludesBearer(security []map[string][]string) bool {
	for _, requirement := range security {
		if _, ok := requirement["bearerAuth"]; ok {
			return true
		}
	}
	return false
}
