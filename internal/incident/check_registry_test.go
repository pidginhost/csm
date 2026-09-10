package incident_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

type incidentSelectors map[string]map[string]bool

func registeredIncidentChecks() map[string]bool {
	names := make(map[string]bool)
	for _, name := range checks.AllCheckNames() {
		names[name] = true
	}
	return names
}

func TestIncidentSelectorsUseRegisteredChecks(t *testing.T) {
	registered := registeredIncidentChecks()
	for selector, members := range readIncidentSelectors(t, registered) {
		for name := range members {
			if !registered[name] {
				t.Errorf("%s selects unregistered check %q", selector, name)
			}
		}
	}
}

func readIncidentSelectors(t *testing.T, registered map[string]bool) incidentSelectors {
	t.Helper()
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	selectors := make(incidentSelectors)
	for _, entry := range files {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if err := inventoryIncidentSelectors(file, registered, selectors); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
	}
	if len(selectors) == 0 {
		t.Fatal("no incident selectors inspected")
	}
	return selectors
}

// Read production declarations without importing checks into incident, which
// would cycle through control. The independent fixture supplies expectations.
func inventoryIncidentSelectors(file *ast.File, registered map[string]bool, selectors incidentSelectors) error {
	var problems []error
	add := func(selector string, expr ast.Expr, prefix bool) {
		lit, ok := expr.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			problems = append(problems, fmt.Errorf("%s: nonliteral selector needs an inventory rule", selector))
			return
		}
		name, err := strconv.Unquote(lit.Value)
		if err != nil {
			problems = append(problems, err)
			return
		}
		if selectors[selector] == nil {
			selectors[selector] = make(map[string]bool)
		}
		if !prefix {
			selectors[selector][name] = true
			return
		}
		for check := range registered {
			if strings.HasPrefix(check, name) {
				selectors[selector][check] = true
			}
		}
	}
	for _, decl := range file.Decls {
		switch node := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range node.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range value.Names {
					var literal *ast.CompositeLit
					if i < len(value.Values) {
						literal, _ = value.Values[i].(*ast.CompositeLit)
					}
					if !strings.HasSuffix(name.Name, "Checks") && !incidentStringSet(value.Type, literal) {
						continue
					}
					selectors[name.Name] = make(map[string]bool)
					if literal == nil {
						problems = append(problems, fmt.Errorf("%s: check set needs a literal inventory", name.Name))
						continue
					}
					for _, element := range literal.Elts {
						if pair, ok := element.(*ast.KeyValueExpr); ok {
							if flag, ok := pair.Value.(*ast.Ident); ok && flag.Name != "true" {
								problems = append(problems, fmt.Errorf("%s: disabled or computed member needs an inventory rule", name.Name))
							}
							add(name.Name, pair.Key, false)
						} else {
							add(name.Name, element, false)
						}
					}
				}
			}
		case *ast.FuncDecl:
			if !incidentCheckSelector(node) {
				continue
			}
			ast.Inspect(node.Body, func(n ast.Node) bool {
				switch selection := n.(type) {
				case *ast.SwitchStmt:
					if !incidentCheckExpression(selection.Tag) {
						break
					}
					if selectors[node.Name.Name] == nil {
						selectors[node.Name.Name] = make(map[string]bool)
					}
					for _, statement := range selection.Body.List {
						for _, expr := range statement.(*ast.CaseClause).List {
							add(node.Name.Name, expr, false)
						}
					}
				case *ast.CallExpr:
					fn, ok := selection.Fun.(*ast.SelectorExpr)
					if !ok || fn.Sel.Name != "HasPrefix" || len(selection.Args) != 2 || !incidentCheckExpression(selection.Args[0]) {
						break
					}
					pkg, ok := fn.X.(*ast.Ident)
					if ok && pkg.Name == "strings" {
						add(node.Name.Name, selection.Args[1], true)
					}
				}
				return true
			})
		}
	}
	return errors.Join(problems...)
}

func incidentStringSet(typ ast.Expr, literal *ast.CompositeLit) bool {
	if literal != nil {
		typ = literal.Type
	}
	set, ok := typ.(*ast.MapType)
	if !ok {
		return false
	}
	key, ok := set.Key.(*ast.Ident)
	if !ok || key.Name != "string" {
		return false
	}
	switch value := set.Value.(type) {
	case *ast.Ident:
		return value.Name == "bool"
	case *ast.StructType:
		return len(value.Fields.List) == 0
	}
	return false
}

func incidentCheckSelector(fn *ast.FuncDecl) bool {
	for _, parameter := range fn.Type.Params.List {
		typ, ok := parameter.Type.(*ast.Ident)
		if !ok || typ.Name != "string" {
			continue
		}
		for _, name := range parameter.Names {
			if name.Name == "check" {
				return true
			}
		}
	}
	return false
}

func incidentCheckExpression(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == "check" {
			found = true
		}
		return true
	})
	return found
}
