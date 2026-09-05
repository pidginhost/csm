package checks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Every database-content finding renders dbContentFindingDetails, whose
// document-root line reports what the panel map said this scan rather than
// what was found in the database. A finding that leaves its identity to the
// default Message+Details hash therefore mints a second copy of itself
// whenever that map read flaps. Pairing the two calls is the contract; this
// test is what keeps a new call site from quietly dropping half of it.
func TestDBContentFindingsPinTheirIdentity(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing package files: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, name, nil, 0)
		if parseErr != nil {
			t.Fatalf("parsing %s: %v", name, parseErr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, finding := range findingLiterals(lit) {
				checked += checkFindingLiteral(t, fset, finding)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("found no database-content findings to check; the test no longer matches the code")
	}
}

// findingLiterals returns the alert.Finding literals lit denotes. A slice
// literal elides the element type on its entries, and the check that first
// showed this defect in production is written that way, so both shapes count.
func findingLiterals(lit *ast.CompositeLit) []*ast.CompositeLit {
	if isAlertFindingType(lit.Type) {
		return []*ast.CompositeLit{lit}
	}
	arr, ok := lit.Type.(*ast.ArrayType)
	if !ok || !isAlertFindingType(arr.Elt) {
		return nil
	}
	var out []*ast.CompositeLit
	for _, elt := range lit.Elts {
		if inner, isLit := elt.(*ast.CompositeLit); isLit && inner.Type == nil {
			out = append(out, inner)
		}
	}
	return out
}

// checkFindingLiteral reports 1 when lit builds a database-content finding,
// failing t when that finding leaves its identity unpinned.
func checkFindingLiteral(t *testing.T, fset *token.FileSet, lit *ast.CompositeLit) int {
	t.Helper()
	var buildsDBDetails, pinsIdentity bool
	for _, elt := range lit.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if !isKV {
			continue
		}
		key, isIdent := kv.Key.(*ast.Ident)
		if !isIdent {
			continue
		}
		if key.Name == "DedupKey" {
			pinsIdentity = true
		}
		if key.Name == "Details" && callsIdent(kv.Value, "dbContentFindingDetails") {
			buildsDBDetails = true
		}
	}
	if !buildsDBDetails {
		return 0
	}
	if !pinsIdentity {
		t.Errorf("%s: alert.Finding built with dbContentFindingDetails has no DedupKey, so a served-state flip stores a second copy of it",
			fset.Position(lit.Pos()))
	}
	return 1
}

func isAlertFindingType(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Finding" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "alert"
}

// callsIdent reports whether expr contains a call to the named function.
func callsIdent(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if fn, isIdent := call.Fun.(*ast.Ident); isIdent && fn.Name == name {
			found = true
		}
		return !found
	})
	return found
}
