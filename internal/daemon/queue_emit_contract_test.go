package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every finding producer must count delivery failure. Keeping the raw
// channel sends out of watcher code prevents a new producer silently
// bypassing the shared queue's accounting.
func TestFindingProducersUseAccountedQueueSends(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			s, ok := n.(*ast.SendStmt)
			if !ok {
				return true
			}
			name := ""
			switch ch := s.Chan.(type) {
			case *ast.SelectorExpr:
				name = ch.Sel.Name
			case *ast.Ident:
				name = ch.Name
			}
			if name == "alertCh" {
				t.Errorf("%s sends a finding without shared queue accounting", fset.Position(s.Pos()))
			}
			return true
		})
	}
}
