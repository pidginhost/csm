package checks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The IP response policy lives in the check registry. A second table in the
// block or challenge path would let the two drift apart again.
func TestResponsePolicyHasNoLegacyTables(t *testing.T) {
	legacy := map[string]bool{
		"alwaysBlockChecks":          true,
		"cpanelWebmailFailureChecks": true,
		"challengeableChecks":        true,
		"hardBlockChecks":            true,
		"hardBlockPrefixes":          true,
	}
	fset := token.NewFileSet()
	for _, path := range []string{"autoblock.go", "challenge_route.go"} {
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for _, name := range spec.Names {
				if legacy[name.Name] {
					t.Errorf("%s declares %s; the IP response policy belongs in the check registry", path, name.Name)
				}
			}
			return true
		})
	}
}
