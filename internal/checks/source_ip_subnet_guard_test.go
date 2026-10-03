package checks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SourceIP is an address field: a subnet belongs in CIDRs, where consumers
// read it as a subnet. No production Finding literal may put a subnet in
// SourceIP.
func TestNoProductionLiteralPutsASubnetInSourceIP(t *testing.T) {
	subnetLike := regexp.MustCompile(`(?i)cidr|subnet|prefix|"[^"]*/[^"]*"`)
	root := findRepoRoot(t)
	fset := token.NewFileSet()
	var offenders []string
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".cache", "vendor", "testdata", "node_modules", "e2e":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		file, parseErr := parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "SourceIP" {
				return true
			}
			value := string(src[fset.Position(kv.Value.Pos()).Offset:fset.Position(kv.Value.End()).Offset])
			if subnetLike.MatchString(value) {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, rel+": SourceIP: "+value)
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if len(offenders) > 0 {
		t.Fatalf("subnets put in SourceIP:\n%s", strings.Join(offenders, "\n"))
	}
}
