package admissionowner

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// productionFiles parses every non-test Go file of the module, skipping
// hidden directories (worktrees, caches) and test data.
func productionFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	root := filepath.Join("..", "..")
	files := map[string]*ast.File{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 100 {
		t.Fatalf("parsed only %d production files", len(files))
	}
	return files
}

func inPackage(path, dir string) bool { return filepath.ToSlash(filepath.Dir(path)) == dir }

// Handoffs O1, O26 and O27: the owner is the only production code that
// opens or names the ledger, the owner never queues or publishes directly,
// and the admission package's own code reaches the ledger only through the
// ingress group commit. Detectors will hand work to the ingress; nothing
// else may create candidates or evidence, or a second handle.
func TestProductionStaysOffTheLedgerEntryPoints(t *testing.T) {
	for path, f := range productionFiles(t) {
		for _, violation := range ledgerEntryViolations(path, f) {
			t.Error(violation)
		}
	}
}

func ledgerEntryViolations(path string, f *ast.File) []string {
	var violations []string
	owner, ledgerPkg := inPackage(path, "internal/admissionowner"), inPackage(path, "internal/store")
	admissionNames := map[string]bool{}
	for _, imp := range f.Imports {
		if imp.Path.Value == `"github.com/pidginhost/csm/internal/admission"` {
			name := "admission"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			admissionNames[name] = true
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if (x.Name == "AdmissionLedger" || x.Name == "OpenAdmissionLedger" || x.Name == "Ledger" && admissionNames["."]) && !owner && !ledgerPkg {
				violations = append(violations, fmt.Sprintf("%s names %s outside the owner", path, x.Name))
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == "Submit" && !owner {
				violations = append(violations, fmt.Sprintf("%s submits outside the owner; funnels respond through it", path))
			}
			if name := x.Sel.Name; (name == "OpenAdmissionLedger" || name == "AdmissionLedger") && !owner && !ledgerPkg {
				violations = append(violations, fmt.Sprintf("%s names %s; only the admission owner holds the ledger", path, name))
			}
			if id, ok := x.X.(*ast.Ident); ok && admissionNames[id.Name] && x.Sel.Name == "Ledger" && !owner && !ledgerPkg {
				violations = append(violations, fmt.Sprintf("%s holds the ledger interface outside the owner", path))
			}
			if (x.Sel.Name == "PublishEvidence" && !ledgerPkg) || (x.Sel.Name == "Enqueue" && (owner || inPackage(path, "internal/admission"))) {
				violations = append(violations, fmt.Sprintf("%s references %s; production work enters through the ingress", path, x.Sel.Name))
			}
			if x.Sel.Name == "EnqueueGroup" && !ledgerPkg && path != "internal/admission/ingress.go" {
				violations = append(violations, fmt.Sprintf("%s commits arrivals outside the ingress", path))
			}
		}
		return true
	})
	return violations
}

func TestLedgerEntryGuardRejectsAlternateAccess(t *testing.T) {
	for _, tc := range []struct {
		name, path, source string
		wantViolation      bool
	}{
		{"dot imported interface", "internal/daemon/example.go", `package daemon
import . "github.com/pidginhost/csm/internal/admission"
var handle Ledger`, true},
		{"aliased interface", "internal/daemon/example.go", `package daemon
import adm "github.com/pidginhost/csm/internal/admission"
var handle adm.Ledger`, true},
		{"owner group method value", "internal/admissionowner/example.go", `package admissionowner
func (o *Owner) bypass() { _ = o.ledger.EnqueueGroup }`, true},
		{"group outside ingress", "internal/daemon/example.go", `package daemon
func bypass(handle interface{ EnqueueGroup() }) { _ = handle.EnqueueGroup }`, true},
		{"ingress group commit", "internal/admission/ingress.go", `package admission
func drain(handle Ledger) { _ = handle.EnqueueGroup }`, false},
		{"store group implementation", "internal/store/example.go", `package store
func commit(handle *AdmissionLedger) { _ = handle.EnqueueGroup }`, false},
		{"owner interface", "internal/admissionowner/example.go", `package admissionowner
import . "github.com/pidginhost/csm/internal/admission"
var handle Ledger`, false},
		{"detector submits to an ingress", "internal/checks/example.go", `package checks
func bypass(in interface{ Submit(int) error }) { _ = in.Submit(1) }`, true},
		{"owner submits to its ingress", "internal/admissionowner/example.go", `package admissionowner
func (o *Owner) respond(s int) error { return o.ingress.Submit(s) }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), tc.path, tc.source, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			violations := ledgerEntryViolations(tc.path, f)
			if got := len(violations) > 0; got != tc.wantViolation {
				t.Fatalf("violations = %v, want rejected = %v", violations, tc.wantViolation)
			}
		})
	}
}

// The owner hands its ledger to nobody: no exported function or method
// returns it.
func TestOwnerExportsNoLedger(t *testing.T) {
	checked := 0
	files := productionFiles(t)
	aliases := map[string]ast.Expr{}
	for path, f := range files {
		if !inPackage(path, "internal/admissionowner") {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if typ, ok := n.(*ast.TypeSpec); ok {
				if _, wrapper := typ.Type.(*ast.StructType); !wrapper {
					aliases[typ.Name.Name] = typ.Type
				}
			}
			return true
		})
	}
	for path, f := range files {
		if !inPackage(path, "internal/admissionowner") {
			continue
		}
		checked++
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				if x.Name.IsExported() && x.Body != nil {
					ast.Inspect(x.Body, func(n ast.Node) bool {
						if ret, ok := n.(*ast.ReturnStmt); ok {
							for _, value := range ret.Results {
								if sel, ok := value.(*ast.SelectorExpr); ok && sel.Sel.Name == "ledger" {
									t.Errorf("%s: %s returns its ledger value", path, x.Name.Name)
								}
							}
						}
						return true
					})
				}
				if x.Name.IsExported() && x.Type.Results != nil {
					for _, r := range x.Type.Results.List {
						if holdsLedger(r.Type, aliases, map[string]bool{}) {
							t.Errorf("%s: %s returns the ledger", path, x.Name.Name)
						}
					}
				}
			case *ast.Field:
				if len(x.Names) == 0 && holdsLedger(x.Type, aliases, map[string]bool{}) {
					t.Errorf("%s embeds the ledger", path)
				}
				for _, name := range x.Names {
					if name.IsExported() && holdsLedger(x.Type, aliases, map[string]bool{}) {
						t.Errorf("%s: exported field %s holds the ledger", path, name.Name)
					}
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no owner files checked")
	}
}

func TestOwnerExportGuardRecognizesGroupWriterInterfaces(t *testing.T) {
	expr, err := parser.ParseExpr(`interface {
		EnqueueGroup([]admission.Arrival, *admission.IngressCheckpoint) ([]admission.ArrivalResult, int, error)
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if !holdsLedger(expr, nil, map[string]bool{}) {
		t.Fatal("an exported group-writer interface can hand out the ledger")
	}
}

func holdsLedger(expr ast.Expr, aliases map[string]ast.Expr, seen map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if field, ok := n.(*ast.Field); ok {
			for _, name := range field.Names {
				if name.Name == "Enqueue" || name.Name == "EnqueueGroup" || name.Name == "PublishEvidence" {
					found = true
				}
			}
		}
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name == "AdmissionLedger" || id.Name == "Ledger" {
			found = true
		}
		if alias, ok := aliases[id.Name]; ok && !seen[id.Name] {
			seen[id.Name] = true
			found = holdsLedger(alias, aliases, seen) || found
		}
		return true
	})
	return found
}
