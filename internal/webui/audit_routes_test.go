package webui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Handlers behind requireCSRF change state. They must leave a UI audit entry
// on every path that changes something, and a new handler must not be able to
// skip the audit trail unnoticed. Each exemption below names why the handler
// is not an operator action on the host.
var auditExemptHandlers = map[string]string{
	"apiPrefsUser":      "per-operator display preferences, not host state",
	"apiPrefsViews":     "per-operator saved filter views, not host state",
	"apiGeoIPBatch":     "POST only because the lookup list is large; read-only",
	"apiUndoRun":        "audits as undo_<action> through runUndoEntry",
	"apiSettings":       "dispatches POST to apiSettingsPost",
	"apiIncidentRouter": "dispatches to the incident handlers checked below",
}

func serverMethodCalls(t *testing.T) (map[string][]string, map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string][]string{}
	audits := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			method := fn.Name.Name
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "s" {
					if sel.Sel.Name == "auditLog" || sel.Sel.Name == "auditLogAs" {
						audits[method] = true
					}
					calls[method] = append(calls[method], sel.Sel.Name)
				}
				return true
			})
		}
	}
	return calls, audits
}

func reachesAudit(method string, calls map[string][]string, audits map[string]bool) bool {
	seen := map[string]bool{}
	queue := []string{method}
	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]
		if seen[m] {
			continue
		}
		seen[m] = true
		if audits[m] {
			return true
		}
		queue = append(queue, calls[m]...)
	}
	return false
}

func TestEveryCSRFProtectedHandlerWritesAnAuditEntry(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	routes := regexp.MustCompile(`requireCSRF\(http\.HandlerFunc\(s\.(\w+)\)\)`).FindAllStringSubmatch(string(src), -1)
	if len(routes) < 40 {
		t.Fatalf("found %d CSRF-protected routes; the route pattern changed", len(routes))
	}
	handlers := map[string]bool{}
	for _, m := range routes {
		handlers[m[1]] = true
	}
	// Handlers reached through a dispatcher rather than a route.
	for _, h := range []string{"apiSettingsPost", "apiIncidentStatus"} {
		handlers[h] = true
	}
	calls, audits := serverMethodCalls(t)
	var missing []string
	for h := range handlers {
		if _, exempt := auditExemptHandlers[h]; exempt {
			continue
		}
		if !reachesAudit(h, calls, audits) {
			missing = append(missing, h)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("state-changing handlers with no UI audit entry: %s", strings.Join(missing, ", "))
	}
}

// Browser logins, failed logins, logouts and session revocations are
// security events and belong in the same trail.
func TestSessionLifecycleHandlersWriteAuditEntries(t *testing.T) {
	calls, audits := serverMethodCalls(t)
	for _, h := range []string{"handleLogin", "handleLogout", "handleSessionRevoke", "apiSessions"} {
		if !reachesAudit(h, calls, audits) {
			t.Errorf("%s writes no UI audit entry", h)
		}
	}
}
