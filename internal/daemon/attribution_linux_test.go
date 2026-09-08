//go:build linux

package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// The live audit listener resolves the audit uid through the shared passwd
// cache and stamps the hosting account; an unknown uid stays unattributed.
func TestAFAlgAuditListenerStampsOwner(t *testing.T) {
	withOwnerTable(t)
	passwd := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(passwd, []byte("alice:x:1001:1001::/home/alice:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checks.SwapUIDCacheForTest(passwd))
	_, _ = withAuditLog(t)
	ch := make(chan alert.Finding, 2)
	l, err := NewAFAlgAuditListener(ch, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	l.handleLine(sampleAFAlgLine)
	unknown := `type=SYSCALL msg=audit(1761826284.452:91235): arch=c000003e syscall=41 success=yes exit=3 a0=38 a1=5 a2=2 a3=0 items=0 ppid=12 pid=4243 auid=4294967295 uid=4242 gid=4242 euid=4242 suid=4242 fsuid=4242 egid=4242 sgid=4242 fsgid=4242 tty=pts0 ses=2 comm="exploit" exe="/tmp/exploit" key="csm_af_alg_socket"`
	l.handleLine(unknown)
	got := []alert.Finding{<-ch, <-ch}
	requireOwner(t, got[:1], "af_alg_socket_use", "alice")
	requireOwner(t, got[1:], "af_alg_socket_use", "")
}

// realtimeEmissionSites reports, for each check name, how many string
// literals of that name appear in fanotify.go and how many of them sit in a
// path-carrying emission: an argument to sendAlertWithPath, or a Finding
// literal that also sets FilePath. A dedup lookup through shouldAlert is
// neither and is ignored.
func realtimeEmissionSites(t *testing.T, names []string) (total, stamped map[string]int) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fanotify.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}
	total, stamped = map[string]int{}, map[string]int{}
	ignored := map[token.Pos]bool{}
	literalName := func(e ast.Expr) (string, bool) {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(lit.Value)
		return s, err == nil && wanted[s]
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "sendAlertWithPath":
				// (severity, check, message, details, path, procInfo)
				if len(x.Args) >= 2 {
					if name, ok := literalName(x.Args[1]); ok {
						stamped[name]++
					}
				}
			case "shouldAlert":
				// (check, key): a dedup lookup, not an emission.
				if len(x.Args) >= 1 {
					if _, ok := literalName(x.Args[0]); ok {
						ignored[x.Args[0].Pos()] = true
					}
				}
			}
		case *ast.CompositeLit:
			var name string
			hasCheck, hasPath := false, false
			for _, el := range x.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch key.Name {
				case "Check":
					name, hasCheck = literalName(kv.Value)
				case "FilePath":
					hasPath = true
				}
			}
			if hasCheck && hasPath {
				stamped[name]++
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		if name, ok := literalName(toExpr(n)); ok && !ignored[n.Pos()] {
			total[name]++
		}
		return true
	})
	return total, stamped
}

func toExpr(n ast.Node) ast.Expr {
	if e, ok := n.(ast.Expr); ok {
		return e
	}
	return nil
}

// Every realtime file family is emitted with the judged file's path: each
// emission site in fanotify.go goes through sendAlertWithPath or sets
// FilePath, and the helper carries the path so the owner resolves from it.
func TestFanotifyFindingsAttributeByPath(t *testing.T) {
	names := []string{
		"cgi_backdoor_realtime", "cgi_suspicious_location_realtime", "credential_log_realtime",
		"executable_in_tmp_realtime", "htaccess_injection_realtime", "phishing_kit_realtime",
		"phishing_realtime", "php_dropper_realtime", "signature_match_realtime",
	}
	total, stamped := realtimeEmissionSites(t, names)
	sort.Strings(names)
	for _, name := range names {
		if total[name] == 0 {
			t.Errorf("%s: no emission site in fanotify.go", name)
		}
		if total[name] != stamped[name] {
			t.Errorf("%s: %d emission sites, %d carry a path", name, total[name], stamped[name])
		}
	}

	alerts := make(chan alert.Finding, len(names))
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	for _, name := range names {
		fm.sendAlertWithPath(alert.Critical, name, name+" fixture", "fixture", "/home/alice/public_html/"+name+".php", "")
	}
	var findings []alert.Finding
	for range names {
		findings = append(findings, <-alerts)
	}
	for _, f := range findings {
		requireOwner(t, []alert.Finding{f}, f.Check, "")
	}
	res := checks.CorrelateFindings(append(findings,
		alert.Finding{Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "carol"},
		alert.Finding{Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "dave"}))
	if len(res.Derived) != 1 || len(res.Unattributed) != 0 {
		t.Fatalf("path-attributed realtime findings did not aggregate: %+v", res)
	}
}
