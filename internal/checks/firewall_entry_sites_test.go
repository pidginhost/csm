package checks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/sourcewalk"
)

// firewallMutations are the firewall engine's methods that change what is
// blocked or allowed. A call to one of these names outside the firewall
// package, or a reference that hands the method on as a value, is a
// firewall call site.
var firewallMutations = []string{
	"AllowIP", "AllowIPPort", "ApplyBlockBatch", "BlockIP", "BlockIPForUndo", "BlockIPForce",
	"BlockIPForcePreserveLifetime", "BlockIPOutcome", "BlockIPOutcomeWithFindingID", "BlockIPRequest",
	"BlockSubnet", "BlockSubnetRequest", "BlockSubnetWithFindingID", "CleanExpiredAllows",
	"CleanExpiredSubnets", "FlushBlocked", "PromoteToPermanentBlock", "PromoteToPermanentBlockWithFindingID",
	"RemoveAllowIP", "RemoveAllowIPBySource", "RemoveAllowIPPort", "RemoveBlockActionRows",
	"RestoreBlockIfUnchanged", "RetireBlockActions", "TempAllowIP", "UnbanIP", "UnblockIP",
	"UnblockIPForUndo", "UnblockSubnet", "UnblockSubnetIfUnchanged", "UndoAction",
}

// Site classes that are not admission entries.
const (
	siteManual   = "manual"   // an operator's command, API or web UI action
	siteCleanup  = "cleanup"  // expiry, pruning or recovery of existing rows
	siteExecutor = "executor" // admission's own executor applying an admitted effect
	siteFunnel   = "funnel"   // a shared helper: its callers are sites too
)

// firewallSites assigns every production function that calls a firewall
// mutation, or a funnel, to the admission entries it serves (comma
// separated) or to one class that needs none. A funnel's callers are
// classified in turn.
var firewallSites = map[string]string{
	"internal/admissionowner/execute.go:Owner.execute":                                     "executor",
	"internal/admissionowner/execute.go:Owner.retireEvicted":                               "executor",
	"internal/admissionowner/retire.go:Owner.checkRetirements":                             "executor",
	"internal/checks/applyblock.go:ApplyBlock":                                             "funnel",
	"internal/checks/applyblock.go:applyBlockLocked":                                       "funnel",
	"internal/checks/autoblock.go:AutoBlockIPs":                                            "scan,mail_subnet,asn_crawl,netblock",
	"internal/checks/autoblock.go:callBlockIP":                                             "funnel",
	"internal/checks/autoblock.go:callBlockSubnet":                                         "funnel",
	"internal/checks/autoblock.go:promoteToPermanentBlock":                                 "permblock",
	"internal/checks/autoblock.go:pruneExemptAutoSubnets":                                  "cleanup",
	"internal/daemon/central_consume.go:Daemon.performCentralAction":                       "central",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallAllowFile":    "manual",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallDenySubnet":   "manual",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallFlush":        "manual",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallRemoveSubnet": "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallAllow":       "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallAllowPort":   "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallRemoveAllow": "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallRemovePort":  "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallTempAllow":   "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallUnblock":     "manual",
	"internal/daemon/control_firewall_mutate.go:operatorForceBlock":                        "manual",
	"internal/daemon/daemon.go:Daemon.applyIncidentBlock":                                  "incident,incident_spray",
	"internal/daemon/daemon.go:Daemon.escalateExpiredChallenges":                           "challenge_timeout",
	"internal/daemon/daemon.go:Daemon.heartbeat":                                           "cleanup",
	"internal/daemon/firewall_startup.go:gateFirewallRows":                                 "cleanup",
	"internal/webui/api.go:Server.apiUnblockIP":                                            "manual",
	"internal/webui/block_lifetime.go:Server.blockIPForUndo":                               "manual",
	"internal/webui/block_lifetime.go:Server.blockIPPreservingLifetime":                    "manual",
	"internal/webui/block_lifetime.go:Server.unblockIPForUndo":                             "manual",
	"internal/webui/block_lifetime.go:Server.undoSnapshotBlocks":                           "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallAllowIP":                             "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallDenySubnet":                          "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallFlush":                               "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallRemoveAllow":                         "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallRemoveSubnet":                        "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallUnban":                               "manual",
	"internal/webui/server.go:blockIPForOperator":                                          "manual",
	"internal/webui/threat_api.go:Server.apiThreatUnwhitelistIP":                           "manual",
	"internal/webui/threat_api.go:Server.releaseIP":                                        "manual",
	"internal/webui/undo_api.go:Server.undoBulkBlock":                                      "manual",
	"internal/webui/undo_api.go:Server.undoBulkWhitelist":                                  "manual",
}

// TestFirewallCallSitesNameTheirEntry walks every production call of, or
// reference to, a firewall mutation outside the firewall package. Each calling function
// must name the automatic entry it acts for, or why it needs none, so a new
// path that changes the firewall cannot bypass admission unnoticed.
func TestFirewallCallSitesNameTheirEntry(t *testing.T) {
	classes := map[string]bool{siteManual: true, siteCleanup: true, siteExecutor: true, siteFunnel: true}
	entries := map[string]bool{}
	for e := admission.EntryScan; e.Valid(); e++ {
		entries[e.String()] = true
	}
	root := findRepoRoot(t)
	calls := firewallCallers(t, root)
	watched := map[string]bool{}
	for _, name := range firewallMutations {
		watched[name] = true
	}
	// A funnel's own name joins the watched set until no new one appears.
	for {
		grew := false
		for site, class := range firewallSites {
			if class != siteFunnel {
				continue
			}
			name := site[strings.LastIndex(site, ":")+1:]
			name = name[strings.LastIndex(name, ".")+1:]
			if !watched[name] {
				watched[name], grew = true, true
			}
		}
		if !grew {
			break
		}
	}
	sites := map[string][]string{}
	for site, callees := range calls {
		for _, callee := range callees {
			if watched[callee] && !strings.Contains(","+strings.Join(sites[site], ",")+",", ","+callee+",") {
				sites[site] = append(sites[site], callee)
			}
		}
	}
	var missing []string
	for site, callees := range sites {
		if _, ok := firewallSites[site]; !ok {
			sort.Strings(callees)
			missing = append(missing, site+" "+strings.Join(callees, ","))
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("unreviewed firewall call site: %s", m)
	}
	served := map[string]bool{}
	for site, class := range firewallSites {
		if !classes[class] {
			for _, entry := range strings.Split(class, ",") {
				if !entries[entry] {
					t.Errorf("%s names %q, which is neither entries nor a site class", site, class)
				}
				served[entry] = true
			}
		}
		if _, ok := sites[site]; !ok {
			t.Errorf("firewallSites lists %s, which calls no firewall mutation or funnel", site)
		}
	}
	for entry := range entries {
		if !served[entry] {
			t.Errorf("entry %s has no firewall call site", entry)
		}
	}
}

// firewallCallers maps each production function outside internal/firewall
// to the names it calls or hands on as values: every selected name, and
// every plain name called, passed as an argument, assigned or returned. stampSiteKey
// names the function.
func firewallCallers(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, top := range []string{"internal", "cmd"} {
		dir := filepath.Join(root, top)
		err := filepath.WalkDir(dir, sourcewalk.IgnoreVanished(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if rel == "internal/firewall" || strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			for _, decl := range f.Decls {
				key := stampSiteKey(rel, decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					switch v := n.(type) {
					case *ast.SelectorExpr:
						out[key] = append(out[key], v.Sel.Name)
					case *ast.CallExpr:
						for _, e := range append([]ast.Expr{v.Fun}, v.Args...) {
							if id, ok := ast.Unparen(e).(*ast.Ident); ok {
								out[key] = append(out[key], id.Name)
							}
						}
					case *ast.AssignStmt:
						for _, e := range v.Rhs {
							if id, ok := ast.Unparen(e).(*ast.Ident); ok {
								out[key] = append(out[key], id.Name)
							}
						}
					case *ast.ValueSpec:
						for _, e := range v.Values {
							if id, ok := ast.Unparen(e).(*ast.Ident); ok {
								out[key] = append(out[key], id.Name)
							}
						}
					case *ast.ReturnStmt:
						for _, e := range v.Results {
							if id, ok := ast.Unparen(e).(*ast.Ident); ok {
								out[key] = append(out[key], id.Name)
							}
						}
					}
					return true
				})
			}
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}
