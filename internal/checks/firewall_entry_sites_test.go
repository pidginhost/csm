package checks

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
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
	"AllowIP", "AllowIPPort", "Apply", "ApplyBlockBatch", "BlockBatchRequest", "BlockIP", "BlockIPForUndo", "BlockIPForce",
	"BlockIPForcePreserveLifetime", "BlockIPOutcome", "BlockIPOutcomeWithFindingID", "BlockIPRequest",
	"BlockSubnet", "BlockSubnetRequest", "BlockSubnetWithFindingID", "CleanExpiredAllows",
	"CleanExpiredSubnets", "FlushBlocked", "MarkBlockActionsUnverified", "PromoteToPermanentBlock", "PromoteToPermanentBlockWithFindingID",
	"RecoverActions", "RefreshDOSExemptSets", "ResolveAction",
	"RemoveAllowIP", "RemoveAllowIPBySource", "RemoveAllowIPPort", "RemoveBlockActionRows",
	"RestoreBlockIfUnchanged", "RetireBlockActions", "TempAllowIP", "UnbanIP", "UnblockIP",
	"UnblockIPForUndo", "UnblockSubnet", "UnblockSubnetIfUnchanged", "UndoAction", "UpdateCloudflareSet",
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
	"internal/admissionowner/execute.go:Owner.execute":                                        "executor",
	"internal/admissionowner/execute.go:Owner.ready":                                          "executor",
	"internal/admissionowner/execute.go:Owner.retireEvicted":                                  "executor",
	"internal/admissionowner/retire.go:Owner.checkRetirements":                                "executor",
	"internal/checks/applyblock.go:ApplyBlock":                                                "funnel",
	"internal/checks/applyblock.go:applyBlockLocked":                                          "funnel",
	"internal/checks/autoblock.go:AutoBlockIPs":                                               "scan,mail_subnet,asn_crawl,netblock",
	"internal/checks/autoblock.go:callBlockIP":                                                "funnel",
	"internal/checks/autoblock.go:callBlockSubnet":                                            "funnel",
	"internal/checks/autoblock.go:promoteToPermanentBlock":                                    "permblock",
	"internal/checks/autoblock.go:pruneExemptAutoSubnets":                                     "cleanup",
	"internal/daemon/central_consume.go:Daemon.performCentralAction":                          "central",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallAllowFile":       "manual",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallApplyConfirmed":  "manual",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallDenyFile":        "manual",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallDenySubnet":      "manual",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallFlush":           "manual",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallRemoveSubnet":    "manual",
	"internal/daemon/control_firewall_batch.go:ControlListener.handleFirewallRestart":         "manual",
	"internal/daemon/control_firewall_batch.go:Daemon.settleRestoredFirewallWindowLocked":     "cleanup",
	"internal/daemon/control_firewall_batch.go:applyFirewallEngine":                           "funnel",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallAllow":          "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallAllowPort":      "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallBlock":          "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallRemoveAllow":    "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallRemovePort":     "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallTempAllow":      "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallTempBan":        "manual",
	"internal/daemon/control_firewall_mutate.go:ControlListener.handleFirewallUnblock":        "manual",
	"internal/daemon/control_firewall_mutate.go:operatorForceBlock":                           "funnel",
	"internal/daemon/daemon.go:Daemon.Run":                                                    "manual",
	"internal/daemon/daemon.go:Daemon.applyIncidentBlock":                                     "incident,incident_spray",
	"internal/daemon/daemon.go:Daemon.escalateExpiredChallenges":                              "challenge_timeout",
	"internal/daemon/daemon.go:Daemon.heartbeat":                                              "cleanup",
	"internal/daemon/daemon.go:Daemon.refreshCloudflareIPs":                                   "cleanup",
	"internal/daemon/firewall_action_recovery.go:ControlListener.handleFirewallActionResolve": "manual",
	"internal/daemon/firewall_action_recovery.go:recoverFirewallActions":                      "funnel",
	"internal/daemon/firewall_startup.go:Daemon.prepareFirewall":                              "cleanup",
	"internal/daemon/firewall_startup.go:Daemon.startFirewall":                                "cleanup",
	"internal/daemon/firewall_startup.go:gateFirewallRows":                                    "cleanup",
	"internal/daemon/mailranges.go:Daemon.doMailRangesRefresh":                                "cleanup",
	"internal/daemon/mailranges.go:mailRangesReapplyFn":                                       "funnel",
	"internal/webui/api.go:Server.apiBlockIP":                                                 "manual",
	"internal/webui/api.go:Server.apiUnblockBulk":                                             "manual",
	"internal/webui/api.go:Server.apiUnblockIP":                                               "manual",
	"internal/webui/block_lifetime.go:Server.blockIPForUndo":                                  "funnel",
	"internal/webui/block_lifetime.go:Server.blockIPPreservingLifetime":                       "funnel",
	"internal/webui/block_lifetime.go:Server.unblockIPForUndo":                                "funnel",
	"internal/webui/block_lifetime.go:Server.undoSnapshotBlocks":                              "funnel",
	"internal/webui/firewall_api.go:Server.apiFirewallAllowIP":                                "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallDenySubnet":                             "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallFlush":                                  "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallRemoveAllow":                            "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallRemoveSubnet":                           "manual",
	"internal/webui/firewall_api.go:Server.apiFirewallUnban":                                  "manual",
	"internal/webui/server.go:blockIPForOperator":                                             "funnel",
	"internal/webui/threat_api.go:Server.apiThreatBlockIP":                                    "manual",
	"internal/webui/threat_api.go:Server.apiThreatBlockIPPermanent":                           "manual",
	"internal/webui/threat_api.go:Server.apiThreatBulkAction":                                 "manual",
	"internal/webui/threat_api.go:Server.apiThreatClearIP":                                    "manual",
	"internal/webui/threat_api.go:Server.apiThreatTempWhitelistIP":                            "manual",
	"internal/webui/threat_api.go:Server.apiThreatUnwhitelistIP":                              "manual",
	"internal/webui/threat_api.go:Server.apiThreatWhitelistIP":                                "manual",
	"internal/webui/threat_api.go:Server.operatorBlockIP":                                     "funnel",
	"internal/webui/threat_api.go:Server.releaseIP":                                           "funnel",
	"internal/webui/undo_api.go:Server.apiUndoRun":                                            "manual",
	"internal/webui/undo_api.go:Server.runUndoEntry":                                          "funnel",
	"internal/webui/undo_api.go:Server.undoBulkBlock":                                         "funnel",
	"internal/webui/undo_api.go:Server.undoBulkReblock":                                       "funnel",
	"internal/webui/undo_api.go:Server.undoBulkWhitelist":                                     "funnel",
}

// The syntax walk deliberately over-approximates method references across
// interfaces and build tags. Record unrelated names separately, so they do
// not acquire a misleading firewall class or hide other mutations at a site.
var nonFirewallReferences = map[string]map[string]string{
	"cmd/csm/stalwart.go:runStalwartSetup":                                                    {"plan.Apply": "Stalwart settings plan"},
	"internal/antispam/worker/handle.go:handle":                                               {"t.Apply": "anti-spam settings transaction"},
	"internal/daemon/control_handlers_incidents.go:ControlListener.handleIncidentsBulkStatus": {"args.Apply": "boolean request field"},
	"internal/daemon/daemon.go:Daemon.dispatchBatch":                                          {"d.autoFreezer.Apply": "mail queue freezer"},
	"internal/mailfwd/adapter/service.go:eximMutation.applyTo":                                {"target.Apply": "Exim configuration adapter"},
	"internal/mailfwd/guard/reconciler.go:Reconciler.Reconcile":                               {"r.Guard.Apply": "mail forwarding policy"},
	"internal/webui/firewall_rollback_api.go:Server.apiFirewallTentativeApply":                {"mgr.Apply": "configuration rollback manager"},
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
	sites := firewallMutationSites(calls, firewallSites, nonFirewallReferences)
	for site, refs := range nonFirewallReferences {
		for name, reason := range refs {
			if reason == "" || !slices.Contains(calls[site], name) {
				t.Errorf("stale or unexplained non-firewall reference: %s %s", site, name)
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

func firewallMutationSites(calls map[string][]string, classes map[string]string, unrelated map[string]map[string]string) map[string][]string {
	watched := map[string]bool{}
	for _, name := range firewallMutations {
		watched[name] = true
	}
	// Shared wrappers are watched at their callers as well as their bodies.
	for site, class := range classes {
		if class == siteFunnel {
			name := site[strings.LastIndex(site, ":")+1:]
			name = name[strings.LastIndex(name, ".")+1:]
			watched[name] = true
		}
	}
	sites := map[string][]string{}
	for site, callees := range calls {
		for _, reference := range callees {
			callee := firewallReferenceName(reference)
			if watched[callee] && unrelated[site][reference] == "" && !slices.Contains(sites[site], callee) {
				sites[site] = append(sites[site], callee)
			}
		}
	}
	return sites
}

func firewallReferenceName(reference string) string {
	return reference[strings.LastIndex(reference, ".")+1:]
}

// firewallCallers maps each production function outside internal/firewall
// to the names it calls or hands on as values: every selected name, and
// plain function references, including values stored in containers or sent
// through channels. Selectors retain their receiver to distinguish name
// collisions. Package-level initializers keep their variable name so callers
// of a stored function can be classified too.
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
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			visit := func(key string, node ast.Node) {
				bare := func(exprs ...ast.Expr) {
					for _, e := range exprs {
						if id, ok := ast.Unparen(e).(*ast.Ident); ok {
							out[key] = append(out[key], id.Name)
						}
					}
				}
				ast.Inspect(node, func(n ast.Node) bool {
					switch v := n.(type) {
					case *ast.SelectorExpr:
						var reference bytes.Buffer
						if err := format.Node(&reference, fset, v); err != nil {
							t.Fatal(err)
						}
						out[key] = append(out[key], reference.String())
					case *ast.CallExpr:
						bare(v.Fun)
						bare(v.Args...)
					case *ast.AssignStmt:
						bare(v.Rhs...)
					case *ast.ValueSpec:
						bare(v.Values...)
					case *ast.CompositeLit:
						bare(v.Elts...)
					case *ast.KeyValueExpr:
						bare(v.Value)
					case *ast.SendStmt:
						bare(v.Value)
					case *ast.ReturnStmt:
						bare(v.Results...)
					case *ast.UnaryExpr:
						bare(v.X)
					case *ast.StarExpr:
						bare(v.X)
					case *ast.TypeAssertExpr:
						bare(v.X)
					case *ast.IndexExpr:
						bare(v.X)
					case *ast.IndexListExpr:
						bare(v.X)
					case *ast.RangeStmt:
						bare(v.X)
					}
					return true
				})
			}
			for _, decl := range f.Decls {
				if gen, ok := decl.(*ast.GenDecl); ok {
					for _, spec := range gen.Specs {
						values, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						if len(values.Names) == len(values.Values) {
							for i, value := range values.Values {
								// The value wrapper also visits a bare function alias.
								visit(rel+":"+values.Names[i].Name, &ast.ValueSpec{Values: []ast.Expr{value}})
							}
						} else {
							// A tuple initializer can hand the callback to either
							// result. Keep both names in the conservative inventory.
							for _, name := range values.Names {
								visit(rel+":"+name.Name, values)
							}
						}
					}
				} else {
					visit(stampSiteKey(rel, decl), decl)
				}
			}
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}
