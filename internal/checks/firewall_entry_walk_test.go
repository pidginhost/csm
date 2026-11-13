package checks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFirewallMutationCoverage(t *testing.T) {
	// These APIs also install or settle firewall state, even when no
	// production caller currently uses the batch entry point.
	for _, name := range []string{
		"Apply", "BlockBatchRequest", "MarkBlockActionsUnverified", "RecoverActions", "ResolveAction",
		"RefreshDOSExemptSets", "UpdateCloudflareSet",
	} {
		if !slices.Contains(firewallMutations, name) {
			t.Errorf("firewall mutation %s is not watched", name)
		}
	}
}

func TestFirewallCallersReferenceForms(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"direct", `engine.BlockIP()`, "BlockIP"},
		{"method value", `saved := engine.BlockIP; saved()`, "BlockIP"},
		{"method expression", `saved := (*firewall.Engine).BlockIP; saved(engine)`, "BlockIP"},
		{"struct method", `saved := holder{run: engine.BlockIP}; saved.run()`, "BlockIP"},
		{"stored closure", `saved := func() { engine.BlockIP() }; saved()`, "BlockIP"},
		{"interface wrapper", `wrapped := interface{ BlockIP() }(engine); wrapped.BlockIP()`, "BlockIP"},
		{"funnel call", `ApplyBlock()`, "ApplyBlock"},
		{"funnel argument", `register((ApplyBlock))`, "ApplyBlock"},
		{"funnel assignment", `saved := ApplyBlock; saved()`, "ApplyBlock"},
		{"funnel declaration", `var saved = ApplyBlock; saved()`, "ApplyBlock"},
		{"funnel return", `return ApplyBlock`, "ApplyBlock"},
		{"funnel struct", `saved := holder{run: ApplyBlock}; saved.run()`, "ApplyBlock"},
		{"funnel slice", `saved := []func(){ApplyBlock}; saved[0]()`, "ApplyBlock"},
		{"funnel map", `saved := map[string]func(){"run": ApplyBlock}; saved["run"]()`, "ApplyBlock"},
		{"funnel channel", `queue <- ApplyBlock`, "ApplyBlock"},
		{"generic funnel", `saved := ApplyBlock[Target]; saved()`, "ApplyBlock"},
		{"generic funnel arguments", `saved := ApplyBlock[Target, Result]; saved()`, "ApplyBlock"},
		{"iterator funnel", `for range ApplyBlock {}`, "ApplyBlock"},
		{"callback address", `saved := &deferredBlock; (*saved)()`, "deferredBlock"},
		{"callback pointer", `(*callbackPtr)()`, "callbackPtr"},
		{"callback assertion", `anyCallback.(func())()`, "anyCallback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"internal/sample", "cmd"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			path := "internal/sample/site.go"
			if err := os.WriteFile(filepath.Join(root, path), []byte("package sample\nfunc site() { "+tc.body+" }\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			calls := firewallCallers(t, root)
			if !slices.ContainsFunc(calls[path+":site"], func(ref string) bool { return firewallReferenceName(ref) == tc.want }) {
				t.Fatalf("site references %v; missing %s", calls[path+":site"], tc.want)
			}
		})
	}
}

func TestFirewallSharedHelpersExposeNewCallers(t *testing.T) {
	// These helpers do not establish an operator request themselves. A
	// future automatic caller must be classified at its own entry point.
	for _, site := range []string{
		"internal/daemon/control_firewall_mutate.go:operatorForceBlock",
		"internal/webui/server.go:blockIPForOperator",
		"internal/webui/block_lifetime.go:Server.blockIPPreservingLifetime",
		"internal/webui/block_lifetime.go:Server.blockIPForUndo",
		"internal/webui/block_lifetime.go:Server.unblockIPForUndo",
		"internal/webui/block_lifetime.go:Server.undoSnapshotBlocks",
		"internal/webui/threat_api.go:Server.releaseIP",
		"internal/webui/undo_api.go:Server.undoBulkBlock",
		"internal/webui/undo_api.go:Server.undoBulkWhitelist",
	} {
		const caller = "internal/sample/site.go:automatic"
		name := firewallReferenceName(site[strings.LastIndex(site, ":")+1:])
		got := firewallMutationSites(map[string][]string{caller: {name}}, firewallSites, nil)
		if !slices.Equal(got[caller], []string{name}) {
			t.Errorf("new caller of %s escaped classification: %v", site, got)
		}
	}
}

func TestFirewallCallersNameStoredFunctions(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"internal/sample", "cmd"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const path = "internal/sample/site.go"
	const source = `package sample
var deferredBlock = func() { engine.BlockIP() }
var apply = (*firewall.Engine).Apply
var first, second = split(engine.BlockIP)
`
	if err := os.WriteFile(filepath.Join(root, path), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := firewallCallers(t, root)
	for site, want := range map[string]string{"deferredBlock": "BlockIP", "apply": "Apply", "first": "BlockIP", "second": "BlockIP"} {
		if !slices.ContainsFunc(calls[path+":"+site], func(ref string) bool { return firewallReferenceName(ref) == want }) {
			t.Errorf("%s references %v; missing %s", site, calls[path+":"+site], want)
		}
	}
}

func TestFirewallNameCollisionsDoNotHideMutations(t *testing.T) {
	const site = "internal/sample/site.go:site"
	unrelated := map[string]map[string]string{site: {"settings.Apply": "settings transaction"}}
	for _, tc := range []struct {
		refs, want []string
	}{
		{[]string{"settings.Apply"}, nil},
		{[]string{"settings.Apply", "engine.Apply"}, []string{"Apply"}},
		{[]string{"settings.Apply", "engine.BlockIP"}, []string{"BlockIP"}},
	} {
		got := firewallMutationSites(map[string][]string{site: tc.refs}, nil, unrelated)
		if !slices.Equal(got[site], tc.want) {
			t.Errorf("references %v produce %v; want %v", tc.refs, got[site], tc.want)
		}
	}
}

func TestFirewallFunnelsReachInterfaceCallers(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"internal/sample", "cmd"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const path = "internal/sample/site.go"
	const source = `package sample
type Wrapper struct { engine *Engine }
func (w *Wrapper) Deny() { w.engine.BlockIP() }
func automatic(w interface { Deny() }) { saved := holder{run: w.Deny}; saved.run() }
var deferredBlock = func() { engine.BlockIP() }
func later() { deferredBlock() }
`
	if err := os.WriteFile(filepath.Join(root, path), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	classes := map[string]string{path + ":Wrapper.Deny": siteFunnel, path + ":deferredBlock": siteFunnel}
	sites := firewallMutationSites(firewallCallers(t, root), classes, nil)
	want := map[string][]string{
		path + ":Wrapper.Deny":  {"BlockIP"},
		path + ":automatic":     {"Deny"},
		path + ":deferredBlock": {"BlockIP"},
		path + ":later":         {"deferredBlock"},
	}
	if len(sites) != len(want) {
		t.Fatalf("sites = %v; want %v", sites, want)
	}
	for site, refs := range want {
		if !slices.Equal(sites[site], refs) {
			t.Errorf("%s = %v; want %v", site, sites[site], refs)
		}
	}
}
