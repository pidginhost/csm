package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/ipmap"
	"github.com/pidginhost/csm/internal/stalwartapi"
)

// stalwartListDaemon gives a Stalwart host whose CSM blocks 203.0.113.9,
// whose rule is on and whose namespaces are empty.
func stalwartListDaemon(t *testing.T, withKey bool) (*Daemon, *config.Config, *fakeStalwart, *int) {
	t.Helper()
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	checks.GetThreatDB().AddPermanent("203.0.113.9", "test")
	prevADB := attackdb.Global()
	attackdb.SetGlobal(attackdb.NewForTest(nil))
	t.Cleanup(func() { attackdb.SetGlobal(prevADB) })
	d := newTestDaemon(t)
	d.stalwart = &stalwartState{}
	cfg := &config.Config{StatePath: d.cfg.StatePath}
	cfg.Stalwart.APIKeyFile = filepath.Join(t.TempDir(), "stalwart-api.key")
	if withKey {
		if err := os.WriteFile(cfg.Stalwart.APIKeyFile, []byte("test-key-1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	useActiveConfig(t, cfg)
	f := &fakeStalwart{rule: &stalwartapi.SpamRule{ID: "r", Type: "Any", Enabled: true}}
	clients := stalwartHost(t, func() *config.Config { return cfg }, f)
	return d, cfg, f, clients
}

func listChecks(findings []alert.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[f.Check]++
	}
	return out
}

func TestStalwartListWritesKeysAndReloads(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	findings := d.stalwartListTick(context.Background(), time.Now())
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
	want := map[string][]string{"csm-ip-blocked": {"203.0.113.9"}, "csm-ip-canary": {ipmap.CanaryAddr}}
	if !reflect.DeepEqual(f.keyCreates, want) || len(f.keyDeletes) != 0 || f.lookupReloads != 1 {
		t.Fatalf("creates=%v deletes=%v reloads=%d, want %v, none and 1", f.keyCreates, f.keyDeletes, f.lookupReloads, want)
	}
	st := d.stalwart.list.Load()
	if st == nil || st.ruleOff || st.filterOff || st.m == nil {
		t.Fatalf("state = %+v, want the map with rule and filter on", st)
	}
}

func TestStalwartListNoChangeNoReload(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	d.stalwartListTick(context.Background(), time.Now())
	f.keyCreates, f.keyDeletes, f.lookupReloads = nil, nil, 0
	if findings := d.stalwartListTick(context.Background(), time.Now()); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
	if len(f.keyCreates) != 0 || len(f.keyDeletes) != 0 || f.lookupReloads != 0 {
		t.Fatalf("creates=%v deletes=%v reloads=%d, want no writes", f.keyCreates, f.keyDeletes, f.lookupReloads)
	}
}

// Keys an operator adds, duplicates or flips are deleted from CSM's namespaces.
func TestStalwartListOwnsNamespaces(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.keys = map[string][]stalwartapi.LookupKey{
		"csm-ip-blocked": {
			{ID: "a", Key: "203.0.113.9"},
			{ID: "b", Key: "203.0.113.9"},
			{ID: "c", Key: "198.51.100.5"},
			{ID: "d", Key: "203.0.113.9", Glob: true},
		},
		"csm-ip-canary": {{ID: "e", Key: ipmap.CanaryAddr}},
	}
	d.stalwartListTick(context.Background(), time.Now())
	if !reflect.DeepEqual(f.keyDeletes, []string{"b", "c", "d"}) || len(f.keyCreates) != 0 || f.lookupReloads != 1 {
		t.Fatalf("deletes=%v creates=%v reloads=%d, want b c d deleted, nothing created, one reload", f.keyDeletes, f.keyCreates, f.lookupReloads)
	}
	if got := f.keys["csm-ip-blocked"]; len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("csm-ip-blocked = %+v, want only a", got)
	}
}

// The only copy of a wanted key whose glob flag disagrees with its text is
// replaced, not kept.
func TestStalwartListReplacesFlippedGlob(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.keys = map[string][]stalwartapi.LookupKey{
		"csm-ip-blocked": {{ID: "a", Key: "203.0.113.9", Glob: true}},
		"csm-ip-canary":  {{ID: "e", Key: ipmap.CanaryAddr}},
	}
	d.stalwartListTick(context.Background(), time.Now())
	want := map[string][]string{"csm-ip-blocked": {"203.0.113.9"}}
	if !reflect.DeepEqual(f.keyDeletes, []string{"a"}) || !reflect.DeepEqual(f.keyCreates, want) || f.lookupReloads != 1 {
		t.Fatalf("deletes=%v creates=%v reloads=%d, want a replaced and one reload", f.keyDeletes, f.keyCreates, f.lookupReloads)
	}
}

func TestStalwartListClearsWhenRuleOff(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule *stalwartapi.SpamRule
	}{
		{"disabled", &stalwartapi.SpamRule{ID: "r", Type: "Any"}},
		{"missing", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, f, _ := stalwartListDaemon(t, true)
			f.rule = tc.rule
			f.keys = map[string][]stalwartapi.LookupKey{}
			var all []string
			for i, ns := range ipmap.StalwartNamespaces() {
				id := fmt.Sprintf("k%d", i)
				f.keys[ns] = []stalwartapi.LookupKey{{ID: id, Key: "203.0.113.9"}}
				all = append(all, id)
			}
			if findings := d.stalwartListTick(context.Background(), time.Now()); len(findings) != 0 {
				t.Fatalf("findings = %+v, want none", findings)
			}
			if !reflect.DeepEqual(f.keyDeletes, all) || len(f.keyCreates) != 0 || f.lookupReloads != 1 {
				t.Fatalf("deletes=%v creates=%v reloads=%d, want all 14 deleted and one reload", f.keyDeletes, f.keyCreates, f.lookupReloads)
			}
			if st := d.stalwart.list.Load(); st == nil || !st.ruleOff {
				t.Fatalf("state = %+v, want ruleOff", st)
			}
		})
	}
}

// Stalwart failing mid-sync still gets a reload, so the loaded list
// matches the stored keys and the next tick heals.
func TestStalwartListReloadsAfterPartialWrite(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.keys = map[string][]stalwartapi.LookupKey{"csm-ip-blocked": {{ID: "x", Key: "198.51.100.5"}}}
	f.createErr = errors.New("stalwart x:MemoryLookupKey/set: create failed")
	findings := d.stalwartListTick(context.Background(), time.Now())
	if !reflect.DeepEqual(f.keyDeletes, []string{"x"}) || f.lookupReloads != 1 {
		t.Fatalf("deletes=%v reloads=%d, want x deleted and one reload", f.keyDeletes, f.lookupReloads)
	}
	if len(findings) != 1 || findings[0].Check != stalwartCheckAddressList || findings[0].Severity != alert.Warning ||
		!strings.Contains(findings[0].Message+findings[0].Details, "create failed") {
		t.Fatalf("findings = %+v, want one %s warning with the create error", findings, stalwartCheckAddressList)
	}
	if got := latestChecks(d)[stalwartCheckAddressList]; got != 1 {
		t.Fatalf("stored %d %s findings, want 1", got, stalwartCheckAddressList)
	}
	f.createErr = nil
	d.stalwartListTick(context.Background(), time.Now())
	if got := latestChecks(d)[stalwartCheckAddressList]; got != 0 {
		t.Fatalf("a healed sync left %d %s findings", got, stalwartCheckAddressList)
	}
}

func TestStalwartListForbiddenFinding(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.keysErr = fmt.Errorf("stalwart /jmap: %w", stalwartapi.ErrForbidden)
	findings := d.stalwartListTick(context.Background(), time.Now())
	if len(findings) != 1 || findings[0].Check != stalwartCheckAddressList || !strings.Contains(findings[0].Message, "run csm stalwart setup") {
		t.Fatalf("findings = %+v, want one %s asking to run setup", findings, stalwartCheckAddressList)
	}
	if len(f.keyCreates) != 0 || len(f.keyDeletes) != 0 || f.lookupReloads != 0 {
		t.Fatalf("creates=%v deletes=%v reloads=%d, want no writes", f.keyCreates, f.keyDeletes, f.lookupReloads)
	}
}

func TestStalwartListObserveModeWritesNothing(t *testing.T) {
	d, cfg, f, _ := stalwartListDaemon(t, true)
	cfg.Mode = "observe"
	f.rule = nil
	f.keys = map[string][]stalwartapi.LookupKey{"csm-ip-blocked": {{ID: "x", Key: "198.51.100.5"}}}
	d.stalwartListTick(context.Background(), time.Now())
	if len(f.keyCreates) != 0 || len(f.keyDeletes) != 0 || f.lookupReloads != 0 {
		t.Fatalf("creates=%v deletes=%v reloads=%d, want no writes in observe mode", f.keyCreates, f.keyDeletes, f.lookupReloads)
	}
	if st := d.stalwart.list.Load(); st == nil || !st.ruleOff || st.m == nil {
		t.Fatalf("state = %+v, want it stored with the rule off", st)
	}
}

func TestStalwartListNoKeyFile(t *testing.T) {
	d, _, _, clients := stalwartListDaemon(t, false)
	if findings := d.stalwartListTick(context.Background(), time.Now()); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none without a key", findings)
	}
	if *clients != 0 {
		t.Fatalf("%d clients made without a key file", *clients)
	}
	st := d.stalwart.list.Load()
	if st == nil || st.ruleOff || st.m == nil || st.m.Weight(netip.MustParseAddr("203.0.113.9")) == 0 {
		t.Fatalf("state = %+v, want the built map with the rule not known off", st)
	}
}

func TestStalwartFilterOffFinding(t *testing.T) {
	for _, tc := range []struct {
		name           string
		spamOff, stOff bool
	}{
		{"settings", true, false},
		{"stage", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, f, _ := stalwartListDaemon(t, true)
			f.spamOff, f.stageOff = tc.spamOff, tc.stOff
			findings := d.stalwartListTick(context.Background(), time.Now())
			if c := listChecks(findings); len(findings) != 1 || c[stalwartCheckFilterOff] != 1 || findings[0].Severity != alert.Warning {
				t.Fatalf("findings = %+v, want one %s warning", findings, stalwartCheckFilterOff)
			}
			if st := d.stalwart.list.Load(); st == nil || !st.filterOff {
				t.Fatalf("state = %+v, want filterOff", st)
			}
			f.spamOff, f.stageOff = false, false
			d.stalwartListTick(context.Background(), time.Now())
			if got := latestChecks(d)[stalwartCheckFilterOff]; got != 0 {
				t.Fatalf("filter back on left %d %s findings", got, stalwartCheckFilterOff)
			}
			if st := d.stalwart.list.Load(); st.filterOff {
				t.Fatal("filter back on still reads as off")
			}
		})
	}
}
