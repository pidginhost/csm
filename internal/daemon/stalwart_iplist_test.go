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
	"unicode"
	"unicode/utf8"

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
		{"other type", &stalwartapi.SpamRule{ID: "r", Type: "Inbound", Enabled: true}},
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

// A key with the old role is refused by HTTP status or, as Stalwart does
// for a missing permission, by a forbidden method error.
func TestStalwartListForbiddenFinding(t *testing.T) {
	for _, tc := range []struct {
		name             string
		keysErr, ruleErr error
	}{
		{"http keys", fmt.Errorf("stalwart /jmap: %w", stalwartapi.ErrForbidden), nil},
		{"method keys", &stalwartapi.MethodError{Method: "x:MemoryLookupKey/query", Type: "forbidden"}, nil},
		{"method rule", nil, &stalwartapi.MethodError{Method: "x:SpamRule/query", Type: "forbidden"}},
		{"joined method", fmt.Errorf("sync: %w", errors.Join(
			&stalwartapi.MethodError{Method: "x:MemoryLookupKey/set", Type: "serverFail"},
			fmt.Errorf("reload: %w", &stalwartapi.MethodError{Method: "x:Action/set", Type: "forbidden"}),
		)), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, f, _ := stalwartListDaemon(t, true)
			f.keysErr, f.ruleErr = tc.keysErr, tc.ruleErr
			findings := d.stalwartListTick(context.Background(), time.Now())
			if len(findings) != 1 || findings[0].Check != stalwartCheckAddressList || !strings.Contains(findings[0].Message, "run csm stalwart setup") {
				t.Fatalf("findings = %+v, want one %s asking to run setup", findings, stalwartCheckAddressList)
			}
			if len(f.keyCreates) != 0 || len(f.keyDeletes) != 0 || f.lookupReloads != 0 {
				t.Fatalf("creates=%v deletes=%v reloads=%d, want no writes", f.keyCreates, f.keyDeletes, f.lookupReloads)
			}
			if st := d.stalwart.list.Load(); st == nil || st.ruleOff || st.m.Weight(netip.MustParseAddr("203.0.113.9")) == 0 {
				t.Fatalf("state = %+v, want the built map with the rule not known off", st)
			}
		})
	}
}

// The built map guards evidence while Stalwart has not answered yet.
func TestStalwartListStoresMapBeforeReads(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.filterHold, f.filterHeld = make(chan struct{}), make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.stalwartListTick(context.Background(), time.Now())
	}()
	<-f.filterHeld
	st := d.stalwart.list.Load()
	close(f.filterHold)
	<-done
	if st == nil || st.ruleOff || st.filterOff || st.m.Weight(netip.MustParseAddr("203.0.113.9")) == 0 {
		t.Fatalf("state during the filter read = %+v, want the built map with nothing known off", st)
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

func TestStalwartListKeepsRuleOffDuringReads(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.rule = nil
	d.stalwartListTick(context.Background(), time.Now())
	if st := d.stalwart.list.Load(); st == nil || !st.ruleOff {
		t.Fatalf("state = %+v, want the rule off after the first tick", st)
	}
	f.filterHold, f.filterHeld = make(chan struct{}), make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.stalwartListTick(context.Background(), time.Now())
	}()
	<-f.filterHeld
	st := d.stalwart.list.Load()
	close(f.filterHold)
	<-done
	if st == nil || !st.ruleOff || st.m.Weight(netip.MustParseAddr("203.0.113.9")) == 0 {
		t.Fatalf("state during the next filter read = %+v, want the new map with the rule still off", st)
	}
}

func TestStalwartListKeyRemovedForgetsRuleOff(t *testing.T) {
	d, cfg, f, _ := stalwartListDaemon(t, true)
	f.rule = nil
	d.stalwartListTick(context.Background(), time.Now())
	if err := os.Remove(cfg.Stalwart.APIKeyFile); err != nil {
		t.Fatal(err)
	}
	d.stalwartListTick(context.Background(), time.Now())
	if st := d.stalwart.list.Load(); st == nil || st.ruleOff {
		t.Fatalf("state = %+v, want the rule not known off without a key", st)
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

func TestStalwartListReloadFailureRecoversNextTick(t *testing.T) {
	d, cfg, f, _ := stalwartListDaemon(t, true)
	failure := errors.New("reload unavailable")
	f.lookupReloadErrors = []error{failure, failure, failure, failure}
	for i := 0; i < 2; i++ {
		findings := d.stalwartListTick(context.Background(), time.Now())
		if len(findings) != 1 || !strings.Contains(findings[0].Details, failure.Error()) || f.lookupReloads != 2*(i+1) {
			t.Fatalf("tick %d: findings=%v reloads=%d", i, findings, f.lookupReloads)
		}
	}
	cfg.Mode = "observe"
	d.stalwartListTick(context.Background(), time.Now())
	if f.lookupReloads != 4 || latestChecks(d)[stalwartCheckAddressList] != 1 {
		t.Fatal("observe mode reloaded or cleared an unfinished reload warning")
	}
	cfg.Mode = "enforce"
	f.keyCreates = nil
	findings := d.stalwartListTick(context.Background(), time.Now())
	if len(findings) != 0 || f.lookupReloads != 5 || len(f.keyCreates) != 0 || latestChecks(d)[stalwartCheckAddressList] != 0 {
		t.Fatalf("recovery: findings=%v reloads=%d creates=%v", findings, f.lookupReloads, f.keyCreates)
	}
	d.stalwartListTick(context.Background(), time.Now())
	if f.lookupReloads != 5 {
		t.Fatal("successful reload was repeated")
	}
}

func TestStalwartListReloadRetry(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.lookupReloadErrors = []error{errors.New("try again"), nil}
	if findings := d.stalwartListTick(context.Background(), time.Now()); len(findings) != 0 || f.lookupReloads != 2 {
		t.Fatalf("findings=%v reloads=%d", findings, f.lookupReloads)
	}
}

func TestStalwartListFilterReadFailureKeepsWarning(t *testing.T) {
	for _, source := range []string{"settings", "stage", "both"} {
		t.Run(source, func(t *testing.T) {
			d, _, f, _ := stalwartListDaemon(t, true)
			f.spamOff = true
			findings := d.stalwartListTick(context.Background(), time.Now())
			original := findings
			d.store.SetBaseline(findings)
			f.spamOff = false
			if source != "stage" {
				f.spamErr = errors.New("settings unavailable")
			}
			if source != "settings" {
				f.stageErr = errors.New("stage unavailable")
			}
			findings = d.stalwartListTick(context.Background(), time.Now())
			if latestChecks(d)[stalwartCheckFilterOff] != 1 || !d.stalwart.list.Load().filterOff || len(d.store.FilterNew(original)) != 0 {
				t.Fatalf("failed read cleared or rearmed warning: %v", findings)
			}
			f.spamErr, f.stageErr = nil, nil
			d.stalwartListTick(context.Background(), time.Now())
			if latestChecks(d)[stalwartCheckFilterOff] != 0 || d.stalwart.list.Load().filterOff {
				t.Fatal("successful reads did not clear warning")
			}
		})
	}
}

func TestStalwartListCallsHaveDeadlines(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.keys = map[string][]stalwartapi.LookupKey{"csm-ip-blocked": {{ID: "old", Key: "198.51.100.5"}}}
	ctx, cancel := context.WithTimeout(context.Background(), stalwartListTickLimit)
	defer cancel()
	d.stalwartListTick(ctx, time.Now())
	if f.unbounded != 0 {
		t.Fatalf("%d calls exceed the backend deadline", f.unbounded)
	}
}

func TestStalwartListFindingBoundsServerText(t *testing.T) {
	err := &stalwartapi.MethodError{Method: "x:SpamRule/query", Type: "forbidden", Description: "bad\x00\x1b\r\n" + strings.Repeat("\u00e9", 10000)}
	f := stalwartListFinding(err, time.Now())
	if len(f.Details) > 1024 || !utf8.ValidString(f.Details) || strings.ContainsFunc(f.Details, unicode.IsControl) || !strings.Contains(f.Message, "run csm stalwart setup") {
		t.Fatalf("unsafe finding: detail bytes=%d, valid UTF-8=%t", len(f.Details), utf8.ValidString(f.Details))
	}
}

func TestStalwartListKeyStatFailureReports(t *testing.T) {
	d, cfg, _, clients := stalwartListDaemon(t, false)
	loop := filepath.Join(t.TempDir(), "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	cfg.Stalwart.APIKeyFile = filepath.Join(loop, "key")
	findings := d.stalwartListTick(context.Background(), time.Now())
	if len(findings) != 1 || findings[0].Check != stalwartCheckAddressList || *clients != 0 {
		t.Fatalf("findings=%v client calls=%d", findings, *clients)
	}
}

func TestStalwartListRuleReadError(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.ruleErr = errors.New("rule unavailable")
	findings := d.stalwartListTick(context.Background(), time.Now())
	if len(findings) != 1 || !strings.Contains(findings[0].Details, "rule unavailable") || latestChecks(d)[stalwartCheckAddressList] != 1 {
		t.Fatalf("findings=%v", findings)
	}
	if !reflect.DeepEqual(f.listCalls, []string{"settings", "stage", "rule"}) {
		t.Fatalf("calls=%v", f.listCalls)
	}
}

func TestStalwartListCanceledTickDoesNotPublish(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.ruleErr = errors.New("old failure")
	old := d.stalwartListTick(context.Background(), time.Now())
	d.store.SetBaseline(old)
	queued := len(d.alertCh)
	f.ruleErr = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.stalwartListTick(ctx, time.Now())
	if latestChecks(d)[stalwartCheckAddressList] != 1 || len(d.store.FilterNew(old)) != 0 || len(d.alertCh) != queued {
		t.Fatal("cancelled tick changed findings, dismissal or alert queue")
	}
}

func TestStalwartListStopsOnFirstSyncError(t *testing.T) {
	for _, operation := range []string{"read", "delete", "create"} {
		t.Run(operation, func(t *testing.T) {
			d, _, f, _ := stalwartListDaemon(t, true)
			ns := ipmap.StalwartNamespaces()[0]
			if operation != "read" {
				ns = "csm-ip-blocked"
			}
			f.keys = map[string][]stalwartapi.LookupKey{ns: {{ID: "old", Key: "198.51.100.5"}}}
			failure := errors.New(operation + " failed")
			want := []string{"settings", "stage", "rule"}
			for _, namespace := range ipmap.StalwartNamespaces() {
				want = append(want, "keys:"+namespace)
				if namespace == ns {
					break
				}
			}
			reloads := 0
			switch operation {
			case "read":
				f.keysErr = failure
			case "delete":
				f.keyDeleteErr = failure
				want = append(want, "delete", "reload")
				reloads = 1
			case "create":
				f.createErr = failure
				want = append(want, "delete", "create:"+ns, "reload")
				reloads = 1
			}
			findings := d.stalwartListTick(context.Background(), time.Now())
			if !reflect.DeepEqual(f.listCalls, want) || f.lookupReloads != reloads || len(findings) != 1 || !strings.Contains(findings[0].Details, failure.Error()) {
				t.Fatalf("calls=%v findings=%v reloads=%d", f.listCalls, findings, f.lookupReloads)
			}
		})
	}
}

func TestStalwartListReloadAfterCancellation(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.onKeyCreate = cancel
	f.createErr = context.Canceled
	f.lookupReloadErrors = []error{errors.New("retry"), errors.New("reload failed")}
	findings := d.stalwartListTick(ctx, time.Now())
	if len(findings) != 1 || !strings.Contains(findings[0].Details, "context canceled") || !strings.Contains(findings[0].Details, "reload failed") || f.lookupReloads != 2 {
		t.Fatalf("findings=%v reloads=%d", findings, f.lookupReloads)
	}
	for i, err := range f.reloadContextErrors {
		if err != nil || f.reloadTimeouts[i] <= 0 || f.reloadTimeouts[i] > 5*time.Second {
			t.Fatalf("reload %d: context error=%v timeout=%v", i, err, f.reloadTimeouts[i])
		}
	}
	if latestChecks(d)[stalwartCheckAddressList] != 0 || len(d.alertCh) != 0 {
		t.Fatal("cancelled sync published a finding")
	}
}

func TestStalwartListDeadlineStillPublishes(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.ruleErr = context.DeadlineExceeded
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	d.stalwartListTick(ctx, time.Now())
	if latestChecks(d)[stalwartCheckAddressList] != 1 || len(d.alertCh) != 1 {
		t.Fatal("timed-out tick did not publish failure")
	}
}

func TestStalwartListKeyReadFailure(t *testing.T) {
	d, _, _, _ := stalwartListDaemon(t, true)
	previous := stalwartClient
	stalwartClient = func(*config.Config) (stalwartAPI, error) { return nil, errors.New("key file unreadable") }
	defer func() { stalwartClient = previous }()
	findings := d.stalwartListTick(context.Background(), time.Now())
	if len(findings) != 1 || findings[0].Check != stalwartCheckAddressList || !strings.Contains(findings[0].Details, "key file unreadable") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestStalwartListMissingKeyClearsFindings(t *testing.T) {
	d, cfg, f, clients := stalwartListDaemon(t, true)
	f.spamOff = true
	f.ruleErr = errors.New("rule unavailable")
	d.stalwartListTick(context.Background(), time.Now())
	calls := *clients
	cfg.Stalwart.APIKeyFile = filepath.Join(t.TempDir(), "missing")
	findings := d.stalwartListTick(context.Background(), time.Now())
	if len(findings) != 0 || *clients != calls || latestChecks(d)[stalwartCheckAddressList] != 0 || latestChecks(d)[stalwartCheckFilterOff] != 0 {
		t.Fatalf("findings=%v clients=%d", findings, *clients)
	}
}

func TestStalwartListUnknownFilterPreservesStoredWarning(t *testing.T) {
	d, _, f, _ := stalwartListDaemon(t, true)
	f.spamOff = true
	old := d.stalwartListTick(context.Background(), time.Now())
	d.store.SetBaseline(old)
	d.stalwart.list.Store(nil)
	f.spamOff = false
	f.spamErr = errors.New("settings unavailable")
	d.stalwartListTick(context.Background(), time.Now())
	if latestChecks(d)[stalwartCheckFilterOff] != 1 || len(d.store.FilterNew(old)) != 0 {
		t.Fatal("unknown initial filter read cleared the stored warning or dismissal")
	}
}
