package checks

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// TestLogicalOwnerMapsConsistent guards the exact-name contract between the
// ownership maps: a typo in one map silently turns "incomplete" into
// "completed" and purges state findings the owner never re-emitted.
func TestLogicalOwnerMapsConsistent(t *testing.T) {
	for physical, owners := range physicalCheckLogicalOwners {
		if _, ok := runnerFindingNames[physical]; !ok {
			t.Errorf("physicalCheckLogicalOwners key %q is not a runnable check", physical)
		}
		for _, owner := range owners {
			if _, ok := logicalOwnerFindingNames[owner]; !ok {
				t.Errorf("logical owner %q has no finding names", owner)
			}
			if _, ok := logicalOwnerDisableAliases[owner]; !ok {
				t.Errorf("logical owner %q has no disable aliases", owner)
			}
			if _, ok := runnerFindingNames[owner]; ok {
				t.Errorf("logical owner %q must not be a runnerFindingNames key", owner)
			}
			for _, name := range perRunFindingNames[owner] {
				if !slices.Contains(logicalOwnerFindingNames[owner], name) {
					t.Errorf("per-run name %q of owner %q is not among its finding names", name, owner)
				}
			}
		}
	}
	for owner, aliases := range logicalOwnerDisableAliases {
		if !slices.Contains(aliases, owner) {
			t.Errorf("owner %q disable aliases %v must include the owner ID", owner, aliases)
		}
		for _, alias := range aliases {
			if alias == "js_taint_scan_incomplete" {
				t.Errorf("coverage diagnostic must not be a disable alias for %q", owner)
			}
		}
	}
}

func jsOwnerPurgeNames() []string {
	return []string{"js_keylogger_dataflow", "js_taint_scan_incomplete"}
}

func TestRunnerJSOwnerCompletesIndependentlyOfYARA(t *testing.T) {
	check := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		markCheckIncomplete(ctx, "yara_deep")
		return []alert.Finding{{Check: "yara_scan_incomplete", Severity: alert.High}}
	}}

	_, purge := runParallelWithContext(context.Background(), &config.Config{}, nil, []namedCheck{check}, "deep", true)

	for _, name := range jsOwnerPurgeNames() {
		if !slices.Contains(purge, name) {
			t.Errorf("completed JS owner name %q missing from purge list: %v", name, purge)
		}
	}
	if slices.Contains(purge, "yara_match_scheduled") {
		t.Errorf("incomplete YARA owner purged its state findings: %v", purge)
	}
	if !slices.Contains(purge, "yara_scan_incomplete") {
		t.Errorf("per-run YARA status finding missing from purge list: %v", purge)
	}
}

func TestRunnerJSOwnerIncompleteDoesNotPurgeJSFindings(t *testing.T) {
	check := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		markCheckIncomplete(ctx, "js_taint_deep")
		return []alert.Finding{{Check: "js_taint_scan_incomplete", Severity: alert.Warning}}
	}}

	_, purge := runParallelWithContext(context.Background(), &config.Config{}, nil, []namedCheck{check}, "deep", true)

	if slices.Contains(purge, "js_keylogger_dataflow") {
		t.Errorf("incomplete JS owner purged its state findings: %v", purge)
	}
	if !slices.Contains(purge, "js_taint_scan_incomplete") {
		t.Errorf("per-run JS status finding missing from purge list: %v", purge)
	}
	if !slices.Contains(purge, "yara_match_scheduled") {
		t.Errorf("completed YARA owner names missing from purge list: %v", purge)
	}
}

func TestRunnerLogicalOwnerTimeoutPurgesNothing(t *testing.T) {
	prevTimeout := timeoutForFunc
	t.Cleanup(func() { timeoutForFunc = prevTimeout })
	timeoutForFunc = func(string) time.Duration { return 50 * time.Millisecond }

	check := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		<-ctx.Done()
		return nil
	}}

	findings, purge := runParallelWithContext(context.Background(), &config.Config{}, nil, []namedCheck{check}, "deep", true)

	for _, name := range append(jsOwnerPurgeNames(), "yara_match_scheduled", "yara_scan_incomplete") {
		if slices.Contains(purge, name) {
			t.Errorf("timed-out physical check purged %q: %v", name, purge)
		}
	}
	if !containsFindingCheck(findings, "check_timeout") {
		t.Fatalf("timed-out check did not emit check_timeout: %+v", findings)
	}
}

func TestRunnerLogicalOwnerPanicPurgesNothing(t *testing.T) {
	check := namedCheck{name: "yara_deep", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		panic("forced check panic")
	}}

	findings, purge := runParallelWithContext(context.Background(), &config.Config{}, nil, []namedCheck{check}, "deep", true)

	for _, name := range append(jsOwnerPurgeNames(), "yara_match_scheduled", "yara_scan_incomplete") {
		if slices.Contains(purge, name) {
			t.Errorf("panicked physical check purged %q: %v", name, purge)
		}
	}
	if !containsFindingCheck(findings, "check_panic") {
		t.Fatalf("panicked check did not emit check_panic: %+v", findings)
	}
}

func TestRunnerJSOnlyDisablementPurgesAndSkipsJSOwner(t *testing.T) {
	for _, alias := range []string{"js_taint_deep", "js_keylogger_dataflow"} {
		t.Run(alias, func(t *testing.T) {
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			st.SetLatestFindings([]alert.Finding{
				{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "stale JS finding"},
				{Check: "yara_match_scheduled", Severity: alert.Critical, Message: "stale YARA finding"},
			})

			ran := false
			check := namedCheck{name: "yara_deep", fn: func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
				ran = true
				return []alert.Finding{{Check: "yara_match_scheduled", Severity: alert.Critical, Message: "fresh YARA finding"}}
			}}

			cfg := &config.Config{DisabledChecks: []string{alias}}
			findings, purge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "deep", true)

			if !ran {
				t.Fatal("JS-only disablement must keep the physical wrapper runnable for YARA")
			}
			for _, name := range jsOwnerPurgeNames() {
				if !slices.Contains(purge, name) {
					t.Errorf("disabled JS owner name %q missing from purge list: %v", name, purge)
				}
			}

			StoreLatestScanFindings(st, purge, findings)
			got := st.LatestFindings()
			if containsFindingCheck(got, "js_keylogger_dataflow") {
				t.Fatalf("disabled JS owner's stale finding survived: %+v", got)
			}
			if !containsFindingCheck(got, "yara_match_scheduled") {
				t.Fatalf("YARA finding lost during JS-only disablement: %+v", got)
			}
		})
	}
}

func TestRunnerYARAAliasDisablementKeepsJSRunning(t *testing.T) {
	for _, alias := range []string{"yara_deep", "yara_match_scheduled", "yara_scan_incomplete"} {
		t.Run(alias, func(t *testing.T) {
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			st.SetLatestFindings([]alert.Finding{
				{Check: "yara_match_scheduled", Severity: alert.Critical, Message: "stale YARA finding"},
			})

			ran := false
			check := namedCheck{name: "yara_deep", fn: func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
				ran = true
				return []alert.Finding{{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "fresh JS finding", FilePath: "/tmp/x.js"}}
			}}

			cfg := &config.Config{DisabledChecks: []string{alias}}
			findings, purge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "deep", true)

			if !ran {
				t.Fatal("YARA-only disablement must keep the physical wrapper runnable for JS")
			}
			if !slices.Contains(purge, "yara_match_scheduled") {
				t.Errorf("disabled YARA consumer names missing from purge list: %v", purge)
			}

			StoreLatestScanFindings(st, purge, findings)
			got := st.LatestFindings()
			if containsFindingCheck(got, "yara_match_scheduled") {
				t.Fatalf("disabled YARA consumer's stale finding survived: %+v", got)
			}
			if !containsFindingCheck(got, "js_keylogger_dataflow") {
				t.Fatalf("fresh JS finding lost during YARA-only disablement: %+v", got)
			}
		})
	}
}

func TestRunnerBothConsumersDisabledSkipsWrapper(t *testing.T) {
	ran := false
	check := namedCheck{name: "yara_deep", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		ran = true
		return nil
	}}

	cfg := &config.Config{DisabledChecks: []string{"yara_deep", "js_taint_deep"}}
	_, purge := runParallelWithContext(context.Background(), cfg, nil, []namedCheck{check}, "deep", true)

	if ran {
		t.Fatal("wrapper must be skipped when both consumers are disabled")
	}
	for _, name := range append(jsOwnerPurgeNames(), "yara_match_scheduled", "yara_scan_incomplete") {
		if !slices.Contains(purge, name) {
			t.Errorf("both-disabled purge list missing %q: %v", name, purge)
		}
	}
}

func TestDisabledCheckVocabularyJSTaint(t *testing.T) {
	configNames := DisabledCheckConfigNames()
	for _, want := range []string{"js_taint_deep", "js_keylogger_dataflow"} {
		if !slices.Contains(configNames, want) {
			t.Errorf("DisabledCheckConfigNames missing %q", want)
		}
	}
	if slices.Contains(configNames, "js_taint_scan_incomplete") {
		t.Error("js_taint_scan_incomplete must be rejected as a disable value")
	}

	uiNames := DisabledCheckNames()
	if !slices.Contains(uiNames, "js_keylogger_dataflow") {
		t.Error("DisabledCheckNames missing public alias js_keylogger_dataflow")
	}
	if slices.Contains(uiNames, "js_taint_deep") {
		t.Error("owner ID js_taint_deep must stay out of the UI vocabulary")
	}
	if slices.Contains(uiNames, "js_taint_scan_incomplete") {
		t.Error("js_taint_scan_incomplete must stay out of the UI vocabulary")
	}
}

func TestLatestPurgeNamesForDeepTiersIncludeJSOwner(t *testing.T) {
	for name, names := range map[string][]string{
		"deep":         LatestPurgeCheckNamesForTier(TierDeep),
		"reduced-deep": LatestPurgeCheckNamesForReducedDeep(),
	} {
		for _, want := range jsOwnerPurgeNames() {
			if !slices.Contains(names, want) {
				t.Errorf("%s purge names missing %q", name, want)
			}
		}
	}
}
