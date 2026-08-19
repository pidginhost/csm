package checks

import (
	"context"
	"fmt"
	"slices"
	"strings"
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
	if problems := logicalOwnerConsistencyProblems(
		physicalCheckLogicalOwners,
		logicalOwnerFindingNames,
		logicalOwnerDisableAliases,
		perRunFindingNames,
	); len(problems) > 0 {
		t.Fatalf("logical owner maps are inconsistent:\n%s", strings.Join(problems, "\n"))
	}
}

func logicalOwnerConsistencyProblems(
	physicalOwners map[string][]string,
	findingNames map[string][]string,
	disableAliases map[string][]string,
	perRunNames map[string][]string,
) []string {
	var problems []string
	hosted := make(map[string]string)
	for physical, owners := range physicalOwners {
		if _, ok := runnerFindingNames[physical]; !ok {
			problems = append(problems, fmt.Sprintf("physical owner key %q is not a runnable check", physical))
		}
		for _, owner := range owners {
			if previous, exists := hosted[owner]; exists {
				problems = append(problems, fmt.Sprintf("logical owner %q is hosted by both %q and %q", owner, previous, physical))
			} else {
				hosted[owner] = physical
			}
			if _, ok := runnerFindingNames[owner]; ok {
				problems = append(problems, fmt.Sprintf("logical owner %q must not be a runnable check", owner))
			}
		}
	}

	for label, values := range map[string]map[string][]string{
		"finding names":   findingNames,
		"disable aliases": disableAliases,
	} {
		for owner := range hosted {
			if _, ok := values[owner]; !ok {
				problems = append(problems, fmt.Sprintf("logical owner %q has no %s", owner, label))
			}
		}
		for owner := range values {
			if _, ok := hosted[owner]; !ok {
				problems = append(problems, fmt.Sprintf("%s key %q is not a hosted logical owner", label, owner))
			}
		}
	}

	for owner := range hosted {
		ownedNames := findingNames[owner]
		if len(ownedNames) == 0 {
			problems = append(problems, fmt.Sprintf("logical owner %q has no owned finding names", owner))
		}
		for _, name := range ownedNames {
			if _, ok := LookupCheck(name); !ok {
				problems = append(problems, fmt.Sprintf("logical owner %q has unknown finding name %q", owner, name))
			}
		}
		aliases := disableAliases[owner]
		if !slices.Contains(aliases, owner) {
			problems = append(problems, fmt.Sprintf("logical owner %q disable aliases %v omit its owner ID", owner, aliases))
		}
		for _, alias := range aliases {
			if alias != owner && alias != hosted[owner] && !slices.Contains(ownedNames, alias) {
				problems = append(problems, fmt.Sprintf("logical owner %q has unowned disable alias %q", owner, alias))
			}
		}
		statusNames, ok := perRunNames[owner]
		if !ok {
			problems = append(problems, fmt.Sprintf("logical owner %q has no per-run finding names", owner))
		}
		for _, name := range statusNames {
			if !slices.Contains(ownedNames, name) {
				problems = append(problems, fmt.Sprintf("per-run name %q of owner %q is not an owned finding", name, owner))
			}
			if slices.Contains(aliases, name) {
				problems = append(problems, fmt.Sprintf("per-run status %q must not disable owner %q", name, owner))
			}
		}
	}
	for owner := range perRunNames {
		if _, physical := runnerFindingNames[owner]; physical {
			continue
		}
		if _, logical := hosted[owner]; !logical {
			problems = append(problems, fmt.Sprintf("per-run key %q is neither a runnable check nor a hosted logical owner", owner))
		}
	}
	return problems
}

func cloneNameMap(src map[string][]string) map[string][]string {
	out := make(map[string][]string, len(src))
	for name, values := range src {
		out[name] = slices.Clone(values)
	}
	return out
}

func TestLogicalOwnerMapsRejectOwnerNameTypos(t *testing.T) {
	const misspelled = "js_taint_dee"
	tests := map[string]func(map[string][]string, map[string][]string, map[string][]string, map[string][]string){
		"physical owner": func(physical, _, _, _ map[string][]string) {
			physical["yara_deep"] = []string{misspelled}
		},
		"finding names": func(_, findings, _, _ map[string][]string) {
			findings[misspelled] = findings[logicalOwnerJSTaintDeep]
			delete(findings, logicalOwnerJSTaintDeep)
		},
		"disable aliases": func(_, _, aliases, _ map[string][]string) {
			aliases[misspelled] = aliases[logicalOwnerJSTaintDeep]
			delete(aliases, logicalOwnerJSTaintDeep)
		},
		"per-run names": func(_, _, _, perRun map[string][]string) {
			perRun[misspelled] = perRun[logicalOwnerJSTaintDeep]
			delete(perRun, logicalOwnerJSTaintDeep)
		},
	}

	for name, breakMap := range tests {
		t.Run(name, func(t *testing.T) {
			physical := cloneNameMap(physicalCheckLogicalOwners)
			findings := cloneNameMap(logicalOwnerFindingNames)
			aliases := cloneNameMap(logicalOwnerDisableAliases)
			perRun := cloneNameMap(perRunFindingNames)
			breakMap(physical, findings, aliases, perRun)

			if problems := logicalOwnerConsistencyProblems(physical, findings, aliases, perRun); len(problems) == 0 {
				t.Fatalf("a typo in %s passed the consistency check", name)
			}
		})
	}
}

func TestSplitDisabledChecksRescuesOnlyYARADeepWrapper(t *testing.T) {
	for _, check := range checksForTier(TierAll) {
		if check.name == "yara_deep" {
			continue
		}
		t.Run(check.name, func(t *testing.T) {
			enabled, disabled := splitDisabledChecks(
				&config.Config{DisabledChecks: []string{check.name}},
				[]namedCheck{check},
			)
			if len(enabled) != 0 || len(disabled) != 1 || disabled[0].name != check.name {
				t.Fatalf("disabled check %q was rescued: enabled=%v disabled=%v", check.name, enabled, disabled)
			}
		})
	}
}

func TestReputationHealthLogicalOwnerDisablement(t *testing.T) {
	check := namedCheck{name: "ip_reputation", fn: CheckIPReputation}

	enabled, disabled := splitDisabledChecks(
		&config.Config{DisabledChecks: []string{"reputation_quota_exhausted"}},
		[]namedCheck{check},
	)
	if len(enabled) != 1 || enabled[0].name != "ip_reputation" || len(disabled) != 0 {
		t.Fatalf("disabling quota health disabled reputation scoring: enabled=%v disabled=%v", enabled, disabled)
	}

	enabled, disabled = splitDisabledChecks(
		&config.Config{DisabledChecks: []string{"ip_reputation"}},
		[]namedCheck{check},
	)
	if len(enabled) != 0 || len(disabled) != 1 || disabled[0].name != "ip_reputation" {
		t.Fatalf("disabling ip_reputation left a hosted health owner running: enabled=%v disabled=%v", enabled, disabled)
	}
}

func TestCriticalRunDoesNotPurgeDeepLogicalOwnerNames(t *testing.T) {
	check := namedCheck{name: "health", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return nil
	}}
	_, runPurge := runParallelWithContext(
		context.Background(),
		&config.Config{DisabledChecks: []string{logicalOwnerJSTaintDeep}},
		nil,
		[]namedCheck{check},
		string(TierCritical),
		true,
	)

	for source, names := range map[string][]string{
		"critical tier ownership": LatestPurgeCheckNamesForTier(TierCritical),
		"critical run":            runPurge,
	} {
		for _, name := range append(jsOwnerPurgeNames(), runnerFindingNames["yara_deep"]...) {
			if slices.Contains(names, name) {
				t.Errorf("%s unexpectedly purged deep name %q: %v", source, name, names)
			}
		}
	}
}

func TestRunnerHostAndLogicalOwnerIncompletePreserveStateFindings(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	st.SetLatestFindings([]alert.Finding{
		{Check: "yara_match_scheduled", Severity: alert.Critical, Message: "prior YARA window"},
		{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "prior JS window"},
	})

	check := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		markCheckIncomplete(ctx, "yara_deep")
		markCheckIncomplete(ctx, logicalOwnerJSTaintDeep)
		return []alert.Finding{
			{Check: "yara_scan_incomplete", Severity: alert.High, Message: "YARA partial"},
			{Check: "js_taint_scan_incomplete", Severity: alert.Warning, Message: "JS partial"},
		}
	}}
	findings, purge := runParallelWithContext(context.Background(), &config.Config{}, st, []namedCheck{check}, "deep", true)
	StoreLatestScanFindings(st, purge, findings)

	got := st.LatestFindings()
	for _, name := range []string{"yara_match_scheduled", "js_keylogger_dataflow", "yara_scan_incomplete", "js_taint_scan_incomplete"} {
		if !containsFindingCheck(got, name) {
			t.Errorf("incomplete owners lost %q: findings=%+v purge=%v", name, got, purge)
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
		markCheckIncomplete(ctx, logicalOwnerJSTaintDeep)
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

func TestRunnerAllConsumersDisabledSkipsWrapper(t *testing.T) {
	ran := false
	check := namedCheck{name: "yara_deep", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		ran = true
		return nil
	}}

	cfg := &config.Config{DisabledChecks: []string{"yara_deep", "js_taint_deep", "php_taint_deep"}}
	_, purge := runParallelWithContext(context.Background(), cfg, nil, []namedCheck{check}, "deep", true)

	if ran {
		t.Fatal("wrapper must be skipped when every consumer is disabled")
	}
	for _, name := range append(jsOwnerPurgeNames(), "yara_match_scheduled", "yara_scan_incomplete") {
		if !slices.Contains(purge, name) {
			t.Errorf("all-disabled purge list missing %q: %v", name, purge)
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
