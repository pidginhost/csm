package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/jstaint"
	"github.com/pidginhost/csm/internal/state"
)

func TestOversizeJSSourceWithNULKeepsCoverageAndPriorFinding(t *testing.T) {
	useRollingStore(t)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	// The prefix has no taint candidate tokens, and ends inside a literal.
	// A real flow beyond the peek must still be reported as unexamined.
	source := "const data='\x00" + strings.Repeat("x", jstaint.MaxSourceBytes) + "';" + jsKeyloggerFixture
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "bundle.dat", source)
	st.SetLatestFindings([]alert.Finding{{
		Check: "js_keylogger_dataflow", Severity: alert.Critical,
		Message: "prior JS finding", FilePath: path,
	}})
	calls := countJSTaintAnalyze(t)
	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerPHPTaintDeep},
	}, st)

	if got := calls.Load(); got != 0 {
		t.Fatalf("oversize source reached the analyzer %d times", got)
	}
	gaps := jsFindingsByCheck(findings, "js_taint_scan_incomplete")
	if len(gaps) != 1 || !strings.Contains(gaps[0].Details, "oversize=1") || !strings.Contains(gaps[0].Details, path) {
		t.Fatalf("coverage = %+v, want one oversize gap for %s", gaps, path)
	}
	carried := jsFindingsByCheck(findings, "js_keylogger_dataflow")
	if len(carried) != 1 || carried[0].FilePath != path {
		t.Fatalf("prior findings = %+v, want the previous finding at %s", carried, path)
	}
	if collector.contains(logicalOwnerJSTaintDeep) {
		t.Fatal("a known-path gap marked the whole check incomplete")
	}
}
