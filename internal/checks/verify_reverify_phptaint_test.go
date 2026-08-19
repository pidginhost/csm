package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/phptaint"
)

func writePHPTaintReverifyFile(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	withQuarantineAllowedRoots(t, dir)
	path := filepath.Join(dir, "probe.php")
	if err := os.WriteFile(path, []byte("<?php echo 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, FileContentSHA256(path)
}

func TestReverifyPHPTaintUsesIsolatedAnalyzer(t *testing.T) {
	path, hash := writePHPTaintReverifyFile(t)
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		return phptaint.Report{
			Status:       phptaint.StatusAnalyzed,
			TotalResults: 1,
			Results: []phptaint.Result{{
				Source: "curl_exec", Sink: "eval", Confidence: phptaint.ConfidenceHigh,
			}},
		}
	})

	res := VerifyFindingInput(VerifyInput{
		Check: "php_remote_taint", Path: path, ContentSHA256: hash,
	})
	if !res.Checked || res.Resolved {
		t.Fatalf("PHP taint finding verified as %+v, want still flagged", res)
	}
	if !strings.Contains(res.Detail, "remote-source code execution") {
		t.Fatalf("detail = %q, want PHP taint classifier result", res.Detail)
	}
}

func TestReverifyPHPTaintFailsClosedOnCoverageGap(t *testing.T) {
	path, hash := writePHPTaintReverifyFile(t)
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		return phptaint.CoverageGap(phptaint.StatusTimeout, "worker killed")
	})

	res := VerifyFindingInput(VerifyInput{
		Check: "php_remote_taint", Path: path, ContentSHA256: hash,
	})
	if res.Checked || res.Resolved {
		t.Fatalf("coverage gap verified as %+v, want unresolved and unchecked", res)
	}
	if !strings.Contains(res.Detail, "timeout") {
		t.Fatalf("detail = %q, want timeout coverage status", res.Detail)
	}
}

func TestStaleSweepDoesNotDismissLivePHPTaintFinding(t *testing.T) {
	path, hash := writePHPTaintReverifyFile(t)
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		return phptaint.Report{
			Status:       phptaint.StatusAnalyzed,
			TotalResults: 1,
			Results:      []phptaint.Result{{Source: "curl_exec", Sink: "eval"}},
		}
	})
	finding := alert.Finding{
		Check: "php_remote_taint", Message: "live", FilePath: path, ContentSHA256: hash,
	}
	store := &fakeFindingStore{
		findings:  []alert.Finding{finding},
		dismissed: map[string]bool{},
	}

	if got := ReverifyStaleContentFindings(store); len(got) != 0 {
		t.Fatalf("live PHP taint finding was dismissed: %+v", got)
	}
	if store.dismissed[finding.Key()] {
		t.Fatal("live PHP taint finding was removed from state")
	}
}
