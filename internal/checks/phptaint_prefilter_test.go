package checks

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaintworker"
)

// Exercise the real adapter and supervisor: a stubbed analyzer would miss
// changes to which files reach the worker and become coverage gaps.
func TestCheckYARADeepPHPTaintPrefilterLimitsWorkerGaps(t *testing.T) {
	useRollingStore(t)
	root := t.TempDir()
	writeYARADeepFile(t, root, "a.png", "\x89PNG\r\n\x1a\n\x00")
	writeYARADeepFile(t, root, "b.txt", "plain text")
	writeYARADeepFile(t, root, "c.php", "<?php echo 'safe';")
	candidate := writeYARADeepFile(t, root, "d.dat", "<?PHP EVAL(CURL_EXEC($c));")
	// Open the breaker before the scan so neither refusal nor spawn failure
	// can turn unrelated content into unexamined PHP coverage.
	sup, err := phptaintworker.NewSupervisor(phptaintworker.SupervisorConfig{
		Command: filepath.Join(t.TempDir(), "missing-worker"),
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Stop() })
	withPHPTaintAnalyzer(t, defaultPHPTaintAnalyze)
	SetPHPTaintAnalyzer(sup)
	t.Cleanup(func() { SetPHPTaintAnalyzer(nil) })
	for range phptaintworker.ConsecutiveFailureLimit {
		sup.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	}

	findings := CheckYARADeep(context.Background(), &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerJSTaintDeep},
	}, nil)
	gaps := jsFindingsByCheck(findings, "php_taint_scan_incomplete")
	if len(gaps) != 1 || !strings.Contains(gaps[0].Details, "worker_failure=1") || !strings.Contains(gaps[0].Details, candidate) {
		t.Fatalf("gap must name only the PHP candidate: %+v", findings)
	}
	for _, name := range []string{"a.png", "b.txt", "c.php"} {
		if strings.Contains(gaps[0].Details, name) {
			t.Errorf("non-candidate %s became a coverage gap: %+v", name, gaps[0])
		}
	}
	if q := sup.QueueStatuses(time.Now())["requests"]; q.DroppedTotal != phptaintworker.ConsecutiveFailureLimit+1 || q.Depth != 0 || q.InFlight != 0 || sup.SpawnCount() != 0 {
		t.Fatalf("scan sent non-candidates to the worker: %+v", q)
	}
}
