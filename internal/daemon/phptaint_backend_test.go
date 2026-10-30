package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/workerproc"
)

// stubPHPTaintUnits replaces the unit seams and records what init asked for.
func stubPHPTaintUnits(t *testing.T) (stopped *[]string, units *[]workerproc.UnitConfig) {
	t.Helper()
	stopped, units = new([]string), new([]workerproc.UnitConfig)
	realStop, realLauncher, realHidden := stopParseWorkerUnits, phpTaintWorkerLauncher, parseWorkerHiddenPaths
	stopParseWorkerUnits = func(_ context.Context, prefix string) error {
		*stopped = append(*stopped, prefix)
		return nil
	}
	phpTaintWorkerLauncher = func(cfg workerproc.UnitConfig) workerproc.Launcher {
		*units = append(*units, cfg)
		return func(context.Context) (workerproc.Process, error) { return nil, errors.New("no units in tests") }
	}
	parseWorkerHiddenPaths = func() []string { return []string{"/home2"} }
	t.Cleanup(func() {
		stopParseWorkerUnits, phpTaintWorkerLauncher, parseWorkerHiddenPaths = realStop, realLauncher, realHidden
	})
	return stopped, units
}

func TestPHPTaintAnalyzerLifecycleInstallsLazySupervisor(t *testing.T) {
	stubPHPTaintUnits(t)
	allowParseWorkerCommand(t)
	d := &Daemon{binaryPath: "/opt/csm/csm"}
	if err := d.initPHPTaintAnalyzer(); err != nil {
		t.Fatal(err)
	}
	if d.phpTaintSup == nil {
		t.Fatal("PHP taint supervisor was not installed")
	}
	if got := d.phpTaintSup.SpawnCount(); got != 0 {
		t.Fatalf("worker spawned during initialization: %d", got)
	}
	q, ok := d.QueueStatuses()["php_taint.requests"]
	if !ok || q.Status != "ok" || !q.CapacityUnavailable || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("PHP worker queue was not published: found=%v status=%+v", ok, q)
	}

	d.stopPHPTaintAnalyzer()
	if d.phpTaintSup != nil {
		t.Fatal("PHP taint supervisor survived shutdown")
	}
	if q, ok := d.QueueStatuses()["php_taint.requests"]; !ok || q.Status != "ok" || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("stopped worker health was discarded: found=%v status=%+v", ok, q)
	}
}

func TestPHPTaintAnalyzerRejectsMissingBinary(t *testing.T) {
	d := &Daemon{}
	if err := d.initPHPTaintAnalyzer(); err == nil {
		t.Fatal("empty worker command was accepted")
	}
	if d.phpTaintSup != nil {
		t.Fatal("failed initialization retained a supervisor")
	}
}

func TestPHPTaintAnalyzerUsesLockedDownUnits(t *testing.T) {
	stopped, units := stubPHPTaintUnits(t)
	allowParseWorkerCommand(t)
	d := &Daemon{binaryPath: "/opt/csm/csm"}
	if err := d.initPHPTaintAnalyzer(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.stopPHPTaintAnalyzer)
	if !slices.Equal(*stopped, []string{"csm-phptaint-worker-"}) {
		t.Fatalf("leftover units stopped with %q", *stopped)
	}
	if len(*units) != 1 {
		t.Fatalf("unit configs = %d, want 1", len(*units))
	}
	cfg := (*units)[0]
	if cfg.Prefix != "csm-phptaint-worker" || !slices.Equal(cfg.InaccessiblePaths, []string{"/home2"}) {
		t.Fatalf("unit prefix %q, hidden %q", cfg.Prefix, cfg.InaccessiblePaths)
	}
	if cfg.Command != d.binaryPath || len(cfg.Args) == 0 || cfg.Args[0] != "phptaint-worker" {
		t.Fatalf("unit runs %q %q", cfg.Command, cfg.Args)
	}
}

// Both preflight and unit failures must reach the scan's coverage report.
// Leaving the analyzer unset makes the consumer silently skip candidates.
func TestPHPTaintAnalyzerReportsStartupFailure(t *testing.T) {
	for _, preflight := range []bool{true, false} {
		name := "unit launch"
		if preflight {
			name = "unexecutable binary"
		}
		t.Run(name, func(t *testing.T) {
			stubPHPTaintUnits(t)
			allowParseWorkerCommand(t)
			wantReason := "no units in tests"
			if preflight {
				wantReason = "binary is owner-only"
				checkParseWorkerCommand = func(string) error { return errors.New(wantReason) }
			}
			d := &Daemon{binaryPath: "/opt/csm/csm"}
			t.Cleanup(d.stopPHPTaintAnalyzer)
			if err := d.initPHPTaintAnalyzer(); err != nil {
				t.Fatalf("startup failure must be reported through the analyzer: %v", err)
			}
			const source = "<?php eval(curl_exec($c));"
			report := d.phpTaintSup.Analyze(context.Background(), []byte(source))
			if report.Status != phptaint.StatusWorkerFailure || !strings.Contains(report.Reason, wantReason) {
				t.Fatalf("startup failure was not preserved: %+v", report)
			}
			if d.phpTaintSup.SpawnCount() != 0 {
				t.Fatal("failed unit start fell back to another process")
			}
			root := t.TempDir()
			path := filepath.Join(root, "candidate.dat")
			if err := os.WriteFile(path, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "plain.txt"), []byte("plain text"), 0600); err != nil {
				t.Fatal(err)
			}
			findings := checks.CheckYARADeep(context.Background(), &config.Config{
				AccountRoots: []string{root}, DisabledChecks: []string{"yara_deep", "js_taint_deep"},
			}, nil)
			gaps := 0
			for _, finding := range findings {
				if finding.Check != "php_taint_scan_incomplete" {
					continue
				}
				gaps++
				if !strings.Contains(finding.Details, "worker_failure=1") || !strings.Contains(finding.Details, path) || strings.Contains(finding.Details, "plain.txt") {
					t.Fatalf("coverage gap must name only the candidate: %+v", finding)
				}
			}
			if gaps != 1 {
				t.Fatalf("got %d coverage gaps, want 1: %+v", gaps, findings)
			}
		})
	}
}
