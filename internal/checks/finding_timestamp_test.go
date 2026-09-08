package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func assertFindingTimestamp(t *testing.T, f alert.Finding, before, after time.Time) {
	t.Helper()
	if f.Timestamp.Before(before) || f.Timestamp.After(after) {
		t.Errorf("%s timestamp = %v, want within [%v, %v]", f.Check, f.Timestamp, before, after)
	}
}

// The legacy exec poller sends these findings directly, without the scan
// runner's timestamp fallback. Process identity checks also need this time.
func TestLegacyProcessFindingsStampTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name, exe, cmdline, check string
	}{
		{"kernel disguise", "/opt/worker", "[kworker/0:1]", "fake_kernel_thread"},
		{"executable name", "/opt/gsocket", "worker", "suspicious_process"},
		{"command line", "/opt/worker", "bash -i", "suspicious_process"},
		{"executable path", "/tmp/worker", "worker", "suspicious_process"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withMockOS(t, &mockOS{
				glob: func(pattern string) ([]string, error) {
					return []string{filepath.Join("/proc/4242", filepath.Base(pattern))}, nil
				},
				readFile: func(name string) ([]byte, error) {
					switch filepath.Base(name) {
					case "status":
						return []byte("Name:\tworker\nUid:\t1001\t1001\t1001\t1001\n"), nil
					case "cmdline":
						return []byte(tc.cmdline), nil
					}
					return nil, os.ErrNotExist
				},
				readlink: func(string) (string, error) { return tc.exe, nil },
			})
			check := CheckSuspiciousProcesses
			if tc.check == "fake_kernel_thread" {
				check = CheckFakeKernelThreads
			}
			before := time.Now()
			findings := check(context.Background(), &config.Config{}, nil)
			after := time.Now()
			if len(findings) != 1 || findings[0].Check != tc.check || findings[0].PID != 4242 {
				t.Fatalf("findings = %+v, want one %s for PID 4242", findings, tc.check)
			}
			assertFindingTimestamp(t, findings[0], before, after)
		})
	}
}

func TestAutoResponseFindingsStampTimestamp(t *testing.T) {
	t.Run("kill", func(t *testing.T) {
		calls := withSimulatedProcessSignal(t)
		withMockOS(t, &procMock{uid: "1001", exe: "/tmp/evil", uptime: 1000, startTick: 10000})
		cfg := &config.Config{}
		cfg.AutoResponse.Enabled, cfg.AutoResponse.KillProcesses = true, true
		before := time.Now()
		findings := AutoKillProcesses(context.Background(), cfg, []alert.Finding{{
			Check: "suspicious_process", PID: 4242, Severity: alert.Critical, Timestamp: before.Add(-time.Second),
		}})
		after := time.Now()
		if len(findings) != 1 || len(calls.signaled) != 1 || calls.signaled[0] != 4242 {
			t.Fatalf("findings = %+v, signaled = %v", findings, calls.signaled)
		}
		assertFindingTimestamp(t, findings[0], before, after)
	})
	t.Run("quarantine", func(t *testing.T) {
		root := t.TempDir()
		withAutoRespQuarantineDir(t, filepath.Join(root, "quarantine"))
		path := filepath.Join(root, "dropper.php")
		if err := os.WriteFile(path, []byte("<?php system($_GET['cmd']);"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{}
		cfg.AutoResponse.Enabled, cfg.AutoResponse.QuarantineFiles = true, true
		before := time.Now()
		findings := AutoQuarantineFiles(cfg, []alert.Finding{{
			Check: "webshell", Severity: alert.Critical, FilePath: path,
		}})
		after := time.Now()
		if len(findings) != 1 || !strings.Contains(findings[0].Message, "AUTO-QUARANTINE") {
			t.Fatalf("findings = %+v, want one quarantine action", findings)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("quarantined source still present: %v", err)
		}
		assertFindingTimestamp(t, findings[0], before, after)
	})
}
