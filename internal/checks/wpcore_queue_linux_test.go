//go:build linux

package checks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestWPCoreQueueInterruptedCommandRetainsPartialResults(t *testing.T) {
	for _, shape := range []struct {
		name, line string
		findings   int
	}{
		{"modified", "Warning: File doesn't verify against checksum: wp-includes/plugin.php", 3},
		{"legacy", "Warning: File wp-includes/plugin.php doesn't verify against checksum.", 3},
		{"filtered_locale", "Warning: File doesn't verify against checksum: readme.html", 0},
		{"filtered_log", "Warning: File should not exist: error_log", 0},
		{"extraneous", "Warning: File should not exist: wp-includes/extra.php", 3},
		{"no_integrity_control", "Error: fixture checksum operation unavailable", 0},
	} {
		for _, signaled := range []bool{false, true} {
			ending := "completed_exit_one"
			if signaled {
				ending = "interrupted_SIGTERM"
			}
			t.Run(shape.name+"/"+ending, func(t *testing.T) {
				roots, _ := wpCoreQueueFixtures(t, 3)
				bin := t.TempDir()
				path := filepath.Join(bin, "wp")
				suffix := "exit 1\n"
				if signaled {
					suffix = "kill -TERM \"$$\"\n"
				}
				script := "#!/bin/sh\nprintf '%s\\n' \"" + shape.line + "\"\n" + suffix
				if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				var calls, observedSignals atomic.Int32
				withMockCmd(t, &mockCmd{runContext: func(ctx context.Context, name string, args ...string) ([]byte, error) {
					wpCoreQueuePath(t, name, args)
					calls.Add(1)
					out, err := runCmdCombinedContextReal(ctx, name, args...)
					if ctx.Err() != nil {
						t.Error("parent context unexpectedly ended")
					}
					if !strings.Contains(string(out), shape.line) {
						t.Error("real helper lost the partial checksum output")
					}
					var exited *exec.ExitError
					if !errors.As(err, &exited) {
						t.Errorf("real helper did not return its process failure: %T", err)
					} else {
						status, ok := exited.Sys().(syscall.WaitStatus)
						switch {
						case !ok:
							t.Error("missing actual Linux wait status")
						case signaled:
							if !status.Signaled() || status.Signal() != syscall.SIGTERM {
								t.Errorf("actual command was not terminated by SIGTERM: %v", status)
							} else {
								observedSignals.Add(1)
							}
						case !status.Exited() || status.ExitStatus() != 1:
							t.Errorf("normal checksum mismatch did not exit 1: %v", status)
						}
					}
					return out, err
				}})
				findings := CheckWPCore(context.Background(), &config.Config{}, nil)
				if calls.Load() != 3 || len(findings) != shape.findings {
					t.Fatalf("partial result policy changed: commands=%d findings=%d want=%d", calls.Load(), len(findings), shape.findings)
				}
				if signaled && observedSignals.Load() != 3 {
					t.Fatalf("only %d real interrupted commands observed", observedSignals.Load())
				}
				if shape.findings > 0 {
					seen := make(map[string]bool)
					for _, f := range findings {
						if f.Check != "wp_core_integrity" {
							t.Errorf("unexpected partial finding kind: %s", f.Check)
						}
						if shape.name != "extraneous" && f.Severity != alert.Critical {
							t.Errorf("modified PHP severity changed: %s", f.Severity)
						}
						seen[findingDetailPath(f.Details)] = true
					}
					for _, root := range roots {
						if !seen[filepath.Dir(root)] {
							t.Error("partial finding missing installation identity")
						}
					}
				}
				// A command the kernel killed lost its work. One that ran and
				// exited with an error answered the check, even when the
				// answer is that this tree could not be verified.
				wantLoss := uint64(0)
				if signaled {
					wantLoss = 3
				}
				row := wpCoreQueueSnapshot(t, time.Now())
				if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != wantLoss || row.RecentDrops != wantLoss {
					t.Errorf("real command interruption must retain partial findings and count each unfinished installation: got=%+v want_lost=%d", row, wantLoss)
				}
				if wantLoss == 3 && row.Reason != "dropped_work" {
					t.Errorf("repeated real operational failures are reported healthy: %+v", row)
				}
				if GlobalCMSCache().Size() != 0 {
					t.Fatal("failed command populated verified cache")
				}
			})
		}
	}
}
