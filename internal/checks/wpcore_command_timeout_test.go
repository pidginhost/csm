package checks

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestWPCoreRealCommandTimeoutMustNotVerifyFiles(t *testing.T) {
	wpCoreQueueFixtures(t, 1)
	var calls atomic.Int32
	withMockCmd(t, &mockCmd{runContext: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		wpCoreQueuePath(t, name, args)
		calls.Add(1)
		started := time.Now()
		out, err := runCmdCombinedContextReal(ctx, "sleep", strconv.Itoa(int(cmdTimeout/time.Second)+5))
		if elapsed := time.Since(started); elapsed < cmdTimeout || ctx.Err() != nil {
			t.Errorf("did not exercise the command's own deadline: elapsed=%s parent=%v", elapsed, ctx.Err())
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("actual command timeout returned %v", err)
		}
		return out, err
	}})
	findings := CheckWPCore(context.Background(), &config.Config{}, nil)
	if calls.Load() != 1 || len(findings) != 0 || GlobalCMSCache().Size() != 0 {
		t.Errorf("timed-out verification outcome: calls=%d findings=%d cached=%d", calls.Load(), len(findings), GlobalCMSCache().Size())
	}
	if q := wpCoreQueueSnapshot(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 1 {
		t.Errorf("real command timeout did not retain failed work: %+v", q)
	}
}

func TestRunCmdCombinedContextPreservesNativeOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, script, output string
		exitCode             int
		canceled             bool
	}{
		{name: "success", script: "printf 'fixture output'", output: "fixture output"},
		{name: "nonzero", script: "printf 'fixture output'; printf 'fixture error' >&2; exit 7", output: "fixture outputfixture error", exitCode: 7},
		{name: "canceled", script: "printf 'fixture must not run'", canceled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			out, err := runCmdCombinedContextReal(ctx, "sh", "-c", tc.script)
			if string(out) != tc.output {
				t.Errorf("combined output = %q, want %q", out, tc.output)
			}
			switch {
			case tc.canceled:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("parent cancellation = %v", err)
				}
			case tc.exitCode == 0:
				if err != nil {
					t.Errorf("successful command = %v", err)
				}
			default:
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != tc.exitCode {
					t.Errorf("native exit result = %v", err)
				}
			}
		})
	}
}

func TestRunCmdCombinedContextPreservesParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	out, err := runCmdCombinedContextReal(ctx, "sleep", "1")
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(ctx.Err(), context.DeadlineExceeded) || len(out) != 0 {
		t.Fatalf("parent deadline result: out=%q error=%v parent=%v", out, err, ctx.Err())
	}
}

func TestVerifyWPCoreRealTimeoutDoesNotResolveFinding(t *testing.T) {
	root := t.TempDir()
	withWPVerifyAllowedRoots(t, root)
	dir := makeWPInstall(t, root, "alice")
	var calls int
	withMockCmd(t, &mockCmd{runContext: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if path := wpCoreQueuePath(t, name, args); path != dir {
			t.Errorf("re-check path = %q, want %q", path, dir)
		}
		calls++
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("re-check command has no deadline")
		}
		// Dispatch delay consumes the caller's existing deadline budget.
		time.Sleep(100 * time.Millisecond)
		out, err := runCmdCombinedContextReal(ctx, "sleep", strconv.Itoa(int(wpVerifyTimeout/time.Second)+5))
		if time.Now().Before(deadline) || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("did not reach the re-check deadline: parent=%v", ctx.Err())
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("actual re-check timeout returned %v", err)
		}
		return out, err
	}})
	result := VerifyFinding("wp_core_integrity", "WordPress core integrity failure for alice", "Path: "+dir)
	if calls != 1 || result.Checked || result.Resolved {
		t.Fatalf("timed-out re-check: commands=%d result=%+v", calls, result)
	}
}
