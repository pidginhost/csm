package checks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// These tests exercise the *Real implementations directly with real
// /bin/echo / /bin/false / /bin/sh invocations.

func TestRunCmdRealSuccess(t *testing.T) {
	out, err := runCmdReal("/bin/echo", "hello")
	if err != nil {
		t.Fatalf("expected no error from echo, got %v", err)
	}
	if !strings.Contains(string(out), "hello") {
		t.Errorf("expected output to contain 'hello', got %q", out)
	}
}

func TestRunCmdRealCommandNotFound(t *testing.T) {
	_, err := runCmdReal("/nonexistent-binary-xyz", "arg")
	if err == nil {
		t.Error("expected error for missing binary")
	}
}

func TestRunCmdAllowNonZeroSuccess(t *testing.T) {
	out, err := runCmdAllowNonZeroReal("/bin/echo", "ok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "ok") {
		t.Errorf("expected 'ok' in output, got %q", out)
	}
}

func TestRunCmdAllowNonZeroSwallowsExitError(t *testing.T) {
	// /usr/bin/false exits 1 — should not surface as error to the caller.
	out, err := runCmdAllowNonZeroReal("/usr/bin/false")
	if err != nil {
		t.Errorf("non-zero exit should be swallowed, got %v", err)
	}
	// Output is normally empty for false.
	if string(out) != "" {
		t.Errorf("expected empty output from /usr/bin/false, got %q", out)
	}
}

func TestRunCmdAllowNonZeroCommandNotFoundErrors(t *testing.T) {
	_, err := runCmdAllowNonZeroReal("/nonexistent-binary-xyz")
	if err == nil {
		t.Error("missing binary should still surface as error")
	}
}

func TestRunCmdCombinedContextSuccess(t *testing.T) {
	out, err := runCmdCombinedContextReal(context.Background(), "/bin/echo", "combined")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "combined") {
		t.Errorf("expected output to contain 'combined', got %q", out)
	}
}

func TestRunCmdCombinedContextParentCancelledReturnsCtxErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Use a command that would normally succeed quickly.
	_, err := runCmdCombinedContextReal(ctx, "/bin/echo", "x")
	if err == nil {
		t.Error("expected error from cancelled parent context")
	}
}

func TestRunCmdWithEnvRealPropagatesEnv(t *testing.T) {
	// Use /bin/sh to print an env var we set, verifying RunWithEnv
	// extends the environment.
	out, err := runCmdWithEnvReal("/bin/sh", []string{"-c", "echo $CSM_TEST_VAR"}, "CSM_TEST_VAR=marker")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "marker") {
		t.Errorf("expected env var to propagate, got %q", out)
	}
}

func TestRunCmdWithEnvRealCommandNotFoundErrors(t *testing.T) {
	_, err := runCmdWithEnvReal("/nonexistent-xyz", []string{"a"}, "X=1")
	if err == nil {
		t.Error("missing binary should error")
	}
}

// runCmdStdoutContextReal: stdout-only variant used by plugincheck so wp-cli
// chatter on stderr (PHP warnings, MYSQL_OPT_RECONNECT deprecations, plugin
// backtraces) can't pollute the JSON on stdout.

func TestRunCmdStdoutContextSuccess(t *testing.T) {
	out, err := runCmdStdoutContextReal(context.Background(), "/bin/echo", "stdout-only")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "stdout-only") {
		t.Errorf("expected 'stdout-only' in output, got %q", out)
	}
}

func TestRunCmdStdoutContextDropsStderr(t *testing.T) {
	// This is the regression guard for the "invalid character 'W' looking
	// for beginning of value" class: a child that prints junk on stderr
	// and JSON on stdout must yield *only* the JSON.
	out, err := runCmdStdoutContextReal(context.Background(), "/bin/sh", "-c",
		`echo "WARNING: MYSQL_OPT_RECONNECT" >&2; echo '[{"name":"x"}]'`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != `[{"name":"x"}]` {
		t.Errorf("stdout-only runner leaked stderr: got %q", got)
	}
}

func TestRunCmdStdoutContextTimeoutReturnsDeadlineExceeded(t *testing.T) {
	// Parent with a short deadline. /bin/sleep 5 is guaranteed to outlive it.
	// Helper must surface context.DeadlineExceeded so the caller can tell a
	// hung command apart from a legitimately-empty result (the old code
	// returned (nil, nil) and parsers downstream misreported the cause as
	// "unexpected end of JSON input").
	parent, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := runCmdStdoutContextReal(parent, "/bin/sleep", "5")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestRunCmdStdoutContextParentCancelledReturnsCtxErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runCmdStdoutContextReal(ctx, "/bin/echo", "x")
	if err == nil {
		t.Error("expected error from cancelled parent context")
	}
}
