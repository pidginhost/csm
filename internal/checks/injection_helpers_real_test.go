package checks

import (
	"context"
	"strings"
	"testing"
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
