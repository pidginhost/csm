package checks

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const cmdTimeout = 2 * time.Minute

func hashFileContent(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:]), nil
}

func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

// runCmd executes a command with a timeout. Returns output and error.
// On timeout or error, returns empty output and nil error for graceful degradation.
func runCmd(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintf(os.Stderr, "Command timed out: %s %v\n", name, args)
		return nil, nil
	}
	return out, err
}

// runCmdAllowNonZero is like runCmd but treats a non-zero exit as a
// normal signal carrying output (not an error). Used for tools like
// `rpm -V`, `debsums -c`, and `dpkg --verify` which print findings to
// stdout and exit non-zero to indicate "problems found". Actual launch
// failures (binary missing, permission denied) still return an error.
func runCmdAllowNonZero(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintf(os.Stderr, "Command timed out: %s %v\n", name, args)
		return nil, nil
	}
	var exitErr *exec.ExitError
	if err != nil && errors.As(err, &exitErr) {
		// Tool ran to completion but reported findings via exit code.
		// Preserve stdout (findings); exitErr.Stderr carries stderr.
		return out, nil
	}
	return out, err
}

func runCmdCombinedContext(parent context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, cmdTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintf(os.Stderr, "Command timed out: %s %v\n", name, args)
		return nil, nil
	}
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	return out, err
}

// runCmdWithEnv executes a command with extra environment variables.
// Used for passing secrets (e.g., MYSQL_PWD) without exposing on command line.
func runCmdWithEnv(name string, args []string, extraEnv ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintf(os.Stderr, "Command timed out: %s\n", name)
		return nil, nil
	}
	return out, err
}
