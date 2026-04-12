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
	data, err := osFS.ReadFile(path)
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

// runCmd delegates to the package-level cmdExec provider.
// Check functions call runCmd; tests swap cmdExec via SetCmdRunner.
func runCmd(name string, args ...string) ([]byte, error) {
	return cmdExec.Run(name, args...)
}

func runCmdAllowNonZero(name string, args ...string) ([]byte, error) {
	return cmdExec.RunAllowNonZero(name, args...)
}

func runCmdCombinedContext(parent context.Context, name string, args ...string) ([]byte, error) {
	return cmdExec.RunContext(parent, name, args...)
}

func runCmdWithEnv(name string, args []string, extraEnv ...string) ([]byte, error) {
	return cmdExec.RunWithEnv(name, args, extraEnv...)
}

// ---------------------------------------------------------------------------
// Real implementations — used by realCmd in provider.go
// ---------------------------------------------------------------------------

func runCmdReal(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintf(os.Stderr, "Command timed out: %s %v\n", name, args)
		return nil, nil
	}
	return out, err
}

func runCmdAllowNonZeroReal(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintf(os.Stderr, "Command timed out: %s %v\n", name, args)
		return nil, nil
	}
	var exitErr *exec.ExitError
	if err != nil && errors.As(err, &exitErr) {
		return out, nil
	}
	return out, err
}

func runCmdCombinedContextReal(parent context.Context, name string, args ...string) ([]byte, error) {
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

func runCmdWithEnvReal(name string, args []string, extraEnv ...string) ([]byte, error) {
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
