package modsec

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

const reloadTimeout = 30 * time.Second

// Reload executes the configured web server reload command.
// Returns combined stdout+stderr output and any error.
func Reload(command string) (string, error) {
	if command == "" {
		return "", errors.New("reload command is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
	defer cancel()

	// Run through shell to support compound commands, quoted paths, etc.
	// #nosec G204 -- `command` is the operator-configured reload command
	// from csm.yaml (e.g. "apachectl graceful"), loaded at daemon startup
	// from a root-owned config. Not webui-settable.
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	output := string(out)

	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("reload timed out after %v", reloadTimeout)
	}
	if err != nil {
		return output, fmt.Errorf("reload failed: %w (output: %s)", err, output)
	}
	return output, nil
}
