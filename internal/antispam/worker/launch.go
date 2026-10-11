package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/systemdrun"
)

// Timeout bounds one worker run. systemd stops the transient unit at the
// same limit (spec section 4.2).
const Timeout = 5 * time.Minute

// Command is the hidden csm subcommand that runs Handle as root.
const Command = "antispam-worker"

// maxStderr bounds the worker diagnostics copied into an error.
const maxStderr = 512

// Results contain summaries, not command transcripts. Reject excess stdout
// rather than silently accepting a complete JSON prefix of truncated output.
const maxResultBytes = 1 << 20

type cappedBuffer struct {
	data     []byte
	limit    int
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - len(b.data)
	if n > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	// Drain excess output so a full pipe cannot block the worker's rollback.
	return n, nil
}

// Run sends req to `csm antispam-worker` in a transient systemd unit, outside
// the daemon's sandbox, and returns the worker's result. A failed or busy
// result is a Result, not an error; an error means no result came back. A failed
// systemd-run lookup or availability probe wraps systemdrun.ErrUnavailable and
// means the worker was not attempted. Other errors may follow state changes.
func Run(ctx context.Context, req antispam.Request) (antispam.Result, error) {
	binary, err := os.Executable()
	if err != nil {
		return antispam.Result{}, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return antispam.Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		// #nosec G204 -- this executable with a fixed subcommand, or systemd-run with fixed flags.
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = bytes.NewReader(body)
		// The transient unit's descendants may retain the
		// pipes after CommandContext kills the process we are waiting for.
		cmd.WaitDelay = time.Second
		stdout := cappedBuffer{limit: maxResultBytes}
		stderr := cappedBuffer{limit: maxStderr}
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				err = ctxErr
			}
			if detail := clip(string(stderr.data)); detail != "" {
				err = fmt.Errorf("%w: %s", err, detail)
			}
		}
		if stdout.exceeded {
			return nil, errors.Join(fmt.Errorf("antispam worker output exceeds %d bytes", maxResultBytes), err)
		}
		return stdout.data, err
	}
	return execute(ctx, binary, exec.LookPath, run)
}

func execute(ctx context.Context, binary string, lookup systemdrun.LookPathFunc, run systemdrun.RunnerFunc) (antispam.Result, error) {
	out, runErr := systemdrun.Run(ctx, lookup, run, systemdrun.Options{Pipe: true, RuntimeMax: Timeout, Required: true}, binary, Command)
	// The worker exits 1 for a failed or busy result and still prints it.
	if result, err := antispam.ParseResult(out); err == nil {
		return result, nil
	} else if runErr == nil {
		return antispam.Result{}, fmt.Errorf("antispam worker returned no result: %w", err)
	}
	return antispam.Result{}, fmt.Errorf("antispam worker failed: %w", runErr)
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxStderr {
		s = s[:maxStderr]
	}
	return s
}
