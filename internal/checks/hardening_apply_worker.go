package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/systemdrun"
)

// The daemon runs under ProtectSystem=strict and ProtectKernelTunables, so
// sshd_config, /etc/sysctl.d, /etc/shadow, the PHP scan directories and
// /proc/sys are read-only to it. Hardening fixes run in a root worker that
// PID 1 starts as a transient unit outside that sandbox. The daemon hands it
// only a section and check names; every path and value comes from the
// fixer tables in the worker.

// HardeningApplyWorkerCommand is the csm subcommand that applies fixes.
const HardeningApplyWorkerCommand = "hardening-apply-worker"

const (
	hardeningApplyRequestLimit = 16 << 10
	hardeningApplyMaxNames     = 64
	// HardeningApplyWorkerTimeout bounds the whole worker run. Each command
	// it starts has its own hardeningApplyTimeout.
	HardeningApplyWorkerTimeout = 8 * time.Minute
)

var hardeningCheckNamePattern = regexp.MustCompile(`^[a-z0-9_]{1,80}$`)

// HardeningApplyRequest is the one request the worker reads from stdin.
type HardeningApplyRequest struct {
	Category string   `json:"category"`
	Names    []string `json:"names"`
}

type hardeningApplyReply struct {
	Results []HardeningFixResult `json:"results"`
}

// Validate refuses a request the worker would not run.
func (r HardeningApplyRequest) Validate() error {
	if !slices.Contains(HardeningCategories, r.Category) {
		return fmt.Errorf("unknown hardening category %q", r.Category)
	}
	if len(r.Names) > hardeningApplyMaxNames {
		return fmt.Errorf("too many checks: %d, at most %d", len(r.Names), hardeningApplyMaxNames)
	}
	for _, n := range r.Names {
		if !hardeningCheckNamePattern.MatchString(n) {
			return fmt.Errorf("invalid check name %q", n)
		}
	}
	return nil
}

// HandleHardeningApply reads one request from in, applies it, and writes the
// results to out as JSON. Nothing is applied unless the whole request is valid.
func HandleHardeningApply(in io.Reader, out io.Writer, apply func(category string, names []string) ([]HardeningFixResult, error)) error {
	body, err := io.ReadAll(io.LimitReader(in, hardeningApplyRequestLimit+1))
	if err != nil {
		return err
	}
	if len(body) > hardeningApplyRequestLimit {
		return errors.New("hardening apply request exceeds limit")
	}
	var req HardeningApplyRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&req); err != nil {
		return fmt.Errorf("invalid hardening apply request: %w", err)
	}
	if err = dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("hardening apply request has trailing data")
	}
	if err = req.Validate(); err != nil {
		return err
	}
	results, err := apply(req.Category, req.Names)
	if err != nil {
		return err
	}
	if results == nil {
		results = []HardeningFixResult{}
	}
	return json.NewEncoder(out).Encode(hardeningApplyReply{Results: results})
}

// RunHardeningApplyWorker applies the fixes through the root worker. An
// error wrapping systemdrun.ErrUnavailable means nothing was attempted.
// configFile is passed on so the worker reads the daemon's config.
func RunHardeningApplyWorker(ctx context.Context, configFile string, req HardeningApplyRequest) ([]HardeningFixResult, error) {
	binary, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return runHardeningApplyWorker(ctx, binary, configFile, exec.LookPath, runWorkerCommand, req)
}

func runHardeningApplyWorker(ctx context.Context, binary, configFile string, lookPath systemdrun.LookPathFunc, run systemdrun.InputRunnerFunc, req HardeningApplyRequest) ([]HardeningFixResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	args := []string{HardeningApplyWorkerCommand}
	if configFile != "" {
		args = append(args, "--config", configFile)
	}
	// Required: inside the sandbox most fixes would fail half-way, after
	// the /tmp ones had already changed the host.
	out, err := systemdrun.RunInput(ctx, lookPath, run, systemdrun.Options{Required: true, RuntimeMax: HardeningApplyWorkerTimeout}, body, binary, args...)
	if err != nil {
		if errors.Is(err, systemdrun.ErrUnavailable) {
			return nil, err
		}
		return nil, fmt.Errorf("hardening worker: %w", err)
	}
	var reply hardeningApplyReply
	if err := json.Unmarshal(out, &reply); err != nil {
		return nil, fmt.Errorf("hardening worker reply: %w: %s", err, firstLines(strings.TrimSpace(string(out)), 3))
	}
	return reply.Results, nil
}

// runWorkerCommand returns stdout alone, so the reply stays parseable, and
// adds stderr to the error.
func runWorkerCommand(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- this executable with a fixed worker subcommand, or systemd-run with fixed flags.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return out, fmt.Errorf("%w: %s", err, firstLines(msg, 3))
		}
	}
	return out, err
}
