package checks

import (
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
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
	Names    []string `json:"names,omitempty"`
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

// ReadHardeningApplyRequest checks the complete request at both the HTTP
// and worker boundaries. Omitted names and an empty list select the section.
func ReadHardeningApplyRequest(in io.Reader) (HardeningApplyRequest, error) {
	var req HardeningApplyRequest
	body, err := io.ReadAll(io.LimitReader(in, hardeningApplyRequestLimit+1))
	if err != nil {
		return req, err
	}
	if len(body) > hardeningApplyRequestLimit {
		return req, errors.New("hardening apply request exceeds limit")
	}
	// Distinguish an omitted selection from an explicit JSON null.
	req.Names = []string{}
	if err = jsonv2.Unmarshal(body, &req, jsonv2.RejectUnknownMembers(true)); err != nil {
		return req, errors.New("invalid hardening apply request")
	}
	if req.Names == nil {
		return req, errors.New("names must be an array")
	}
	return req, req.Validate()
}

// HandleHardeningApply reads one request from in, applies it, and writes the
// results to out as JSON. Nothing is applied unless the whole request is valid.
func HandleHardeningApply(in io.Reader, out io.Writer, apply func(category string, names []string) ([]HardeningFixResult, error)) error {
	req, err := ReadHardeningApplyRequest(in)
	if err != nil {
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
// The worker receives the same main configuration and drop-in directory.
func RunHardeningApplyWorker(ctx context.Context, cfg *config.Config, req HardeningApplyRequest) ([]HardeningFixResult, error) {
	binary, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return runHardeningApplyWorker(ctx, binary, cfg, exec.LookPath, RunWorkerCommand, req)
}

func runHardeningApplyWorker(ctx context.Context, binary string, cfg *config.Config, lookPath systemdrun.LookPathFunc, run systemdrun.InputRunnerFunc, req HardeningApplyRequest) ([]HardeningFixResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	out, err := runHardeningWorker(ctx, binary, cfg, lookPath, run, HardeningApplyWorkerCommand, body)
	if err != nil {
		return nil, err
	}
	var reply hardeningApplyReply
	if err := jsonv2.Unmarshal(out, &reply, jsonv2.RejectUnknownMembers(true)); err != nil || reply.Results == nil {
		return nil, errors.New("invalid hardening worker reply")
	}
	for _, result := range reply.Results {
		if !hardeningCheckNamePattern.MatchString(result.Name) || (result.Status != "applied" && result.Status != "skipped" && result.Status != "failed") {
			return nil, errors.New("invalid hardening worker result")
		}
	}
	return reply.Results, nil
}

// hardeningWorkerUnit names the transient unit of both hardening workers.
// systemd will not start a second unit under a name in use, so an apply and
// an undo never change the same files and records at once.
const hardeningWorkerUnit = "csm-hardening-apply.service"

// runHardeningWorker runs a hardening worker command as a transient unit
// outside the sandbox, with body on stdin, and returns its stdout. The
// worker receives the same main configuration and drop-in directory.
func runHardeningWorker(ctx context.Context, binary string, cfg *config.Config, lookPath systemdrun.LookPathFunc, run systemdrun.InputRunnerFunc, command string, body []byte) ([]byte, error) {
	args := []string{command}
	if cfg.ConfigFile != "" {
		path, err := filepath.Abs(cfg.ConfigFile)
		if err != nil {
			return nil, err
		}
		args = append(args, "--config", path)
		if cfg.ConfigDir != "" {
			args = append(args, "--config-dir", cfg.ConfigDir)
		}
	}
	// Required: inside the sandbox most fixes would fail half-way, after
	// the /tmp ones had already changed the host.
	out, err := systemdrun.RunInput(ctx, lookPath, run, systemdrun.Options{Required: true, Unit: hardeningWorkerUnit, RuntimeMax: HardeningApplyWorkerTimeout}, body, binary, args...)
	if err != nil {
		if errors.Is(err, systemdrun.ErrUnavailable) {
			return nil, err
		}
		return nil, fmt.Errorf("hardening worker: %w", err)
	}
	return out, nil
}

// RunWorkerCommand runs a worker with input on stdin. It returns stdout
// alone, so a reply stays parseable, and adds stderr to the error.
func RunWorkerCommand(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
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
