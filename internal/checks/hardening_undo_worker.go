package checks

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/systemdrun"
)

// HardeningUndoWorkerCommand is the csm subcommand that undoes one applied
// fix.
const HardeningUndoWorkerCommand = "hardening-undo-worker"

// HardeningUndoRequest is the one request the undo worker reads from stdin.
// It names a fix and nothing else: what to restore comes from the record
// the root worker kept when it applied the fix.
type HardeningUndoRequest struct {
	Name string `json:"name"`
}

// Validate refuses a request the worker would not run.
func (r HardeningUndoRequest) Validate() error {
	if !knownHardeningFix(r.Name) {
		return fmt.Errorf("unknown hardening fix %q", r.Name)
	}
	return nil
}

// ReadHardeningUndoRequest checks the complete request at both the HTTP
// and worker boundaries.
func ReadHardeningUndoRequest(in io.Reader) (HardeningUndoRequest, error) {
	var req HardeningUndoRequest
	body, err := io.ReadAll(io.LimitReader(in, hardeningApplyRequestLimit+1))
	if err != nil {
		return req, err
	}
	if len(body) > hardeningApplyRequestLimit {
		return req, errors.New("hardening undo request exceeds limit")
	}
	if err := jsonv2.Unmarshal(body, &req, jsonv2.RejectUnknownMembers(true)); err != nil {
		return req, errors.New("invalid hardening undo request")
	}
	return req, req.Validate()
}

// HandleHardeningUndo reads one request from in, undoes that fix, and
// writes the result to out as JSON. Nothing is undone unless the whole
// request is valid.
func HandleHardeningUndo(in io.Reader, out io.Writer, undo func(string) HardeningFixResult) error {
	req, err := ReadHardeningUndoRequest(in)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(undo(req.Name))
}

// RunHardeningUndoWorker undoes one fix through the root worker. An error
// wrapping systemdrun.ErrUnavailable means nothing was attempted.
func RunHardeningUndoWorker(ctx context.Context, cfg *config.Config, name string) (HardeningFixResult, error) {
	binary, err := os.Executable()
	if err != nil {
		return HardeningFixResult{}, err
	}
	return runHardeningUndoWorker(ctx, binary, cfg, exec.LookPath, RunWorkerCommand, name)
}

func runHardeningUndoWorker(ctx context.Context, binary string, cfg *config.Config, lookPath systemdrun.LookPathFunc, run systemdrun.InputRunnerFunc, name string) (HardeningFixResult, error) {
	req := HardeningUndoRequest{Name: name}
	if err := req.Validate(); err != nil {
		return HardeningFixResult{}, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return HardeningFixResult{}, err
	}
	out, err := runHardeningWorker(ctx, binary, cfg, lookPath, run, HardeningUndoWorkerCommand, body)
	if err != nil {
		return HardeningFixResult{}, err
	}
	var res HardeningFixResult
	if err := jsonv2.Unmarshal(out, &res, jsonv2.RejectUnknownMembers(true)); err != nil || res.Name != name ||
		(res.Status != "undone" && res.Status != "refused" && res.Status != "failed") {
		return HardeningFixResult{}, errors.New("invalid hardening worker reply")
	}
	return res, nil
}
