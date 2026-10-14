package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/pidginhost/csm/internal/eximlock"
	"github.com/pidginhost/csm/internal/mailfwd/policy"
	"github.com/pidginhost/csm/internal/systemdrun"
)

const eximMutationLimit = 8 << 20
const eximMutationTimeout = 5 * time.Minute

// workerBusyExit is the worker's exit status when another CSM transaction
// holds the Exim lock (EX_TEMPFAIL). systemd-run --pipe returns the unit's
// exit status unchanged, and systemd's own exit codes for a unit it could
// not start begin at 200.
const workerBusyExit = 75

// WorkerExitCode is the forward-guard worker's exit status for the error
// HandleEximMutation returned.
func WorkerExitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, eximlock.ErrBusy), errors.Is(err, errSuperseded):
		return workerBusyExit
	default:
		return 1
	}
}

// The helper accepts policy data, never a destination path or command.
type eximMutation struct {
	RequestID string        `json:"request_id,omitempty"`
	Operation string        `json:"operation"`
	Config    policy.Config `json:"config"`
	BadIPs    []string      `json:"bad_ips"`
}

// applyTo is called only after validation at the worker boundary.
func (r eximMutation) applyTo(target ForwardGuard) error {
	if r.Operation == "apply" {
		return target.Apply(r.Config, r.BadIPs)
	}
	return target.Remove()
}

type eximServiceAdapter struct {
	*EximAdapter
	mutate func(eximMutation) error
}

// NewEximServiceAdapter keeps the entire config transaction, including rollback,
// outside the daemon's mount namespace. Status reads, request records and
// lookup refreshes still use the daemon's existing access to the CSM state
// directory.
func NewEximServiceAdapter() ForwardGuard {
	return &eximServiceAdapter{EximAdapter: NewEximAdapter(), mutate: runEximMutation}
}

func (a *eximServiceAdapter) Apply(cfg policy.Config, ips []string) error {
	return a.submit(eximMutation{Operation: "apply", Config: cfg, BadIPs: ips})
}

// Invalidate cancels any request still waiting for a worker, without starting
// one. Observe mode calls it: a worker started before the switch must not
// change mail configuration afterwards.
func (a *eximServiceAdapter) Invalidate() error {
	return eximlock.WithRetry(context.Background(), filepath.Dir(a.badIPsPath), eximlock.RecordWait, func() error {
		return writeFileAtomic(a.requestPath(), []byte("null"))
	})
}

func (a *eximServiceAdapter) Remove() error {
	return a.submit(eximMutation{Operation: "remove"})
}

// submit records request as the latest one under the shared Exim lock, then
// hands it to the root worker. A worker started for an older request, such
// as one from before a daemon restart, finds the newer record and changes
// nothing. A removal with no rule installed needs no worker. A busy lock
// defers the request, and a request that cannot be recorded starts no
// worker, because the worker could not tell that it is current.
func (a *eximServiceAdapter) submit(request eximMutation) error {
	// Settings can repeat across restarts; each submission must still
	// supersede earlier workers with the same policy and sender list.
	request.RequestID = rand.Text()
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	done := false
	record := func() error {
		if writeErr := writeFileAtomic(a.requestPath(), body); writeErr != nil {
			return writeErr
		}
		if request.Operation == "remove" {
			status, statusErr := a.Status()
			done = statusErr == nil && !status.Installed
		}
		return nil
	}
	if err = eximlock.WithRetry(context.Background(), filepath.Dir(a.badIPsPath), eximlock.RecordWait, record); err != nil || done {
		return err
	}
	return a.mutate(request)
}

func runEximMutation(request eximMutation) error {
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(body) > eximMutationLimit {
		return fmt.Errorf("forward-guard request exceeds limit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), eximMutationTimeout)
	defer cancel()
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		// #nosec G204 -- command is this executable with a fixed helper subcommand, or systemd-run with fixed flags.
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = bytes.NewReader(body)
		return cmd.CombinedOutput()
	}
	return executeEximMutation(ctx, binary, exec.LookPath, run)
}

func executeEximMutation(ctx context.Context, binary string, lookup systemdrun.LookPathFunc, run systemdrun.RunnerFunc) error {
	output, err := systemdrun.Run(ctx, lookup, run, systemdrun.Options{Pipe: true, RuntimeMax: eximMutationTimeout}, binary, "forward-guard-worker")
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == workerBusyExit {
		return fmt.Errorf("forward-guard worker: %w", eximlock.ErrBusy)
	}
	if err != nil {
		return commandFailure("forward-guard worker", output, err)
	}
	return nil
}

// HandleEximMutation handles one bounded request at the privileged CLI boundary.
// Only the fixed cPanel locations in NewEximAdapter are available to callers.
func HandleEximMutation(input io.Reader) error {
	return handleEximMutation(input, lockedEximAdapter{NewEximAdapter()}.mutate)
}

func handleEximMutation(input io.Reader, mutate func(eximMutation) error) error {
	body, err := io.ReadAll(io.LimitReader(input, eximMutationLimit+1))
	if err != nil {
		return err
	}
	if len(body) > eximMutationLimit {
		return fmt.Errorf("forward-guard request exceeds limit")
	}
	var request eximMutation
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("invalid forward-guard request: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("forward-guard request has trailing data")
	}
	switch request.Operation {
	case "apply":
		if !request.Config.Enabled || request.Config.DryRun || (!request.Config.HoldSignals.BounceBackscatter && !request.Config.HoldSignals.BadSenderIP) {
			return fmt.Errorf("forward-guard request must enable an enforceable policy")
		}
		for _, ip := range request.BadIPs {
			addr, err := netip.ParseAddr(ip)
			if err != nil || addr.Zone() != "" {
				return fmt.Errorf("forward-guard request has an invalid address")
			}
		}
	case "remove":
		if request.Config != (policy.Config{}) || len(request.BadIPs) != 0 {
			return fmt.Errorf("remove request must not contain policy data")
		}
	default:
		return fmt.Errorf("unsupported forward-guard operation")
	}
	return mutate(request)
}
