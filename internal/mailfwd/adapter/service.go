package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"time"

	"github.com/pidginhost/csm/internal/mailfwd/policy"
	"github.com/pidginhost/csm/internal/systemdrun"
)

const eximMutationLimit = 8 << 20
const eximMutationTimeout = 5 * time.Minute

// The helper accepts policy data, never a destination path or command.
type eximMutation struct {
	Operation string        `json:"operation"`
	Config    policy.Config `json:"config"`
	BadIPs    []string      `json:"bad_ips"`
}

type eximServiceAdapter struct {
	*EximAdapter
	mutate func(eximMutation) error
}

// NewEximServiceAdapter keeps the entire config transaction, including rollback,
// outside the daemon's mount namespace. Read-only status and lookup refreshes
// still use the daemon's existing access to the CSM state directory.
func NewEximServiceAdapter() ForwardGuard {
	return &eximServiceAdapter{EximAdapter: NewEximAdapter(), mutate: runEximMutation}
}

func (a *eximServiceAdapter) Apply(cfg policy.Config, ips []string) error {
	return a.mutate(eximMutation{Operation: "apply", Config: cfg, BadIPs: ips})
}

func (a *eximServiceAdapter) Remove() error {
	return a.mutate(eximMutation{Operation: "remove"})
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
	if err != nil {
		return commandFailure("forward-guard worker", output, err)
	}
	return nil
}

// HandleEximMutation handles one bounded request at the privileged CLI boundary.
// Only the fixed cPanel locations in NewEximAdapter are available to callers.
func HandleEximMutation(input io.Reader) error {
	return handleEximMutation(input, lockedEximAdapter{NewEximAdapter()})
}

func handleEximMutation(input io.Reader, target ForwardGuard) error {
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
		return target.Apply(request.Config, request.BadIPs)
	case "remove":
		if request.Config != (policy.Config{}) || len(request.BadIPs) != 0 {
			return fmt.Errorf("remove request must not contain policy data")
		}
		return target.Remove()
	default:
		return fmt.Errorf("unsupported forward-guard operation")
	}
}
