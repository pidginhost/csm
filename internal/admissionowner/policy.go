package admissionowner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/verdict"
)

// Asker asks the panel's verdict callback about one block. It must return
// once ctx ends.
type Asker func(ctx context.Context, ip, reason string) (verdict.Response, error)

// ExecutionPolicy is one coherent reading of the configuration automatic
// execution depends on (D11). Reading the settings one getter at a time
// could combine two reloads. The publisher numbers each reading: Epoch
// grows with every change of these settings, including the callback's
// endpoint and authentication and the response lifetimes the closures
// capture, so a repeated reading is the same policy.
type ExecutionPolicy struct {
	Epoch uint64
	// Observe is mode: observe, which forbids an executable owner.
	Observe bool
	// DryRun is auto_response.dry_run resolved, true when omitted.
	DryRun         bool
	VerdictEnabled bool
	VerdictTimeout time.Duration
	CeilingLimit   uint32
	CeilingSource  string
	// Expiry is how long the response a candidate asks for lasts.
	Expiry func(admission.Candidate) time.Duration
	// AskVerdict asks the callback this policy configures, with the
	// client's own validation.
	AskVerdict Asker
}

// ErrPolicy marks an execution policy the owner refused to install.
var ErrPolicy = errors.New("execution policy refused")

const (
	minVerdictTimeout = time.Second
	maxVerdictTimeout = 30 * time.Second
)

func (p ExecutionPolicy) validate() error {
	var problem string
	switch {
	case p.Epoch == 0:
		problem = "no policy is published"
	case p.Observe:
		problem = "mode: observe forbids automatic execution"
	case p.Expiry == nil || p.AskVerdict == nil:
		problem = "the policy has no expiry or verdict asker"
	case p.CeilingLimit == 0 || p.CeilingLimit > admission.MaxCeiling:
		problem = "the hourly ceiling is out of range"
	case p.VerdictTimeout < minVerdictTimeout || p.VerdictTimeout > maxVerdictTimeout:
		problem = "the verdict timeout is out of range"
	default:
		return nil
	}
	return fmt.Errorf("%w: %s", ErrPolicy, problem)
}

// same reports whether q repeats p's settings. The closures cannot be
// compared; the publisher's epoch covers what they capture.
func (p ExecutionPolicy) same(q ExecutionPolicy) bool {
	return p.Epoch == q.Epoch && p.Observe == q.Observe && p.DryRun == q.DryRun &&
		p.VerdictEnabled == q.VerdictEnabled && p.VerdictTimeout == q.VerdictTimeout &&
		p.CeilingLimit == q.CeilingLimit && p.CeilingSource == q.CeilingSource
}

// executable reports whether the owner runs block picks (Options.Blocks).
func (o *Owner) executable() bool { return o.opts.Blocks != nil }

// refreshPolicy reads the published policy at a turn boundary and installs
// a newer one; the installed policy then serves the whole turn. An older
// epoch is ignored and the same one again changes nothing. Different
// settings under an installed epoch, or an invalid newer policy, hold
// execution until a valid newer epoch is installed.
func (o *Owner) refreshPolicy() error {
	before := o.policyErr
	defer func() {
		// Status shows the refusal while it holds execution.
		if o.policyErr != before && o.current.Load() != nil {
			o.publishExecutionHold()
		}
	}()
	if o.opts.Policy == nil {
		o.policyErr = fmt.Errorf("%w: no policy provider", ErrPolicy)
		return o.policyErr
	}
	p := o.opts.Policy()
	switch {
	case p.Epoch < o.seenEpoch:
		return o.policyErr
	case p.Epoch == o.seenEpoch && p.Epoch != 0:
		if o.policyErr == nil && !o.policy.same(p) {
			o.policyErr = fmt.Errorf("%w: epoch %d was published again with other settings", ErrPolicy, p.Epoch)
		}
		return o.policyErr
	}
	o.seenEpoch = p.Epoch
	if err := p.validate(); err != nil {
		o.policyErr = err
		return err
	}
	o.policy, o.policyErr = p, nil
	return nil
}

// ceilingConfig is the configured hourly ceiling and its source. An
// executable owner reads it from its installed policy.
func (o *Owner) ceilingConfig() (uint32, string) {
	if o.executable() {
		return o.policy.CeilingLimit, o.policy.CeilingSource
	}
	return o.opts.Ceiling()
}

// expiry is how long c's response lasts under the configuration.
func (o *Owner) expiry(c admission.Candidate) time.Duration {
	if o.executable() {
		return o.policy.Expiry(c)
	}
	return o.opts.Expiry(c)
}

// heldCause is why automatic execution is held, or nil.
func (o *Owner) heldCause() error {
	if o.policyErr != nil {
		return o.policyErr
	}
	return o.execHold
}
