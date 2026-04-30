package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/control"
)

// PHPRelayController aggregates the phprelay-state references the
// control-socket handlers need. One instance per running daemon;
// constructed in daemon.New (Phase O2) and assigned to ControlListener.phprelay.
//
// The spool-pipeline reference (linux-only spoolPipeline) is intentionally
// not held here so this file stays cross-platform. Phase O2 can attach
// the pipeline through a separate linux-gated wiring file if needed.
type PHPRelayController struct {
	eng          *evaluator
	msgIndex     *msgIDIndex
	ignores      *ignoreList
	actionDryRun *runtimeBool
	enabled      bool
	platform     string
}

// runtimeBool is the in-memory dry-run override; effective-value precedence
// resolves CLI > bbolt > csm.yaml at read time.
type runtimeBool struct {
	mu    sync.Mutex
	set   bool
	value bool
}

//nolint:unused // wired in M3 by phprelay.dry_run handler
func (r *runtimeBool) Set(v bool) { r.mu.Lock(); r.set = true; r.value = v; r.mu.Unlock() }

//nolint:unused // wired in M3 by phprelay.dry_run handler
func (r *runtimeBool) Reset() { r.mu.Lock(); r.set = false; r.mu.Unlock() }

func (r *runtimeBool) Get() (value, set bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.value, r.set
}

// effectiveDryRun resolves the CLI > bbolt > csm.yaml precedence chain.
// For M1 the CLI override is the only source; bbolt + yaml join in M3.
// Returns (effective, source) where source identifies the winning input.
func (c *PHPRelayController) effectiveDryRun() (bool, string) {
	if v, ok := c.actionDryRun.Get(); ok {
		return v, "runtime"
	}
	// Fallback: yaml-level (M3 will add bbolt between).
	if c.eng != nil && c.eng.cfg != nil {
		return c.eng.cfg.PHPRelayDryRunEnabled(), "yaml"
	}
	return true, "default"
}

// Status returns a snapshot of detector state for `csm phprelay status`.
func (c *PHPRelayController) Status(_ context.Context, _ control.PHPRelayStatusRequest) (control.PHPRelayStatusResponse, error) {
	resp := control.PHPRelayStatusResponse{
		Enabled:               c.enabled,
		Platform:              c.platform,
		EffectiveAccountLimit: c.eng.effectiveAccountLimit,
		IgnoresActive:         len(c.ignores.List()),
		RecentFindings:        map[string]int{}, // populated by metrics in Phase N
	}
	eff, _ := c.effectiveDryRun()
	resp.DryRun = eff
	if c.eng.scripts != nil {
		resp.ScriptsTracked = len(c.eng.scripts.Snapshot())
	}
	if c.msgIndex != nil {
		resp.MsgIDIndexSize = c.msgIndex.Len()
	}
	return resp, nil
}

// handlePHPRelayStatus is the dispatcher-side adapter that bridges the
// json.RawMessage args to the typed Status method.
func (c *ControlListener) handlePHPRelayStatus(argsRaw json.RawMessage) (any, error) {
	if c.phprelay == nil {
		return nil, fmt.Errorf("phprelay controller not wired (Phase O2)")
	}
	var req control.PHPRelayStatusRequest
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &req); err != nil {
			return nil, fmt.Errorf("bad args: %w", err)
		}
	}
	return c.phprelay.Status(context.Background(), req)
}

func (c *PHPRelayController) IgnoreScript(_ context.Context, req control.PHPRelayIgnoreScriptRequest) (control.PHPRelayIgnoreScriptResponse, error) {
	if req.ScriptKey == "" {
		return control.PHPRelayIgnoreScriptResponse{}, errors.New("script_key required")
	}
	hours := req.ForHours
	if hours == 0 {
		hours = 24 * 7
	}
	expires := time.Now().Add(time.Duration(hours) * time.Hour)
	by := req.AddedBy
	if by == "" {
		by = "operator"
	}
	if req.Persist {
		if err := c.ignores.AddPersist(scriptKey(req.ScriptKey), expires, by, req.Reason); err != nil {
			return control.PHPRelayIgnoreScriptResponse{}, err
		}
	} else {
		c.ignores.Add(scriptKey(req.ScriptKey), expires, by, req.Reason)
	}
	return control.PHPRelayIgnoreScriptResponse{ExpiresAt: expires}, nil
}

func (c *PHPRelayController) Unignore(_ context.Context, req control.PHPRelayUnignoreRequest) (struct{}, error) {
	if req.ScriptKey == "" {
		return struct{}{}, errors.New("script_key required")
	}
	if req.Persist {
		if err := c.ignores.RemovePersist(scriptKey(req.ScriptKey)); err != nil {
			return struct{}{}, err
		}
	} else {
		c.ignores.Remove(scriptKey(req.ScriptKey))
	}
	return struct{}{}, nil
}

func (c *PHPRelayController) IgnoreList(_ context.Context, _ struct{}) (control.PHPRelayIgnoreListResponse, error) {
	raw := c.ignores.List()
	out := make([]control.PHPRelayIgnoreEntry, 0, len(raw))
	for _, e := range raw {
		out = append(out, control.PHPRelayIgnoreEntry{
			ScriptKey: e.ScriptKey, ExpiresAt: e.ExpiresAt,
			AddedBy: e.AddedBy, Reason: e.Reason,
		})
	}
	return control.PHPRelayIgnoreListResponse{Entries: out}, nil
}

func (c *ControlListener) handlePHPRelayIgnoreScript(argsRaw json.RawMessage) (any, error) {
	if c.phprelay == nil {
		return nil, fmt.Errorf("phprelay controller not wired (Phase O2)")
	}
	var req control.PHPRelayIgnoreScriptRequest
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &req); err != nil {
			return nil, fmt.Errorf("bad args: %w", err)
		}
	}
	return c.phprelay.IgnoreScript(context.Background(), req)
}

func (c *ControlListener) handlePHPRelayUnignore(argsRaw json.RawMessage) (any, error) {
	if c.phprelay == nil {
		return nil, fmt.Errorf("phprelay controller not wired (Phase O2)")
	}
	var req control.PHPRelayUnignoreRequest
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &req); err != nil {
			return nil, fmt.Errorf("bad args: %w", err)
		}
	}
	return c.phprelay.Unignore(context.Background(), req)
}

func (c *ControlListener) handlePHPRelayIgnoreList(argsRaw json.RawMessage) (any, error) {
	if c.phprelay == nil {
		return nil, fmt.Errorf("phprelay controller not wired (Phase O2)")
	}
	_ = argsRaw // no args expected
	return c.phprelay.IgnoreList(context.Background(), struct{}{})
}
