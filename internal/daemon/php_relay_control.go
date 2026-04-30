package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/store"
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
	db           *store.DB
	runner       runner
	eximBin      string
	auditor      auditor
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

func (r *runtimeBool) Set(v bool) { r.mu.Lock(); r.set = true; r.value = v; r.mu.Unlock() }

func (r *runtimeBool) Reset() { r.mu.Lock(); r.set = false; r.mu.Unlock() }

func (r *runtimeBool) Get() (value, set bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.value, r.set
}

// effectiveDryRun resolves precedence: runtime > bbolt > csm.yaml.
// Returns (effective, source) where source identifies the winning input.
func (c *PHPRelayController) effectiveDryRun() (bool, string) {
	if v, set := c.actionDryRun.Get(); set {
		return v, "runtime"
	}
	if c.db != nil {
		if v, ok, err := readDryRunOverride(c.db); err == nil && ok {
			return v, "bbolt"
		}
	}
	if c.eng != nil && c.eng.cfg != nil {
		return c.eng.cfg.PHPRelayDryRunEnabled(), "csm.yaml"
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

func (c *PHPRelayController) DryRun(_ context.Context, req control.PHPRelayDryRunRequest) (control.PHPRelayDryRunResponse, error) {
	switch req.Mode {
	case "on":
		c.actionDryRun.Set(true)
		if req.Persist {
			if err := writeDryRunOverride(c.db, true, "operator"); err != nil {
				return control.PHPRelayDryRunResponse{}, err
			}
		}
	case "off":
		c.actionDryRun.Set(false)
		if req.Persist {
			if err := writeDryRunOverride(c.db, false, "operator"); err != nil {
				return control.PHPRelayDryRunResponse{}, err
			}
		}
	case "reset":
		c.actionDryRun.Reset()
		if req.Persist {
			if err := deleteDryRunOverride(c.db); err != nil {
				return control.PHPRelayDryRunResponse{}, err
			}
		}
	default:
		return control.PHPRelayDryRunResponse{}, errors.New("mode must be on|off|reset")
	}
	eff, src := c.effectiveDryRun()
	return control.PHPRelayDryRunResponse{Effective: eff, Source: src}, nil
}

// DryRunFn returns a closure that evaluates the precedence chain on
// every call. Daemon wiring passes this to newAutoFreezer so that
// `csm phprelay dry-run` actually changes freeze behaviour without
// rebuilding the freezer.
func (c *PHPRelayController) DryRunFn() func() bool {
	return func() bool {
		v, _ := c.effectiveDryRun()
		return v
	}
}

func (c *ControlListener) handlePHPRelayDryRun(argsRaw json.RawMessage) (any, error) {
	if c.phprelay == nil {
		return nil, fmt.Errorf("phprelay controller not wired (Phase O2)")
	}
	var req control.PHPRelayDryRunRequest
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &req); err != nil {
			return nil, fmt.Errorf("bad args: %w", err)
		}
	}
	return c.phprelay.DryRun(context.Background(), req)
}

// Thaw runs `exim -Mt <msg_id>` to release a frozen message back to the
// queue. msgIDPattern validation guards against header-injected garbage
// even though only operators can hit this endpoint. The audit entry is
// written for both success and failure so an operator can later prove
// what was thawed.
//
// req.By is accepted on the wire for forward compatibility (future
// auditEntry.By field) but is not used by the M4 handler.
func (c *PHPRelayController) Thaw(ctx context.Context, req control.PHPRelayThawRequest) (control.PHPRelayThawResponse, error) {
	if !msgIDPattern.MatchString(req.MsgID) {
		return control.PHPRelayThawResponse{}, errors.New("invalid msg_id")
	}
	sub, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stderr, err := c.runner.Run(sub, c.eximBin, []string{"-Mt", req.MsgID})
	c.auditor.Write(auditEntry{
		Ts: time.Now(), MsgID: req.MsgID, Action: "thaw",
		Stderr: stderr,
	})
	if err != nil {
		return control.PHPRelayThawResponse{Stderr: stderr}, err
	}
	return control.PHPRelayThawResponse{Stderr: stderr}, nil
}

func (c *ControlListener) handlePHPRelayThaw(argsRaw json.RawMessage) (any, error) {
	if c.phprelay == nil {
		return nil, fmt.Errorf("phprelay controller not wired (Phase O2)")
	}
	var req control.PHPRelayThawRequest
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &req); err != nil {
			return nil, fmt.Errorf("bad args: %w", err)
		}
	}
	return c.phprelay.Thaw(context.Background(), req)
}
