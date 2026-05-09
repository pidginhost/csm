// Package rollback implements the firewall settings tentative-apply
// workflow: a save with a deadline that auto-reverts unless the operator
// confirms before the timer expires. The manager survives daemon restarts
// (state is persisted in bbolt) so that the apply itself can take down the
// daemon for a config reload without losing the rollback intent.
package rollback

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/store"
)

// MinTimeout and MaxTimeout bound the operator-supplied window. The lower
// bound exists so a misclick cannot leave the operator one second to react;
// the upper bound caps how long a botched apply can sit on disk before
// auto-recovery kicks in.
const (
	MinTimeout     = 1 * time.Minute
	MaxTimeout     = 30 * time.Minute
	DefaultTimeout = 5 * time.Minute
)

// Restarter performs a daemon restart. Production wires this to a
// systemctl exec; tests substitute a fake.
type Restarter func(ctx context.Context) error

// Status describes the current pending rollback for status APIs and the
// Web UI banner. AppliedAt and ExpiresAt are UTC; SecondsRemaining is a
// derived hint computed at call time.
type Status struct {
	Pending          bool      `json:"pending"`
	AppliedAt        time.Time `json:"applied_at,omitempty"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
	SecondsRemaining int64     `json:"seconds_remaining,omitempty"`
	AppliedBy        string    `json:"applied_by,omitempty"`
	PrevHash         string    `json:"prev_hash,omitempty"`
	NewHash          string    `json:"new_hash,omitempty"`
}

// Manager owns the active timer and serialises Apply/Confirm/Revert/Recover
// against each other. Storage and restart are injected so the manager can be
// driven in tests without a real bbolt or systemctl.
type Manager struct {
	mu         sync.Mutex
	db         *store.DB
	configPath string
	restart    Restarter
	now        func() time.Time
	timer      *time.Timer
}

// Process-wide singleton. The daemon installs one Manager at startup; the
// Web UI handlers and the control-socket commands look it up by calling
// Global so they do not need to thread the manager through every layer.
var (
	globalMu sync.Mutex
	global   *Manager
)

// SetGlobal installs the process-wide manager. Safe to call from
// daemon startup; subsequent SetGlobal calls overwrite.
func SetGlobal(m *Manager) {
	globalMu.Lock()
	global = m
	globalMu.Unlock()
}

// Global returns the installed manager or nil when none has been set
// (e.g. inside CLI commands that load config but never start the
// daemon). Callers must nil-check.
func Global() *Manager {
	globalMu.Lock()
	defer globalMu.Unlock()
	return global
}

// NewManager wires a manager. Use SystemctlRestart for the production
// restart path. now defaults to time.Now when nil.
func NewManager(db *store.DB, configPath string, restart Restarter, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{
		db:         db,
		configPath: configPath,
		restart:    restart,
		now:        now,
	}
}

// SystemctlRestart issues `systemctl restart csm.service`. The context
// timeout caps how long we wait for systemctl itself; the daemon restart
// it triggers is asynchronous from systemctl's perspective.
func SystemctlRestart(ctx context.Context) error {
	// #nosec G204 -- fixed argv, no operator input interpolated.
	out, err := exec.CommandContext(ctx, "systemctl", "restart", "csm.service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart csm: %w (%s)", err, string(out))
	}
	return nil
}

// HashYAML returns the sha256 hex digest of yaml bytes. Used so the
// Web UI and CLI can show operators the before/after hash without the
// full file contents.
func HashYAML(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// clampTimeout returns a timeout within [MinTimeout, MaxTimeout]; it
// substitutes DefaultTimeout for zero so callers can pass 0 to mean
// "use the default."
func clampTimeout(d time.Duration) time.Duration {
	if d == 0 {
		return DefaultTimeout
	}
	if d < MinTimeout {
		return MinTimeout
	}
	if d > MaxTimeout {
		return MaxTimeout
	}
	return d
}

// Apply records prevYAML as the snapshot to restore on expiry, computes
// the expiry deadline, and persists the rollback entry. The caller is
// responsible for writing newYAML to disk and triggering the restart;
// this method only stages the rollback intent so it survives the
// daemon restart that the apply requires.
//
// applyBy is logged with the rollback record (e.g. token name or "cli")
// so audits can trace the source.
func (m *Manager) Apply(prevYAML, newYAML []byte, timeout time.Duration, applyBy string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.db.GetFirewallRollback(); ok {
		return statusFromRecord(existing, m.now()), fmt.Errorf("rollback already pending; confirm or revert first")
	}

	timeout = clampTimeout(timeout)
	now := m.now().UTC()
	rb := store.FirewallRollback{
		PrevYAML:  prevYAML,
		PrevHash:  HashYAML(prevYAML),
		NewHash:   HashYAML(newYAML),
		AppliedAt: now,
		ExpiresAt: now.Add(timeout),
		AppliedBy: applyBy,
	}
	if err := m.db.SaveFirewallRollback(rb); err != nil {
		return Status{}, fmt.Errorf("persist rollback: %w", err)
	}

	return statusFromRecord(rb, m.now()), nil
}

// Confirm drops the pending rollback. The new config stays on disk;
// no daemon restart is required. Idempotent: confirming with no
// pending entry is a no-op.
func (m *Manager) Confirm() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	return m.db.ClearFirewallRollback()
}

// Revert restores the snapshot to disk and triggers a daemon restart.
// Returns an error if there is no pending rollback so callers can
// surface a clean "nothing to revert" message instead of silently
// succeeding.
func (m *Manager) Revert(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rb, ok := m.db.GetFirewallRollback()
	if !ok {
		return fmt.Errorf("no pending rollback")
	}
	return m.applyRevertLocked(ctx, rb)
}

// RecoverOnStartup is called once during daemon startup. If a pending
// rollback exists, the manager either fires the revert immediately
// (timer already expired while the daemon was down) or rearms a
// time.AfterFunc for the remaining window.
//
// The bool return is true when an immediate revert was performed so
// the caller can decide whether to bail out of further startup work
// while the restart it triggers takes effect.
func (m *Manager) RecoverOnStartup(ctx context.Context) (reverted bool, err error) {
	m.mu.Lock()
	rb, ok := m.db.GetFirewallRollback()
	if !ok {
		m.mu.Unlock()
		return false, nil
	}
	now := m.now()
	if !now.Before(rb.ExpiresAt) {
		err := m.applyRevertLocked(ctx, rb)
		m.mu.Unlock()
		return true, err
	}
	remaining := rb.ExpiresAt.Sub(now)
	m.armTimerLocked(remaining)
	m.mu.Unlock()
	return false, nil
}

// Status reports the pending rollback for /api/v1/.../rollback and
// the CLI status command. Pending=false means "nothing in flight".
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()

	rb, ok := m.db.GetFirewallRollback()
	if !ok {
		return Status{}
	}
	return statusFromRecord(rb, m.now())
}

func (m *Manager) armTimerLocked(d time.Duration) {
	if m.timer != nil {
		m.timer.Stop()
	}
	m.timer = time.AfterFunc(d, func() {
		// Build a fresh context so the AfterFunc goroutine has a
		// usable deadline; the original ctx from RecoverOnStartup
		// would have been cancelled by the time this fires.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = m.timerExpired(ctx)
	})
}

func (m *Manager) timerExpired(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rb, ok := m.db.GetFirewallRollback()
	if !ok {
		return nil
	}
	return m.applyRevertLocked(ctx, rb)
}

// applyRevertLocked restores the snapshot bytes to the config path,
// clears the pending record, and triggers a daemon restart. Caller
// must hold m.mu.
func (m *Manager) applyRevertLocked(ctx context.Context, rb store.FirewallRollback) error {
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	if len(rb.PrevYAML) == 0 {
		return fmt.Errorf("rollback record has empty prev_yaml; cannot restore")
	}
	if err := integrity.WriteConfigBytesAtomic(m.configPath, rb.PrevYAML); err != nil {
		return fmt.Errorf("restore previous config: %w", err)
	}
	if err := m.db.ClearFirewallRollback(); err != nil {
		// The disk file is restored; an orphan bbolt record would
		// re-trigger revert on next startup, so log and continue
		// rather than aborting the restart.
		fmt.Fprintf(os.Stderr, "rollback: clear store after revert: %v\n", err)
	}
	if m.restart != nil {
		if err := m.restart(ctx); err != nil {
			return fmt.Errorf("trigger restart after revert: %w", err)
		}
	}
	return nil
}

func statusFromRecord(rb store.FirewallRollback, now time.Time) Status {
	remaining := int64(rb.ExpiresAt.Sub(now).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	return Status{
		Pending:          true,
		AppliedAt:        rb.AppliedAt,
		ExpiresAt:        rb.ExpiresAt,
		SecondsRemaining: remaining,
		AppliedBy:        rb.AppliedBy,
		PrevHash:         rb.PrevHash,
		NewHash:          rb.NewHash,
	}
}
