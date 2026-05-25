package daemon

import (
	"context"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/firewall/rollback"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/integrity"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/updatecheck"
)

// Hostname implements health.Provider.
func (d *Daemon) Hostname() string {
	cfg := d.currentCfg()
	if cfg == nil {
		return ""
	}
	return cfg.Hostname
}

// StartedAt implements health.Provider.
func (d *Daemon) StartedAt() time.Time {
	return d.startTime
}

// LatestScan implements health.Provider.
func (d *Daemon) LatestScan() time.Time {
	if d.store == nil {
		return time.Time{}
	}
	return d.store.LatestScanTime()
}

// BaselineAt implements health.Provider. Returns the persisted first-start
// timestamp recorded by EnsureBaseline on the daemon's first successful
// boot against this state directory. Reinstalls and upgrades preserve
// the original value.
func (d *Daemon) BaselineAt() time.Time {
	if d.store == nil {
		return time.Time{}
	}
	return d.store.BaselineAt()
}

// StoreHealthy implements health.Provider.
func (d *Daemon) StoreHealthy() bool {
	s := store.Global()
	if s == nil {
		return false
	}
	return s.IsHealthy()
}

// StoreSizeMB implements health.Provider.
func (d *Daemon) StoreSizeMB() float64 {
	s := store.Global()
	if s == nil {
		return 0
	}
	return float64(s.SizeBytes()) / (1024 * 1024)
}

// SeverityCounts implements health.Provider.
// Buckets the latest findings by severity name.
func (d *Daemon) SeverityCounts() map[string]int {
	out := map[string]int{"critical": 0, "high": 0, "warning": 0}
	if d.store == nil {
		return out
	}
	for _, f := range d.store.LatestFindings() {
		switch f.Severity {
		case alert.Critical:
			out["critical"]++
		case alert.High:
			out["high"]++
		default:
			out["warning"]++
		}
	}
	return out
}

// BlocklistSize implements health.Provider.
func (d *Daemon) BlocklistSize() int {
	s := store.Global()
	if s == nil {
		return 0
	}
	return len(s.LoadFirewallState().Blocked)
}

// IncidentsOpen implements health.Provider. Returns the count of
// open + contained incidents in the correlator. Falls back to 0 if
// the correlator has not been constructed yet (e.g. very early
// startup or shutdown).
func (d *Daemon) IncidentsOpen() int {
	if incidentCorrelator == nil {
		return 0
	}
	return incidentCorrelator.OpenCount()
}

// BPFEnforcementActive implements health.Provider. Reports the
// configured enforcement state. Phase 4 of the BPF Incident Response
// Roadmap. Reads the live config via Daemon.currentCfg(); falls back
// to false if config is nil (very early startup).
func (d *Daemon) BPFEnforcementActive() bool {
	cfg := d.currentCfg()
	if cfg == nil {
		return false
	}
	return cfg.BPFEnforcement.Enabled &&
		cfg.BPFEnforcement.DirectSMTPEgress &&
		bpf.ActiveKind("connection_tracker") == bpf.BackendBPF
}

// HistoryCount implements health.Provider.
func (d *Daemon) HistoryCount() int {
	s := store.Global()
	if s == nil {
		return 0
	}
	return s.HistoryCount()
}

// ConfigHash implements health.Provider.
func (d *Daemon) ConfigHash() string {
	cfg := d.currentCfg()
	if cfg == nil {
		return ""
	}
	return cfg.Integrity.ConfigHash
}

// BinaryHash implements health.Provider.
// Computes the hash on first call via the known binary path; returns empty on error.
func (d *Daemon) BinaryHash() string {
	if d.binaryPath == "" {
		return ""
	}
	h, err := integrity.HashFile(d.binaryPath)
	if err != nil {
		return ""
	}
	return h
}

// DryRunBlocksCount implements health.Provider.
// Returns the number of firewall blocks that were intercepted by dry_run.
func (d *Daemon) DryRunBlocksCount() int {
	s := store.Global()
	if s == nil {
		return 0
	}
	return s.DryRunBlocksCount()
}

// AutomationStatus implements health.Provider.
func (d *Daemon) AutomationStatus() health.AutomationStatus {
	cfg := d.currentCfg()
	out := health.AutomationStatus{
		DryRunBlocks: d.DryRunBlocksCount(),
		LastAction:   d.lastAutomationAction(),
	}
	if cfg != nil {
		out.AutoResponseEnabled = cfg.AutoResponse.Enabled
		out.AutoResponseBlockIPs = cfg.AutoResponse.BlockIPs
		out.AutoResponseDryRun = cfg.AutoResponseDryRunEnabled()
		out.ChallengeEnabled = cfg.Challenge.Enabled
		out.ChallengePortGateEnabled = cfg.Challenge.PortGate.Enabled
	}
	if d.ipList != nil {
		out.ChallengePending = d.ipList.Count()
	}
	out.ChallengePortGateActive = d.challengeGate != nil
	if mgr := rollback.Global(); mgr != nil {
		st := mgr.Status()
		out.FirewallRollbackPending = st.Pending
		out.FirewallRollbackSecondsRemain = st.SecondsRemaining
	}
	return out
}

func (d *Daemon) lastAutomationAction() *health.AutomationAction {
	if d.store == nil {
		return nil
	}
	d.automationActionMu.Lock()
	defer d.automationActionMu.Unlock()
	if !d.automationActionCached.IsZero() && time.Since(d.automationActionCached) < lastAutomationActionTTL {
		return d.automationActionCache
	}
	d.automationActionCache = d.computeLastAutomationAction()
	d.automationActionCached = time.Now()
	return d.automationActionCache
}

func (d *Daemon) computeLastAutomationAction() *health.AutomationAction {
	var (
		best alert.Finding
		ok   bool
	)
	consider := func(findings []alert.Finding) {
		for _, f := range findings {
			if !isAutomationActionCheck(f.Check) {
				continue
			}
			if !ok || f.Timestamp.After(best.Timestamp) {
				best = f
				ok = true
			}
		}
	}
	consider(d.store.LatestFindings())
	if history, _ := d.store.ReadHistory(100, 0); len(history) > 0 {
		consider(history)
	}
	if !ok {
		return nil
	}
	return &health.AutomationAction{
		Check:     best.Check,
		Message:   best.Message,
		Timestamp: best.Timestamp,
	}
}

func isAutomationActionCheck(check string) bool {
	switch check {
	case "auto_block", "auto_response", "challenge_route":
		return true
	}
	return strings.HasPrefix(check, "email_php_relay_action_")
}

// UpdateInfo implements health.Provider. Returns the latest cached
// release-check result, or zero value if the checker was disabled
// or has not completed its first poll yet.
func (d *Daemon) UpdateInfo() health.UpdateInfo {
	if d.updateChecker == nil {
		return health.UpdateInfo{}
	}
	info := d.updateChecker.Latest()
	return health.UpdateInfo{
		LatestVersion: info.LatestVersion,
		Available:     info.Available,
		Source:        info.Source,
		CheckedAt:     info.CheckedAt,
		Err:           info.Err,
	}
}

// startUpdateChecker wires the updatecheck.Checker. No-op when
// updates.check_enabled is false (operator opt-out, e.g. air-gapped
// deployments) or when the running binary is "dev" (still useful but
// the banner will always show).
func (d *Daemon) startUpdateChecker() {
	cfg := d.cfg
	if cfg == nil || !cfg.UpdatesCheckEnabled() {
		return
	}

	interval := cfg.UpdatesInterval()

	pkgProbe := selectPackageProbe(cfg.UpdatesPackageName())

	d.updateChecker = updatecheck.New(updatecheck.Options{
		CurrentVersion: d.version,
		Interval:       interval,
		GitHubAPIURL:   cfg.Updates.GitHubAPIURL,
		PackageProbe:   pkgProbe,
		LogErr: func(source string, err error) {
			csmlog.Debug("update check probe failed", "source", source, "err", err)
		},
	})

	d.wg.Add(1)
	obs.Go("update-checker", func() {
		defer d.wg.Done()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { <-d.stopCh; cancel() }()
		d.updateChecker.Run(ctx)
	})
}

// selectPackageProbe returns an apt or dnf probe based on the
// detected OS family, or nil when the host runs neither (binary
// installs, source builds, etc.).
func selectPackageProbe(packageName string) updatecheck.PackageProbe {
	info := platform.Detect()
	switch {
	case info.IsDebianFamily():
		return updatecheck.AptProbe(packageName)
	case info.IsRHELFamily():
		return updatecheck.DnfProbe(packageName)
	default:
		return nil
	}
}

// compile-time check: Daemon satisfies health.Provider.
var _ health.Provider = (*Daemon)(nil)
