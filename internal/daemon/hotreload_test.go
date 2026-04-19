package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/metrics"
)

// seedConfigAtPath writes cfg to path and re-signs integrity.config_hash
// so that a subsequent config.Load + integrity.Verify would pass. The
// helper drives the same two-pass save that `csm rehash` runs in
// production, and it fills in the minimum fields config.Validate
// demands (one alert method) so reload tests exercise the reload
// logic itself and do not trip the validator on a skeleton config.
func seedConfigAtPath(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	if cfg.Hostname == "" {
		cfg.Hostname = "test.example.com"
	}
	if !cfg.Alerts.Email.Enabled && !cfg.Alerts.Webhook.Enabled {
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.To = []string{"ops@example.com"}
		cfg.Alerts.Email.From = "csm@example.com"
		cfg.Alerts.Email.SMTP = "localhost:25"
	}
	cfg.ConfigFile = path
	cfg.Integrity.ConfigHash = ""
	if err := config.Save(cfg); err != nil {
		t.Fatalf("config.Save (pre-hash): %v", err)
	}
	h, err := integrity.HashConfigStable(path)
	if err != nil {
		t.Fatalf("HashConfigStable: %v", err)
	}
	cfg.Integrity.ConfigHash = h
	if err := config.Save(cfg); err != nil {
		t.Fatalf("config.Save (post-hash): %v", err)
	}
}

// newDaemonForReloadTest builds a minimal Daemon suitable for calling
// reloadConfig directly. The alert channel is buffered so findings
// emitted during reload can be read back without a live dispatcher.
func newDaemonForReloadTest(t *testing.T, cfg *config.Config) *Daemon {
	t.Helper()
	d := &Daemon{
		cfg:     cfg,
		alertCh: make(chan alert.Finding, 8),
	}
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(nil) })
	return d
}

func drainAlert(t *testing.T, d *Daemon, within time.Duration) alert.Finding {
	t.Helper()
	select {
	case f := <-d.alertCh:
		return f
	case <-time.After(within):
		t.Fatalf("expected a finding on alertCh within %s", within)
	}
	return alert.Finding{}
}

func TestReloadConfigSafeFieldUpdatesActive(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")

	orig := &config.Config{}
	orig.Hostname = "host-a"
	orig.Thresholds.MailQueueWarn = 100
	seedConfigAtPath(t, cfgPath, orig)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load seeded config: %v", err)
	}
	d := newDaemonForReloadTest(t, loaded)

	// Edit on disk: bump the threshold. Thresholds is tagged
	// hotreload:"safe" so the reload must accept it.
	edited := &config.Config{}
	edited.Hostname = "host-a"
	edited.Thresholds.MailQueueWarn = 250
	// Preserve integrity from the loaded config for the edit pass;
	// reloadConfig will re-sign anyway, but config.Load happens
	// before re-sign and we need the file to pass loading.
	edited.Integrity = loaded.Integrity
	seedConfigAtPath(t, cfgPath, edited)

	d.reloadConfig()

	got := config.Active()
	if got == nil {
		t.Fatal("Active returned nil after reload")
	}
	if got.Thresholds.MailQueueWarn != 250 {
		t.Errorf("threshold not reloaded: got %d want 250", got.Thresholds.MailQueueWarn)
	}
	// No finding should be emitted on a successful safe reload.
	select {
	case f := <-d.alertCh:
		t.Errorf("unexpected finding on safe reload: %+v", f)
	default:
	}

	// The on-disk file must have a fresh ConfigHash that matches
	// the stable-form hash of its current bytes.
	h, err := integrity.HashConfigStable(cfgPath)
	if err != nil {
		t.Fatalf("hash after reload: %v", err)
	}
	if got.Integrity.ConfigHash != h {
		t.Errorf("integrity not re-signed: active has %q, file hashes to %q",
			got.Integrity.ConfigHash, h)
	}
}

func TestReloadConfigRestartFieldEmitsWarning(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")

	orig := &config.Config{}
	orig.Hostname = "host-a"
	seedConfigAtPath(t, cfgPath, orig)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := newDaemonForReloadTest(t, loaded)

	// Hostname has no hotreload tag -> treated as restart-required.
	edited := &config.Config{}
	edited.Hostname = "host-b"
	edited.Integrity = loaded.Integrity
	seedConfigAtPath(t, cfgPath, edited)

	d.reloadConfig()

	got := config.Active()
	if got == nil || got.Hostname != "host-a" {
		t.Errorf("live hostname should still be host-a, got %q", getHostname(got))
	}

	f := drainAlert(t, d, time.Second)
	if f.Severity != alert.Warning {
		t.Errorf("severity: got %v want Warning", f.Severity)
	}
	if f.Check != "config_reload_restart_required" {
		t.Errorf("check: got %q want config_reload_restart_required", f.Check)
	}
	if !strings.Contains(f.Message, "hostname") {
		t.Errorf("message must name the offending field: %q", f.Message)
	}
}

func TestReloadConfigBadYAMLEmitsCritical(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")

	orig := &config.Config{}
	orig.Hostname = "host-a"
	seedConfigAtPath(t, cfgPath, orig)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := newDaemonForReloadTest(t, loaded)

	// Corrupt the file on disk.
	if err := os.WriteFile(cfgPath, []byte("not: valid: yaml:\n  :\n"), 0o600); err != nil {
		t.Fatalf("corrupt write: %v", err)
	}

	d.reloadConfig()

	if got := config.Active(); got == nil || got.Hostname != "host-a" {
		t.Errorf("live hostname should still be host-a, got %q", getHostname(got))
	}

	f := drainAlert(t, d, time.Second)
	if f.Severity != alert.Critical {
		t.Errorf("severity: got %v want Critical", f.Severity)
	}
	if f.Check != "config_reload_error" {
		t.Errorf("check: got %q want config_reload_error", f.Check)
	}
}

// TestReloadConfigIntegrityVerifyPassesAfterReload is a regression
// guard. Pre-fix, runPeriodicChecks called
// integrity.Verify(d.binaryPath, d.cfg) against the startup config,
// whose stored ConfigHash went stale the moment a SIGHUP reload
// re-signed the on-disk file. Every periodic tick then fired a
// spurious Critical tamper alert. Verify now runs against
// d.currentCfg(), so the stored hash stays in sync with whatever
// the last successful reload wrote to disk.
func TestReloadConfigIntegrityVerifyPassesAfterReload(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")

	// Stand-in binary: any stable file Verify can hash. Keep it
	// separate from cfgPath so rewrites to the config do not change
	// the binary hash mid-test.
	binPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binPath, []byte("stand-in"), 0o600); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	bh, err := integrity.HashFile(binPath)
	if err != nil {
		t.Fatalf("hash bin: %v", err)
	}

	orig := &config.Config{}
	orig.Thresholds.MailQueueWarn = 100
	orig.Integrity.BinaryHash = bh
	seedConfigAtPath(t, cfgPath, orig)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := newDaemonForReloadTest(t, loaded)
	d.binaryPath = binPath

	// Baseline: Verify passes against the freshly-seeded config.
	if err := integrity.Verify(d.binaryPath, d.currentCfg()); err != nil {
		t.Fatalf("baseline Verify: %v", err)
	}

	// Edit a safe field on disk and reload.
	edited := &config.Config{}
	edited.Thresholds.MailQueueWarn = 777
	edited.Integrity = loaded.Integrity
	seedConfigAtPath(t, cfgPath, edited)
	d.reloadConfig()

	// Post-reload: Verify must still pass. Using d.cfg here would
	// fail (stale ConfigHash); the fix routes through
	// d.currentCfg().
	if err := integrity.Verify(d.binaryPath, d.currentCfg()); err != nil {
		t.Errorf("post-reload Verify via d.currentCfg failed: %v", err)
	}

	// Nail down the bug the fix was made for: Verify against the
	// startup d.cfg MUST fail post-reload, because its stored hash
	// is stale. If that starts passing, something shifted; the
	// regression guard on d.currentCfg loses its meaning.
	if err := integrity.Verify(d.binaryPath, d.cfg); err == nil {
		t.Error("Verify against stale d.cfg should fail after reload; " +
			"fix may have regressed or d.cfg is now being kept in sync")
	}
}

// TestReloadConfigRestartRequiredKeepsIntegrityConsistent is a
// regression guard for the cluster6 smoke test finding on
// 2026-04-19: when reload classified the edit as restart_required
// (a restart-tagged field changed), the on-disk file was left with
// the edited content but the stored integrity.config_hash still
// referred to the pre-edit content. Any daemon restart after that
// would crash-loop on integrity check failure.
//
// The fix re-signs the on-disk file (atomic temp + rename) AND
// updates the live cfg's ConfigHash in memory so periodic
// integrity.Verify(currentCfg) does not see a disk/memory
// divergence. The live policy fields stay on the old values --
// that's the "restart required" part -- but the hash tracks the
// on-disk content.
func TestReloadConfigRestartRequiredKeepsIntegrityConsistent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")
	binPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binPath, []byte("stand-in"), 0o600); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	bh, err := integrity.HashFile(binPath)
	if err != nil {
		t.Fatalf("hash bin: %v", err)
	}

	orig := &config.Config{}
	orig.Hostname = "before.example.com"
	orig.Integrity.BinaryHash = bh
	seedConfigAtPath(t, cfgPath, orig)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := newDaemonForReloadTest(t, loaded)
	d.binaryPath = binPath

	// Baseline: Verify passes (seeded hash matches).
	if verr := integrity.Verify(d.binaryPath, d.currentCfg()); verr != nil {
		t.Fatalf("baseline Verify: %v", verr)
	}

	// Edit a RESTART-tagged field on disk (Hostname). The reload
	// must reject the live swap but re-sign the on-disk file so the
	// operator's eventual `systemctl restart` can start cleanly.
	edited := &config.Config{}
	edited.Hostname = "after.example.com"
	edited.Integrity = loaded.Integrity
	seedConfigAtPath(t, cfgPath, edited)
	d.reloadConfig()

	// The live cfg's Hostname must still be "before" (restart_required).
	if got := config.Active(); got == nil || got.Hostname != "before.example.com" {
		t.Errorf("live Hostname should stay on old value, got %q", hostnameOf(got))
	}

	// Verify against the live config must still pass -- the stored
	// ConfigHash in memory was updated to match the new on-disk
	// content. Without this fix, the integrity check would fire a
	// spurious tamper alert every periodic tick.
	if verr := integrity.Verify(d.binaryPath, d.currentCfg()); verr != nil {
		t.Errorf("post-restart-required Verify failed: %v", verr)
	}

	// A direct load-and-verify must also pass -- the on-disk file is
	// internally consistent for the next startup.
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload from disk: %v", err)
	}
	if err := integrity.Verify(d.binaryPath, reloaded); err != nil {
		t.Errorf("on-disk integrity Verify failed: %v", err)
	}

	// And the reloaded cfg should carry the EDITED hostname
	// (because the file on disk has it), not the pre-edit value.
	// The reload rejected the live swap, but the edit still sits on
	// disk for the next restart.
	if reloaded.Hostname != "after.example.com" {
		t.Errorf("on-disk hostname: got %q want after.example.com", reloaded.Hostname)
	}

	// Drain the restart_required finding.
	select {
	case <-d.alertCh:
	default:
		t.Error("expected a restart_required finding on the alert channel")
	}
}

func hostnameOf(c *config.Config) string {
	if c == nil {
		return "<nil>"
	}
	return c.Hostname
}

// TestReloadConfigMetricCountsOutcomes exercises every reloadConfig
// outcome and asserts the csm_config_reloads_total{result=X} counter
// increments accordingly. A later refactor that silently drops one of
// the recordReloadResult calls fails this test instead of leaving
// operators without metrics on a single outcome class.
func TestReloadConfigMetricCountsOutcomes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")

	orig := &config.Config{}
	orig.Thresholds.MailQueueWarn = 100
	seedConfigAtPath(t, cfgPath, orig)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := newDaemonForReloadTest(t, loaded)

	before := scrapeReloadResults(t)

	// 1. noop: reload without editing the file.
	d.reloadConfig()

	// 2. success: safe threshold edit.
	edited := &config.Config{}
	edited.Thresholds.MailQueueWarn = 200
	edited.Integrity = loaded.Integrity
	seedConfigAtPath(t, cfgPath, edited)
	d.reloadConfig()
	// drain any state-changes from the alert channel
	select {
	case <-d.alertCh:
	default:
	}

	// 3. restart_required: edit a restart-tagged field (hostname).
	reloaded := config.Active()
	edited2 := &config.Config{}
	edited2.Hostname = "different.example.com"
	edited2.Thresholds.MailQueueWarn = 200
	edited2.Integrity = reloaded.Integrity
	seedConfigAtPath(t, cfgPath, edited2)
	d.reloadConfig()
	// drain the restart_required finding
	select {
	case <-d.alertCh:
	default:
	}

	// 4. error: corrupt the file.
	if err := os.WriteFile(cfgPath, []byte("bad: :\n  : yaml\n"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	d.reloadConfig()
	select {
	case <-d.alertCh:
	default:
	}

	after := scrapeReloadResults(t)
	for _, want := range []struct {
		result string
		delta  float64
	}{
		{"noop", 1},
		{"success", 1},
		{"restart_required", 1},
		{"error", 1},
	} {
		got := after[want.result] - before[want.result]
		if got != want.delta {
			t.Errorf("result=%s delta: got %g want %g", want.result, got, want.delta)
		}
	}
}

func scrapeReloadResults(t *testing.T) map[string]float64 {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("scrape: %v", err)
	}
	out := map[string]float64{"success": 0, "error": 0, "restart_required": 0, "noop": 0}
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.HasPrefix(line, `csm_config_reloads_total{result=`) {
			continue
		}
		open := strings.Index(line, `"`)
		if open < 0 {
			continue
		}
		rest := line[open+1:]
		end := strings.Index(rest, `"`)
		if end < 0 {
			continue
		}
		result := rest[:end]
		after := strings.TrimSpace(strings.TrimPrefix(rest[end+1:], "}"))
		if after == "" {
			continue
		}
		v, err := strconv.ParseFloat(after, 64)
		if err != nil {
			continue
		}
		out[result] = v
	}
	return out
}

func TestReloadConfigNoChangeIsSilent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")

	orig := &config.Config{}
	orig.Hostname = "host-a"
	seedConfigAtPath(t, cfgPath, orig)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := newDaemonForReloadTest(t, loaded)

	d.reloadConfig()

	select {
	case f := <-d.alertCh:
		t.Errorf("no change should produce no finding: %+v", f)
	default:
	}
}

func getHostname(c *config.Config) string {
	if c == nil {
		return "<nil>"
	}
	return c.Hostname
}
