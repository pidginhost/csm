package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
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
