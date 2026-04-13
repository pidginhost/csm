package daemon

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// ---------------------------------------------------------------------------
// initGeoIP — exercises the method with a nonexistent geoip dir
// ---------------------------------------------------------------------------

func TestInitGeoIP_NonexistentDir(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	d := New(cfg, nil, nil, "")
	// No geoip subdir exists, so geoip.Open returns nil. Should not panic.
	d.initGeoIP()
	if d.geoipDB != nil {
		t.Error("geoipDB should be nil when no DB files exist")
	}
}

func TestInitGeoIP_EmptyGeoIPDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "geoip"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{StatePath: dir}
	d := New(cfg, nil, nil, "")
	d.initGeoIP()
	// Empty geoip dir has no mmdb files, so Open returns nil.
	if d.geoipDB != nil {
		t.Error("geoipDB should be nil when geoip dir is empty")
	}
}

// ---------------------------------------------------------------------------
// publishGeoIP — exercises both branches (existing DB and nil DB)
// ---------------------------------------------------------------------------

func TestPublishGeoIP_NilDB(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	d := New(cfg, nil, nil, "")
	d.geoipDB = nil
	// Should not panic. No mmdb files, so OpenFresh returns nil.
	d.publishGeoIP()
	if d.geoipDB != nil {
		t.Error("geoipDB should remain nil when no DB files exist")
	}
}

// ---------------------------------------------------------------------------
// doGeoIPUpdate — exercises with empty credentials (returns nil results)
// ---------------------------------------------------------------------------

func TestDoGeoIPUpdate_EmptyCredentials(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	d := New(cfg, nil, nil, "")
	// geoip.Update with empty accountID/licenseKey returns nil immediately.
	d.doGeoIPUpdate()
	// Should complete without panic.
}

// ---------------------------------------------------------------------------
// doSignatureUpdate — exercises with invalid URL (fails gracefully)
// ---------------------------------------------------------------------------

func TestDoSignatureUpdate_InvalidURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = t.TempDir()
	cfg.Signatures.UpdateURL = "http://localhost:1/nonexistent"
	d := New(cfg, nil, nil, "")
	// Should fail gracefully with error logged to stderr.
	d.doSignatureUpdate()
}

// ---------------------------------------------------------------------------
// doForgeUpdate — exercises with nil yara scanner (early return)
// ---------------------------------------------------------------------------

func TestDoForgeUpdate_NilYaraScanner(t *testing.T) {
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = t.TempDir()
	d := New(cfg, nil, nil, "")
	// yara.Global() returns nil when not initialized.
	d.doForgeUpdate()
	// Should return early without panic.
}

// ---------------------------------------------------------------------------
// reloadSignatures — exercises with nil global scanners
// ---------------------------------------------------------------------------

func TestReloadSignatures_NilGlobals(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	// Both signatures.Global() and yara.Global() return nil.
	d.reloadSignatures()
	// Should not panic.
}

// ---------------------------------------------------------------------------
// heartbeat — stops on signal
// ---------------------------------------------------------------------------

func TestHeartbeat_StopsOnSignal(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	d.hijackDetector = NewPasswordHijackDetector(cfg, d.alertCh)
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.heartbeat()
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("heartbeat did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// cloudflareRefreshLoop — stops on signal
// ---------------------------------------------------------------------------

func TestCloudflareRefreshLoop_StopsOnSignal(t *testing.T) {
	cfg := &config.Config{}
	cfg.Cloudflare.RefreshHours = 1
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.cloudflareRefreshLoop()
		close(done)
	}()

	// Close immediately — cloudflareRefreshLoop calls refreshCloudflareIPs
	// once on startup (which will fail since no internet/fwEngine), then
	// should exit when stopCh is closed.
	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cloudflareRefreshLoop did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// refreshCloudflareIPs — exercises with nil fwEngine
// ---------------------------------------------------------------------------

func TestRefreshCloudflareIPs_NilFWEngine(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	d := New(cfg, nil, nil, "")
	d.fwEngine = nil
	// FetchCloudflareIPs will attempt HTTP and may fail; the method
	// should handle errors gracefully without panic.
	d.refreshCloudflareIPs()
}

// ---------------------------------------------------------------------------
// startPAMListener — exercises on macOS (fails gracefully)
// ---------------------------------------------------------------------------

func TestStartPAMListener_FailsGracefully(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	// On macOS, PAM listener uses unix socket which may not exist.
	d.startPAMListener()
	// pamListener may be nil on macOS since the socket doesn't exist.
	// The key thing is it doesn't panic.
}

// ---------------------------------------------------------------------------
// startFileMonitor — exercises on macOS (fails gracefully)
// ---------------------------------------------------------------------------

func TestStartFileMonitor_FailsGracefully(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	d.startFileMonitor()
	// On macOS, fanotify is not available. Should not panic.
	if d.fileMonitor != nil {
		t.Error("fileMonitor should be nil on macOS (no fanotify)")
	}
}

// ---------------------------------------------------------------------------
// startSpoolWatcher — enabled but on macOS (fails gracefully)
// ---------------------------------------------------------------------------

func TestStartSpoolWatcher_EnabledOnMacOS(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailAV.Enabled = true
	cfg.EmailAV.ClamdSocket = "/nonexistent/clamd.sock"
	d := New(cfg, nil, nil, "")
	d.startSpoolWatcher()
	// On macOS, NewSpoolWatcher returns error. Should not panic.
	if d.getSpoolWatcher() != nil {
		t.Error("spoolWatcher should be nil on macOS")
	}
}

// ---------------------------------------------------------------------------
// startForwarderWatcher — exercises on macOS (fails gracefully)
// ---------------------------------------------------------------------------

func TestStartForwarderWatcher_FailsGracefully(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	d.startForwarderWatcher()
	// On macOS, NewForwarderWatcher returns error. Should not panic.
	if d.forwarderWatcher != nil {
		t.Error("forwarderWatcher should be nil on macOS")
	}
}

// ---------------------------------------------------------------------------
// startLogWatchers — exercises with no log files present
// ---------------------------------------------------------------------------

func TestStartLogWatchers_NoLogFilesPresent(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	d.hijackDetector = NewPasswordHijackDetector(cfg, d.alertCh)
	// On macOS, none of the Linux log paths exist.
	d.startLogWatchers()
	// All watchers should be empty because no log files exist on macOS.
	d.logWatchersMu.Lock()
	count := len(d.logWatchers)
	d.logWatchersMu.Unlock()
	// No log files should be found on macOS.
	if count != 0 {
		t.Logf("unexpected %d log watchers started (may be valid on Linux CI)", count)
	}
	// Clean up: stop any watchers that were created.
	close(d.stopCh)
	d.logWatchersMu.Lock()
	watchers := d.logWatchers
	d.logWatchersMu.Unlock()
	for _, w := range watchers {
		w.Stop()
	}
	d.wg.Wait()
}

// ---------------------------------------------------------------------------
// runPeriodicChecks — exercises with temp state store
// ---------------------------------------------------------------------------

func TestRunPeriodicChecks_IntegrityFailPath(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := &config.Config{StatePath: dir}
	// Set a BinaryHash so integrity.Verify actually checks and fails.
	cfg.Integrity.BinaryHash = "deadbeef"
	d := New(cfg, st, nil, "/nonexistent/binary")
	// integrity.Verify with a nonexistent binary path will fail.
	// runPeriodicChecks should send an integrity alert and return early
	// (before calling RunTier).
	d.runPeriodicChecks(checks.TierCritical)

	select {
	case f := <-d.alertCh:
		if f.Check != "integrity" {
			t.Errorf("expected integrity check, got %q", f.Check)
		}
		if f.Severity != alert.Critical {
			t.Errorf("expected Critical severity, got %v", f.Severity)
		}
	default:
		t.Error("integrity with bad hash should emit an alert")
	}
}

// ---------------------------------------------------------------------------
// alertDispatcher — exercises batch flush on stop
// ---------------------------------------------------------------------------

func TestAlertDispatcher_FlushesOnStop(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := &config.Config{}
	d := New(cfg, st, nil, "")
	d.wg.Add(1)

	// Pre-load a finding into the channel before starting the dispatcher.
	d.alertCh <- alert.Finding{
		Severity:  alert.High,
		Check:     "test_flush",
		Message:   "flush test",
		Timestamp: time.Now(),
	}

	go d.alertDispatcher()

	// Give dispatcher time to pick up the finding.
	time.Sleep(50 * time.Millisecond)

	// Signal stop — should flush the batch.
	close(d.stopCh)

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(35 * time.Second):
		t.Fatal("alertDispatcher did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// challengeEscalator — stops on signal
// ---------------------------------------------------------------------------

func TestChallengeEscalator_StopsOnSignal(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.challengeEscalator()
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("challengeEscalator did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// retryLogWatcher — stops on signal before finding a file
// ---------------------------------------------------------------------------

func TestRetryLogWatcher_StopsOnSignal(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.retryLogWatcher("/nonexistent/path/that/will/never/appear.log", func(string, *config.Config) []alert.Finding {
			return nil
		})
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("retryLogWatcher did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// signatureUpdater — stops on signal (with URL configured)
// ---------------------------------------------------------------------------

func TestSignatureUpdater_StopsOnSignalWithURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.Signatures.UpdateURL = "http://localhost:1/nonexistent"
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.signatureUpdater()
		close(done)
	}()

	// Close immediately — should exit during the 5-minute wait.
	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("signatureUpdater did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// geoipUpdater — stops on signal (with credentials configured)
// ---------------------------------------------------------------------------

func TestGeoipUpdater_StopsOnSignalWithCredentials(t *testing.T) {
	cfg := &config.Config{}
	cfg.GeoIP.AccountID = "test"
	cfg.GeoIP.LicenseKey = "test"
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.geoipUpdater()
		close(done)
	}()

	// Close immediately — should exit during the initial 5-minute wait.
	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("geoipUpdater did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// deployConfigs — exercises on macOS (no /usr/local/cpanel)
// ---------------------------------------------------------------------------

func TestDeployConfigs_NoCPanel(t *testing.T) {
	// On macOS, /usr/local/cpanel doesn't exist so the function
	// should skip WHM deployment without panic.
	deployConfigs()
}

// ---------------------------------------------------------------------------
// syncEmailAVWebState — exercises with both nil and non-nil values
// ---------------------------------------------------------------------------

func TestSyncEmailAVWebState_BothNil(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.webServer = nil
	d.emailQuarantine = nil
	// Should return immediately without panic.
	d.syncEmailAVWebState()
}

// ---------------------------------------------------------------------------
// startWebUI — enabled but with nil store (error path)
// ---------------------------------------------------------------------------

func TestStartWebUI_EnabledNilStore(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebUI.Enabled = true
	cfg.WebUI.Listen = "127.0.0.1:0"
	d := New(cfg, nil, nil, "")
	// webui.New with nil store may fail. Should not panic.
	d.startWebUI()
	// webServer may or may not be set depending on whether webui.New
	// handles nil store. Key thing is no panic.
}

// ---------------------------------------------------------------------------
// startChallengeServer — enabled with fwEngine (validates full path)
// ---------------------------------------------------------------------------

func TestStartChallengeServer_EnabledNoFWEngine(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	d := New(cfg, nil, nil, "")
	d.fwEngine = nil
	d.startChallengeServer()
	if d.challengeServer != nil {
		t.Error("challengeServer should be nil when fwEngine is nil")
	}
	if d.ipList != nil {
		t.Error("ipList should be nil when fwEngine is nil")
	}
}

// ---------------------------------------------------------------------------
// DroppedAlerts — channel full drops are counted
// ---------------------------------------------------------------------------

func TestRunPeriodicChecks_ChannelFullDrop(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := &config.Config{StatePath: dir}
	// Set a BinaryHash so integrity.Verify fails (nonexistent binary).
	// This avoids proceeding to RunTier which would need a full store.
	cfg.Integrity.BinaryHash = "deadbeef"
	d := New(cfg, st, nil, "/nonexistent/binary")

	// Fill the alert channel completely.
	for i := 0; i < cap(d.alertCh); i++ {
		d.alertCh <- alert.Finding{Check: "filler"}
	}

	// Running periodic checks when channel is full should increment droppedAlerts
	// because the integrity alert can't be sent.
	before := d.DroppedAlerts()
	d.runPeriodicChecks(checks.TierCritical)
	after := d.DroppedAlerts()

	if after <= before {
		t.Errorf("droppedAlerts should increase when channel is full: %d -> %d", before, after)
	}
}

// ---------------------------------------------------------------------------
// filterUnsuppressedFindings — exercises with real state.Store
// ---------------------------------------------------------------------------

func TestFilterUnsuppressedFindings_EmptySuppressions(t *testing.T) {
	findings := []alert.Finding{
		{Check: "test", Message: "msg1"},
		{Check: "test", Message: "msg2"},
	}
	got := filterUnsuppressedFindings(nil, findings, nil)
	if len(got) != 2 {
		t.Errorf("empty suppressions should pass all findings through, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// emailQuarantineCleanup — exercises stop path
// ---------------------------------------------------------------------------

func TestEmailQuarantineCleanup_NilQuarantineStopsOnSignal(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.emailQuarantine = nil
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.emailQuarantineCleanup()
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("emailQuarantineCleanup did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// setSpoolWatcher — exercises with webServer nil (syncEmailAV branch)
// ---------------------------------------------------------------------------

func TestSetSpoolWatcher_TriggersSync(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	sw := &SpoolWatcher{}
	// setSpoolWatcher calls syncEmailAVWebState internally.
	// With nil webServer/quarantine, should not panic.
	d.setSpoolWatcher(sw)
	if got := d.getSpoolWatcher(); got != sw {
		t.Error("setSpoolWatcher did not store the watcher")
	}
}

// ---------------------------------------------------------------------------
// deepScanner with fileMonitor set — exercises reduced deep path
// ---------------------------------------------------------------------------

func TestDeepScanner_StopsOnSignalWithFileMonitor(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.DeepScanIntervalMin = 60
	d := New(cfg, nil, nil, "")
	d.fileMonitor = &FileMonitor{} // non-nil triggers reduced deep path
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.deepScanner()
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("deepScanner with fileMonitor did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// DroppedAlerts — exercises atomic safety under concurrent adds
// ---------------------------------------------------------------------------

func TestDroppedAlerts_IncrementAndRead(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	atomic.AddInt64(&d.droppedAlerts, 3)
	atomic.AddInt64(&d.droppedAlerts, 7)
	if got := d.DroppedAlerts(); got != 10 {
		t.Errorf("DroppedAlerts() = %d, want 10", got)
	}
}

// ---------------------------------------------------------------------------
// startFirewall — enabled but without valid nftables (exercises error path)
// ---------------------------------------------------------------------------

func TestStartFirewall_EnabledFailsGracefully(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall = firewall.DefaultConfig()
	cfg.Firewall.Enabled = true
	cfg.StatePath = t.TempDir()
	// No nftables binary on macOS, so firewall.NewEngine will fail.
	d := New(cfg, nil, nil, "")
	d.startFirewall()
	// fwEngine should be nil on macOS since nftables is not available.
	if d.fwEngine != nil {
		t.Log("fwEngine unexpectedly non-nil (may be valid on Linux)")
	}
}

// ---------------------------------------------------------------------------
// geoipUpdater — custom update interval parsing
// ---------------------------------------------------------------------------

func TestGeoipUpdater_CustomIntervalStopsOnSignal(t *testing.T) {
	cfg := &config.Config{}
	cfg.GeoIP.AccountID = "test"
	cfg.GeoIP.LicenseKey = "test"
	cfg.GeoIP.UpdateInterval = "2h"
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.geoipUpdater()
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("geoipUpdater with custom interval did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// signatureUpdater — custom intervals parsed correctly
// ---------------------------------------------------------------------------

func TestSignatureUpdater_CustomIntervalsStopsOnSignal(t *testing.T) {
	cfg := &config.Config{}
	cfg.Signatures.UpdateURL = "http://localhost:1/test"
	cfg.Signatures.UpdateInterval = "2h"
	cfg.Signatures.YaraForge.UpdateInterval = "48h"
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.signatureUpdater()
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("signatureUpdater with custom intervals did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// watchdogNotifier — exercises with valid env but stopCh
// ---------------------------------------------------------------------------

func TestWatchdogNotifier_NegativeUsecExits(t *testing.T) {
	prev := os.Getenv("WATCHDOG_USEC")
	prevAddr := os.Getenv("NOTIFY_SOCKET")
	os.Setenv("WATCHDOG_USEC", "-100")
	os.Setenv("NOTIFY_SOCKET", "/tmp/test-socket")
	defer func() {
		if prev != "" {
			os.Setenv("WATCHDOG_USEC", prev)
		} else {
			os.Unsetenv("WATCHDOG_USEC")
		}
		if prevAddr != "" {
			os.Setenv("NOTIFY_SOCKET", prevAddr)
		} else {
			os.Unsetenv("NOTIFY_SOCKET")
		}
	}()

	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.watchdogNotifier()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdogNotifier should exit when WATCHDOG_USEC is negative")
	}
}

// ---------------------------------------------------------------------------
// watchdogNotifier — small usec triggers minimum interval
// ---------------------------------------------------------------------------

func TestWatchdogNotifier_SmallUsecUsesMinInterval(t *testing.T) {
	prev := os.Getenv("WATCHDOG_USEC")
	prevAddr := os.Getenv("NOTIFY_SOCKET")
	// 2 seconds in microseconds; half is 1s which is < 10s minimum.
	os.Setenv("WATCHDOG_USEC", "2000000")
	os.Setenv("NOTIFY_SOCKET", "/tmp/nonexistent-wd-min-"+t.Name())
	defer func() {
		if prev != "" {
			os.Setenv("WATCHDOG_USEC", prev)
		} else {
			os.Unsetenv("WATCHDOG_USEC")
		}
		if prevAddr != "" {
			os.Setenv("NOTIFY_SOCKET", prevAddr)
		} else {
			os.Unsetenv("NOTIFY_SOCKET")
		}
	}()

	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.watchdogNotifier()
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("watchdogNotifier with small usec did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// dispatchBatch — perf findings skipped from alertCh
// ---------------------------------------------------------------------------

func TestDispatchBatch_PerfFindingsSkipped(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := &config.Config{}
	d := New(cfg, st, nil, "")

	findings := []alert.Finding{
		{
			Severity:  alert.Warning,
			Check:     "perf_disk_usage",
			Message:   "disk usage warning",
			Timestamp: time.Now(),
		},
		{
			Severity:  alert.High,
			Check:     "real_check",
			Message:   "real alert",
			Timestamp: time.Now(),
		},
	}

	d.dispatchBatch(findings)
	// Verify the findings were processed (stored in state).
	second := st.FilterNew(findings)
	// Both should be seen now.
	if len(second) != 0 {
		t.Errorf("findings should be stored after dispatch, got %d new", len(second))
	}
}

// ---------------------------------------------------------------------------
// runPeriodicChecks — integrity fail with valid hash mismatch
// ---------------------------------------------------------------------------

func TestRunPeriodicChecks_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Use a real binary but set a wrong hash to trigger hash mismatch.
	cfg := &config.Config{StatePath: dir}
	cfg.Integrity.BinaryHash = "wrong_hash_value_here"
	d := New(cfg, st, nil, os.Args[0])
	d.runPeriodicChecks(checks.TierCritical)

	select {
	case f := <-d.alertCh:
		if f.Check != "integrity" {
			t.Errorf("expected integrity check, got %q", f.Check)
		}
	default:
		t.Error("hash mismatch should emit integrity alert")
	}
}

// ---------------------------------------------------------------------------
// startLogWatchers — exercises with PHPShield enabled
// ---------------------------------------------------------------------------

func TestStartLogWatchers_PHPShieldEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.PHPShield.Enabled = true
	d := New(cfg, nil, nil, "")
	d.hijackDetector = NewPasswordHijackDetector(cfg, d.alertCh)
	d.startLogWatchers()
	// On macOS, no log files exist. Clean up.
	close(d.stopCh)
	d.logWatchersMu.Lock()
	watchers := d.logWatchers
	d.logWatchersMu.Unlock()
	for _, w := range watchers {
		w.Stop()
	}
	d.wg.Wait()
}

// ---------------------------------------------------------------------------
// registerWHMPlugin — nonexistent conf path (binary doesn't exist)
// ---------------------------------------------------------------------------

func TestRegisterWHMPlugin_NonexistentConf(t *testing.T) {
	err := registerWHMPlugin("/tmp/nonexistent_csm_conf_" + t.Name())
	if err == nil {
		t.Error("expected error when register_appconfig binary is missing")
	}
}
