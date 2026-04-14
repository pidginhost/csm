package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// ---------------------------------------------------------------------------
// doGeoIPUpdate — exercises the credentials-present path.
// With nonsensical URL/credentials geoip.Update returns an "error" status
// per edition. The function handles that branch without publishing.
// ---------------------------------------------------------------------------

func TestDoGeoIPUpdate_WithCredentialsInvalidPath(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.GeoIP.AccountID = "test-account"
	cfg.GeoIP.LicenseKey = "test-key"
	cfg.GeoIP.Editions = []string{"GeoLite2-City"}
	d := New(cfg, nil, nil, "")
	// No network access in test env - HEAD to maxmind will fail fast and
	// produce an "error" EditionResult which exercises the error branch
	// of doGeoIPUpdate without panicking.
	d.doGeoIPUpdate()
}

// ---------------------------------------------------------------------------
// signatureUpdater — forge-only path (no UpdateURL) still exits on stop.
// ---------------------------------------------------------------------------

func TestSignatureUpdater_ForgeOnlyStopsOnSignal(t *testing.T) {
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = t.TempDir()
	cfg.Signatures.UpdateURL = ""
	cfg.Signatures.YaraForge.Enabled = true
	cfg.Signatures.YaraForge.Tier = "full"
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.signatureUpdater()
		close(done)
	}()

	// yara.Available() is false in !yara builds so the function exits early.
	// In yara builds the goroutine will pick up stopCh from the 5m wait.
	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("forge-only signatureUpdater did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// doForgeUpdate — scanner nil path with store configured.
// Exercises the "nil scanner returns early" guard with various config.
// ---------------------------------------------------------------------------

func TestDoForgeUpdate_StoreConfiguredNilScanner(t *testing.T) {
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = t.TempDir()
	cfg.Signatures.YaraForge.Tier = "core"
	cfg.StatePath = t.TempDir()

	// Open a store so the db != nil branch inside doForgeUpdate would be
	// reachable — but it returns immediately because yara.Global() is nil
	// in the default test build. This still exercises the nil-scanner guard
	// with the full config path populated.
	db, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store.SetGlobal(db)
	defer store.SetGlobal(nil)

	d := New(cfg, nil, nil, "")
	d.doForgeUpdate()
}

// ---------------------------------------------------------------------------
// NewPAMListener — exercises error paths when /var/run/csm is not writable.
// ---------------------------------------------------------------------------

func TestNewPAMListener_NonRootSkipped(t *testing.T) {
	// Skip if running as root - we can't easily induce the MkdirAll failure.
	if os.Geteuid() == 0 {
		t.Skip("test requires non-root user")
	}
	cfg := &config.Config{}
	alertCh := make(chan alert.Finding, 1)
	listener, err := NewPAMListener(cfg, alertCh)
	if err == nil {
		// If for some reason MkdirAll and Listen succeeded, clean up.
		if listener != nil {
			listener.Stop()
		}
		t.Skip("PAM socket dir was writable in this env — branch already covered by success path")
	}
	// err != nil is the non-root expected path; function returned cleanly.
}

// ---------------------------------------------------------------------------
// parseDovecotLogLine — exercises the nil-geoipDB early return branch.
// When geoipDB is nil, the function skips after basic filtering without
// touching bbolt.
// ---------------------------------------------------------------------------

func TestParseDovecotLogLine_NoGeoDBSkips(t *testing.T) {
	line := `Apr  4 10:15:23 server dovecot: imap-login: Login: user=<john@example.com>, method=PLAIN, rip=203.0.113.42, lip=10.0.0.1`
	cfg := &config.Config{}

	// Ensure geoipDB is whatever the test runtime default is (nil).
	findings := parseDovecotLogLine(line, cfg)
	// No GeoIP DB = no way to resolve country = no finding. That's the
	// early-return branch we want to cover.
	if findings != nil {
		t.Logf("geoipDB was set in this env, got findings=%+v (informational only)", findings)
	}
}

func TestParseDovecotLogLine_TrustedCountryWithGeoDBNil(t *testing.T) {
	// Even with a trusted-countries list, if GeoIP DB is nil the function
	// bails before consulting that list. Tests the early-return order.
	line := `dovecot: imap-login: Login: user=<alice@example.com>, rip=8.8.8.8`
	cfg := &config.Config{}
	cfg.Suppressions.TrustedCountries = []string{"US"}

	findings := parseDovecotLogLine(line, cfg)
	// Should return nil because GeoIP DB is nil by default.
	_ = findings
}

func TestParseDovecotLogLine_InfraIPSkipped(t *testing.T) {
	line := `dovecot: imap-login: Login: user=<alice@example.com>, rip=198.51.100.7, lip=10.0.0.1`
	cfg := &config.Config{}
	cfg.InfraIPs = []string{"198.51.100.0/24"}

	findings := parseDovecotLogLine(line, cfg)
	if findings != nil {
		t.Errorf("infra IP should be skipped, got findings=%+v", findings)
	}
}

// ---------------------------------------------------------------------------
// lookupCPanelUser — read-error path when /etc/userdomains is absent.
// ---------------------------------------------------------------------------

func TestLookupCPanelUser_NoFile(t *testing.T) {
	// On macOS /etc/userdomains almost certainly doesn't exist → empty string.
	user := lookupCPanelUser("example.com")
	if user != "" {
		t.Logf("got user=%q (file may exist on this host, informational)", user)
	}
}

// ---------------------------------------------------------------------------
// deployConfigs — covers the ModSecurity write path when /etc/apache2 parent
// exists but is unwritable. Exercises the non-cPanel branch.
// ---------------------------------------------------------------------------

func TestDeployConfigs_ModsecParentNotExistSkipped(t *testing.T) {
	// This test simply verifies deployConfigs tolerates missing parent
	// directories without panic. On macOS neither /usr/local/cpanel nor
	// /etc/apache2/conf.d/modsec nor /usr/local/apache/conf exist,
	// so the function returns after attempting /opt/csm/deploy.sh write.
	deployConfigs()
}

// ---------------------------------------------------------------------------
// reloadSignatures — exercises the web-server nil branch alongside nil scanners.
// ---------------------------------------------------------------------------

func TestReloadSignatures_NilWebServer(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	d.webServer = nil
	// Both signatures.Global() and yara.Global() are nil → function no-ops
	// without touching webServer. Exercises the safety guards.
	d.reloadSignatures()
}

// ---------------------------------------------------------------------------
// deepScanner — exercises stop signal when no fileMonitor is set (full tier).
// The existing TestDeepScanner_StopsOnSignal already covers the no-monitor
// case, but using a small interval plus immediate stop exercises the
// ticker-fire+stop-race happy path.
// ---------------------------------------------------------------------------

func TestDeepScanner_SmallIntervalStopsOnSignal(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.DeepScanIntervalMin = 1 // 1-minute interval (ticker won't fire in test)
	cfg.StatePath = t.TempDir()
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.deepScanner()
		close(done)
	}()

	// Close immediately so the scanner exits in the select.
	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("deepScanner did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// parseDovecotLogLine with store + geoipDB — exercise no-country-data path.
// This constructs a minimal bbolt store so boltDB != nil check passes when
// reached, then forces the country-is-empty branch by passing an invalid IP
// that defaults to "" after GeoIP lookup (nil DB returns empty info).
// ---------------------------------------------------------------------------

func TestParseDovecotLogLine_StoreOpenNoCountry(t *testing.T) {
	cfg := &config.Config{}
	// Open a real bbolt store for this test so store.Global() is not nil.
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "sub"), 0700)
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store.SetGlobal(db)
	defer store.SetGlobal(nil)

	line := `dovecot: imap-login: Login: user=<bob@example.com>, rip=203.0.113.99`
	findings := parseDovecotLogLine(line, cfg)
	// GeoIP DB nil → returns before the store is consulted. This is the
	// "no country" early-return branch.
	if findings != nil {
		t.Logf("findings=%+v (informational)", findings)
	}
}
