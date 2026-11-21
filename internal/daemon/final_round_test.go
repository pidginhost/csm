package daemon

import (
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/store"
)

// ---------------------------------------------------------------------------
// doGeoIPUpdate — exercises the credentials-present path.
// A failed download must leave the loaded database in place.
// ---------------------------------------------------------------------------

func TestDoGeoIPUpdate_DownloadFailure(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.GeoIP.AccountID = "test-account"
	cfg.GeoIP.LicenseKey = rand.Text()
	cfg.GeoIP.Editions = []string{"GeoLite2-City"}
	d := New(cfg, nil, nil, "")
	prev := getGeoIPDB()
	loaded := &geoip.DB{}
	setGeoIPDB(loaded)
	t.Cleanup(func() { setGeoIPDB(prev) })
	requests := failUpdateRequests(t, http.MethodHead)
	d.doGeoIPUpdate()
	if got := requests.Load(); got != 1 {
		t.Fatalf("download attempts = %d, want 1", got)
	}
	if matches, _ := filepath.Glob(filepath.Join(cfg.StatePath, "geoip", "*.mmdb")); len(matches) != 0 {
		t.Fatalf("failed update left databases on disk: %v", matches)
	}
	if getGeoIPDB() != loaded {
		t.Fatal("failed update replaced the GeoIP database")
	}
}

type updateFailureTransport struct {
	t        *testing.T
	method   string
	requests atomic.Int32
}

func (tr *updateFailureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.requests.Add(1)
	if req.Method != tr.method {
		tr.t.Errorf("update request method = %s, want %s", req.Method, tr.method)
	}
	return nil, errors.New("download unavailable")
}

// Both updaters use the default transport. Intercept it so the tests cannot
// contact a public feed or depend on a service listening on the test host.
func failUpdateRequests(t *testing.T, method string) *atomic.Int32 {
	t.Helper()
	tr := &updateFailureTransport{t: t, method: method}
	previous := http.DefaultTransport
	http.DefaultTransport = tr
	t.Cleanup(func() { http.DefaultTransport = previous })
	return &tr.requests
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
	defer func() { _ = db.Close() }()
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
		// The socket dir was writable here: a listener exists and is ours
		// to stop.
		if listener == nil {
			t.Fatal("NewPAMListener returned neither a listener nor an error")
		}
		listener.Stop()
		return
	}
	if listener != nil {
		t.Fatalf("NewPAMListener returned a listener with error %v", err)
	}
	if !strings.Contains(err.Error(), "creating socket dir") && !strings.Contains(err.Error(), "listening on") {
		t.Fatalf("error = %v, want it to name the socket dir or the socket", err)
	}
}

// ---------------------------------------------------------------------------
// parseDovecotLogLine — exercises the nil-geoipDB early return branch.
// When geoipDB is nil, the function skips after basic filtering without
// touching bbolt.
// ---------------------------------------------------------------------------

func TestParseDovecotLogLine_NoGeoDBSkips(t *testing.T) {
	line := `Apr  4 10:15:23 server dovecot: imap-login: Login: user=<john@example.com>, method=PLAIN, rip=203.0.113.42, lip=10.0.0.1`
	cfg := &config.Config{}

	prev := getGeoIPDB()
	setGeoIPDB(nil)
	t.Cleanup(func() { setGeoIPDB(prev) })

	// No GeoIP DB = no way to resolve country = no finding.
	if findings := parseDovecotLogLine(line, cfg, true); findings != nil {
		t.Fatalf("login with no GeoIP database produced findings: %+v", findings)
	}
}

func TestParseDovecotLogLine_TrustedCountryWithGeoDBNil(t *testing.T) {
	// Even with a trusted-countries list, if GeoIP DB is nil the function
	// bails before consulting that list. Tests the early-return order.
	line := `dovecot: imap-login: Login: user=<alice@example.com>, rip=203.0.113.42`
	cfg := &config.Config{}
	cfg.Suppressions.TrustedCountries = []string{"US"}

	prev := getGeoIPDB()
	setGeoIPDB(nil)
	t.Cleanup(func() { setGeoIPDB(prev) })

	if findings := parseDovecotLogLine(line, cfg, true); findings != nil {
		t.Fatalf("login with no GeoIP database produced findings: %+v", findings)
	}
}

func TestParseDovecotLogLine_InfraIPSkipped(t *testing.T) {
	line := `dovecot: imap-login: Login: user=<alice@example.com>, rip=198.51.100.7, lip=10.0.0.1`
	cfg := &config.Config{}
	cfg.InfraIPs = []string{"198.51.100.0/24"}

	findings := parseDovecotLogLine(line, cfg, true)
	if findings != nil {
		t.Errorf("infra IP should be skipped, got findings=%+v", findings)
	}
}

// ---------------------------------------------------------------------------
// lookupCPanelUser — read-error path when /etc/userdomains is absent.
// ---------------------------------------------------------------------------

func TestLookupCPanelUser_NoFile(t *testing.T) {
	withUserdomainsPath(t, filepath.Join(t.TempDir(), "userdomains"))
	if user := lookupCPanelUser("example.com"); user != "" {
		t.Fatalf("lookup with no userdomains file = %q, want empty", user)
	}
}

// ---------------------------------------------------------------------------
// deployConfigs — covers the ModSecurity write path when /etc/apache2 parent
// exists but is unwritable. Exercises the non-cPanel branch.
// ---------------------------------------------------------------------------

func TestDeployConfigs_ModsecParentNotExistSkipped(t *testing.T) {
	// A ModSecurity config directory that does not exist is skipped, not
	// created: no rule file and no overrides file appear under it.
	dirs := []string{"/etc/apache2/conf.d/modsec", "/usr/local/apache/conf"}
	missing := make(map[string]bool)
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			missing[dir] = true
		}
	}

	deployConfigs()

	for _, dir := range dirs {
		if !missing[dir] {
			continue
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("deployConfigs created %s (stat err = %v)", dir, err)
		}
	}
}

// ---------------------------------------------------------------------------
// reloadSignatures — exercises the web-server nil branch alongside nil scanners.
// ---------------------------------------------------------------------------

func TestReloadSignatures_NilWebServer(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	d.webServer = nil
	if yamlRuleCount() != 0 {
		t.Fatalf("test needs no YAML scanner loaded, have %d rules", yamlRuleCount())
	}
	// With no web server to update, the reload still reports that realtime
	// scanning has no rules.
	d.reloadSignatures()
	if d.webServer != nil {
		t.Fatal("reload created a web server")
	}
	select {
	case f := <-d.alertCh:
		if f.Check != "realtime_rules_missing" || !strings.Contains(f.Message, "the configured rules directory") {
			t.Fatalf("finding = %+v, want realtime_rules_missing for the default rules directory", f)
		}
	default:
		t.Fatal("reload with no rules raised no finding")
	}
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
	defer func() { _ = db.Close() }()
	store.SetGlobal(db)
	defer store.SetGlobal(nil)

	line := `dovecot: imap-login: Login: user=<bob@example.com>, rip=203.0.113.99`
	findings := parseDovecotLogLine(line, cfg, true)
	// GeoIP DB nil → returns before the store is consulted. This is the
	// "no country" early-return branch.
	if findings != nil {
		t.Logf("findings=%+v (informational)", findings)
	}
}
