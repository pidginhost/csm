package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailav"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/integrity"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/webui"
	"github.com/pidginhost/csm/internal/yara"
)

// Daemon is the main persistent monitoring process.
type Daemon struct {
	cfg        *config.Config
	store      *state.Store
	lock       *state.LockFile
	binaryPath string

	logWatchers      []*LogWatcher
	logWatchersMu    sync.Mutex
	fileMonitor      *FileMonitor
	hijackDetector   *PasswordHijackDetector
	pamListener      *PAMListener
	spoolWatcher     *SpoolWatcher
	spoolWatcherMu   sync.Mutex
	forwarderWatcher *ForwarderWatcher
	emailQuarantine  *emailav.Quarantine
	webServer        *webui.Server
	challengeServer  *challenge.Server
	ipList           *challenge.IPList
	fwEngine         *firewall.Engine
	geoipDB          *geoip.DB
	geoipMu          sync.Mutex // protects geoipDB for publishGeoIP
	version          string
	alertCh          chan alert.Finding
	droppedAlerts    int64 // atomic counter for alert channel backpressure drops
	stopCh           chan struct{}
	wg               sync.WaitGroup
}

// New creates a new daemon instance.
func New(cfg *config.Config, store *state.Store, lock *state.LockFile, binaryPath string) *Daemon {
	return &Daemon{
		cfg:        cfg,
		store:      store,
		lock:       lock,
		binaryPath: binaryPath,
		alertCh:    make(chan alert.Finding, 500),
		stopCh:     make(chan struct{}),
	}
}

// SetVersion sets the application version for display in the web UI.
func (d *Daemon) SetVersion(v string) {
	d.version = v
}

// Run starts the daemon and blocks until stopped.
func (d *Daemon) Run() error {
	// Initialize structured logging from environment (CSM_LOG_FORMAT,
	// CSM_LOG_LEVEL). The default text handler preserves the legacy
	// "[YYYY-MM-DD HH:MM:SS] msg" format so operators mixing csmlog
	// with legacy fmt.Fprintf call sites see a uniform log stream.
	// CSM_LOG_FORMAT=json switches to structured JSON for log shipping.
	csmlog.Init()

	csmlog.Info("CSM daemon starting")

	// Install config-supplied platform overrides BEFORE the first Detect()
	// call so every check sees the merged view. Must happen before any
	// other code calls platform.Detect() in this daemon run.
	platform.SetOverrides(platform.Overrides{
		WebServer:           platform.WebServer(d.cfg.WebServer.Type),
		ApacheConfigDir:     d.cfg.WebServer.ConfigDir,
		AccessLogPaths:      d.cfg.WebServer.AccessLogs,
		ErrorLogPaths:       d.cfg.WebServer.ErrorLogs,
		ModSecAuditLogPaths: d.cfg.WebServer.ModSecAudits,
	})

	// Log detected platform as a structured record. In text mode this
	// comes out as "[ts] platform detected  os=X  panel=Y  ..."; in
	// JSON mode as {"msg":"platform detected","os":"X","panel":"Y",...}.
	pi := platform.Detect()
	csmlog.Info("platform detected",
		"os", orUnknown(string(pi.OS)),
		"os_version", orUnknown(pi.OSVersion),
		"panel", orNone(string(pi.Panel)),
		"webserver", orNone(string(pi.WebServer)),
	)

	// Verify integrity on startup
	if err := integrity.Verify(d.binaryPath, d.cfg); err != nil {
		tamper := alert.Finding{
			Severity:  alert.Critical,
			Check:     "integrity",
			Message:   fmt.Sprintf("BINARY/CONFIG TAMPER DETECTED: %v", err),
			Timestamp: time.Now(),
		}
		_ = alert.Dispatch(d.cfg, []alert.Finding{tamper})
		return fmt.Errorf("integrity check failed: %w", err)
	}

	// Deploy WHM plugin and configs if cPanel is present
	deployConfigs()

	// Initialize signature scanners and threat DB (fast, no I/O scan)
	if yaraScanner := yara.Init(d.cfg.Signatures.RulesDir); yaraScanner != nil {
		fmt.Fprintf(os.Stderr, "[%s] YARA-X scanner active: %d rule file(s)\n", ts(), yaraScanner.RuleCount())
	}
	checks.InitThreatDB(d.cfg.StatePath, d.cfg.Reputation.Whitelist)
	if db := checks.GetThreatDB(); db != nil {
		fmt.Fprintf(os.Stderr, "[%s] Threat DB initialized (%d entries)\n", ts(), db.Count())
	}
	if adb := attackdb.Init(d.cfg.StatePath); adb != nil {
		// Seed from permanent blocklist on first run (when attack DB is empty)
		if adb.TotalIPs() == 0 {
			if n := adb.SeedFromPermanentBlocklist(d.cfg.StatePath); n > 0 {
				fmt.Fprintf(os.Stderr, "[%s] Attack DB seeded %d IPs from permanent blocklist\n", ts(), n)
			}
		}
		fmt.Fprintf(os.Stderr, "[%s] Attack DB initialized (%s)\n", ts(), adb.FormatTopLine())
	}

	// Start firewall engine if enabled
	d.startFirewall()

	// Start challenge server if enabled (gray listing)
	d.startChallengeServer()

	// Start challenge escalation ticker
	if d.ipList != nil {
		d.wg.Add(1)
		go d.challengeEscalator()
	}

	// Create password hijack detector
	d.hijackDetector = NewPasswordHijackDetector(d.cfg, d.alertCh)

	// Start inotify log watchers
	d.startLogWatchers()

	// Start PAM listener for real-time brute-force detection
	d.startPAMListener()

	// Start fanotify file monitor (real-time detection starts immediately)
	d.startFileMonitor()

	// Start email AV spool watcher (separate fanotify for Exim spool).
	// Spool and forwarder watchers are cPanel-only; they watch paths
	// (/var/spool/exim, /etc/valiases) that only exist on cPanel hosts.
	if platform.Detect().IsCPanel() {
		d.startSpoolWatcher()
		d.startForwarderWatcher()
	}

	// Start Web UI server - available immediately, before initial scan
	d.startWebUI()

	// Wire email quarantine to web server (after both start)
	d.syncEmailAVWebState()

	// Initialize GeoIP databases (after webServer so SetGeoIPDB can attach)
	d.initGeoIP()

	// Run initial scan synchronously (before dispatcher starts)
	fmt.Fprintf(os.Stderr, "[%s] Running initial baseline scan...\n", ts())
	initialFindings := checks.RunTier(d.cfg, d.store, checks.TierCritical)

	// Seed the attack database with initial scan findings
	if adb := attackdb.Global(); adb != nil {
		for _, f := range initialFindings {
			adb.RecordFinding(f)
		}
	}

	d.store.AppendHistory(initialFindings)
	newFindings := d.store.FilterNew(initialFindings)
	suppressions := d.store.LoadSuppressions()
	initialAutoResponseFindings := initialFindings
	if len(suppressions) > 0 {
		initialAutoResponseFindings = filterUnsuppressedFindings(d.store, initialFindings, suppressions)
		newFindings = filterUnsuppressedFindings(d.store, newFindings, suppressions)
	}

	// Permission auto-fix runs on ALL findings (not just new) because
	// it's safe/idempotent and should fix baseline findings too.
	permActions, permFixedKeys := checks.AutoFixPermissions(d.cfg, initialAutoResponseFindings)

	// Challenge routing runs on ALL findings unconditionally when enabled.
	challengeActions := checks.ChallengeRouteIPs(d.cfg, initialAutoResponseFindings)

	// Other auto-response only on new findings
	if len(newFindings) > 0 {
		killActions := checks.AutoKillProcesses(d.cfg, newFindings)
		quarantineActions := checks.AutoQuarantineFiles(d.cfg, newFindings)
		blockActions := checks.AutoBlockIPs(d.cfg, initialAutoResponseFindings)
		newFindings = append(newFindings, killActions...)
		newFindings = append(newFindings, quarantineActions...)
		newFindings = append(newFindings, permActions...)
		newFindings = append(newFindings, challengeActions...)
		newFindings = append(newFindings, blockActions...)
		_ = alert.Dispatch(d.cfg, newFindings)
	}

	// Remove auto-fixed findings before storing to UI
	if len(permFixedKeys) > 0 {
		fixedSet := make(map[string]bool, len(permFixedKeys))
		for _, k := range permFixedKeys {
			fixedSet[k] = true
		}
		var filtered []alert.Finding
		for _, f := range initialFindings {
			key := f.Check + ":" + f.Message
			if !fixedSet[key] {
				filtered = append(filtered, f)
			}
		}
		initialFindings = filtered
	}

	d.store.Update(initialFindings)
	// Merge initial scan findings into the existing set. Previous deep scan
	// results (outdated_plugins, wp_core, etc.) persist across restarts until
	// the next deep scan replaces them. ClearLatestFindings is NOT called
	// here - it would wipe deep scan findings that haven't re-run yet.
	d.store.SetLatestFindings(initialFindings)
	csmlog.Info("initial scan complete", "findings", len(initialFindings), "new", len(newFindings))

	// NOW start the alert dispatcher - no more race with initial scan
	d.wg.Add(1)
	go d.alertDispatcher()

	// Start periodic scanners
	d.wg.Add(1)
	go d.criticalScanner()

	d.wg.Add(1)
	go d.deepScanner()

	// Start automatic signature updates
	d.wg.Add(1)
	go d.signatureUpdater()

	d.wg.Add(1)
	go d.geoipUpdater()

	// Start heartbeat
	d.wg.Add(1)
	go d.heartbeat()

	// Start systemd watchdog notifier — independent goroutine with its own
	// ticker so long-running scans don't block the heartbeat.
	d.wg.Add(1)
	go d.watchdogNotifier()

	csmlog.Info("CSM daemon running")

	// Wait for signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			fmt.Fprintf(os.Stderr, "[%s] SIGHUP received - reloading rules\n", ts())
			d.reloadSignatures()
			d.publishGeoIP()
			if d.fwEngine != nil {
				if err := d.fwEngine.Apply(); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] Firewall reload error: %v\n", ts(), err)
				} else {
					fmt.Fprintf(os.Stderr, "[%s] Firewall rules reloaded\n", ts())
				}
			}
			continue
		}
		break // SIGTERM or SIGINT
	}

	csmlog.Info("shutting down")
	close(d.stopCh)

	// Stop all watchers
	d.logWatchersMu.Lock()
	watchers := d.logWatchers
	d.logWatchersMu.Unlock()
	for _, w := range watchers {
		w.Stop()
	}
	if d.webServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = d.webServer.Shutdown(ctx)
		cancel()
	}
	if d.challengeServer != nil {
		d.challengeServer.Shutdown()
	}
	if d.fileMonitor != nil {
		d.fileMonitor.Stop()
	}
	if sw := d.getSpoolWatcher(); sw != nil {
		sw.Stop()
	}
	if d.pamListener != nil {
		d.pamListener.Stop()
	}

	d.wg.Wait()
	if adb := attackdb.Global(); adb != nil {
		adb.Stop()
	}
	if err := d.store.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] error closing state store: %v\n", ts(), err)
	}
	d.lock.Release()
	fmt.Fprintf(os.Stderr, "[%s] CSM daemon stopped\n", ts())
	return nil
}

// DroppedAlerts returns the total number of alerts dropped due to
// channel backpressure since the daemon started.
func (d *Daemon) DroppedAlerts() int64 {
	return atomic.LoadInt64(&d.droppedAlerts)
}

// alertDispatcher batches and dispatches alerts.
func (d *Daemon) alertDispatcher() {
	defer d.wg.Done()

	// Batch alerts: collect for 5 seconds, then dispatch
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var batch []alert.Finding

	for {
		select {
		case <-d.stopCh:
			// Flush remaining with a timeout to avoid blocking shutdown
			if len(batch) > 0 {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				done := make(chan struct{})
				go func() {
					d.dispatchBatch(batch)
					close(done)
				}()
				select {
				case <-done:
				case <-ctx.Done():
					fmt.Fprintf(os.Stderr, "[%s] shutdown flush timed out after 30s, %d findings not dispatched\n", ts(), len(batch))
				}
				cancel()
			}
			return

		case f := <-d.alertCh:
			batch = append(batch, f)

		case <-ticker.C:
			if len(batch) > 0 {
				d.dispatchBatch(batch)
				batch = nil
			}
		}
	}
}

func (d *Daemon) dispatchBatch(findings []alert.Finding) {
	findings = alert.Deduplicate(findings)
	suppressions := d.store.LoadSuppressions()
	autoResponseFindings := findings
	if len(suppressions) > 0 {
		autoResponseFindings = filterUnsuppressedFindings(d.store, findings, suppressions)
	}

	// Record ALL findings in attack database (before filtering -
	// repeated attacks from the same IP must still be counted even if
	// the alert is suppressed by FilterNew).
	if adb := attackdb.Global(); adb != nil {
		for _, f := range autoResponseFindings {
			adb.RecordFinding(f)
		}
	}

	// Auto-block and permission fix run on ALL findings (not just new ones).
	// These must execute BEFORE FilterNew because repeat offender IPs and
	// recurring permission issues need to be fixed even if the alert was
	// already sent in a previous cycle.

	// Challenge routing runs FIRST - claims eligible IPs before hard-blocking.
	challengeActions := checks.ChallengeRouteIPs(d.cfg, autoResponseFindings)

	blockActions := checks.AutoBlockIPs(d.cfg, autoResponseFindings)
	permActions, permFixedKeys := checks.AutoFixPermissions(d.cfg, autoResponseFindings)

	// Mark auto-blocked IPs in attack database
	if adb := attackdb.Global(); adb != nil {
		for _, f := range blockActions {
			if ip := checks.ExtractIPFromFinding(f); ip != "" {
				adb.MarkBlocked(ip)
			}
		}
	}

	// Dismiss auto-fixed findings from the Findings page
	for _, key := range permFixedKeys {
		d.store.DismissLatestFinding(key)
	}

	// Filter through state - only new findings get alerted and logged
	newFindings := d.store.FilterNew(findings)

	// Filter out suppressed findings - prevents email/webhook alerts for
	// paths the admin has explicitly suppressed (e.g. false positives).
	// Suppressions are stored in state/suppressions.json, not in rule files.
	if len(suppressions) > 0 {
		newFindings = filterUnsuppressedFindings(d.store, newFindings, suppressions)
	}

	// Append auto-response actions to new findings for alerting
	newFindings = append(newFindings, blockActions...)
	newFindings = append(newFindings, challengeActions...)
	newFindings = append(newFindings, permActions...)

	if len(newFindings) == 0 {
		d.store.Update(findings)
		return
	}

	// Log to history
	d.store.AppendHistory(newFindings)

	// Kill and quarantine only run on NEW findings (don't re-kill/re-quarantine)
	killActions := checks.AutoKillProcesses(d.cfg, newFindings)
	quarantineActions := checks.AutoQuarantineFiles(d.cfg, newFindings)
	newFindings = append(newFindings, killActions...)
	newFindings = append(newFindings, quarantineActions...)

	// Correlation
	extra := checks.CorrelateFindings(newFindings)
	now := time.Now()
	for i := range extra {
		if extra[i].Timestamp.IsZero() {
			extra[i].Timestamp = now
		}
	}
	newFindings = append(newFindings, extra...)

	// Broadcast findings (no-op; dashboard uses polling)
	if d.webServer != nil {
		d.webServer.Broadcast(newFindings)
	}

	// Dispatch via email/webhook - filter out findings that are
	// informational or fully automated (no human action needed).
	// These are all visible in the web UI for forensics.
	var alertable []alert.Finding
	for _, f := range newFindings {
		switch f.Check {
		case "modsec_block_realtime", "modsec_warning_realtime", "modsec_csm_block_escalation":
			continue // ModSecurity: fully automated, visible on /modsec
		case "outdated_plugins":
			continue // informational, visible on findings page
		case "email_dkim_failure", "email_spf_rejection":
			continue // operational email auth issues - visible on findings page
		case "email_auth_failure_realtime", "pam_bruteforce", "exim_frozen_realtime":
			continue // failed logins and frozen bounces - informational, no action needed
		}
		alertable = append(alertable, f)
	}
	if err := alert.Dispatch(d.cfg, alertable); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Alert dispatch error: %v\n", ts(), err)
	}

	d.store.Update(findings)
}

func filterUnsuppressedFindings(store *state.Store, findings []alert.Finding, suppressions []state.SuppressionRule) []alert.Finding {
	if len(suppressions) == 0 {
		return findings
	}
	var filtered []alert.Finding
	for _, f := range findings {
		if !store.IsSuppressed(f, suppressions) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// criticalScanner runs critical checks every 10 minutes.
func (d *Daemon) criticalScanner() {
	defer d.wg.Done()

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.runPeriodicChecks(checks.TierCritical)
		}
	}
}

// deepScanner runs deep checks at the configured interval (default 60 min).
// If fanotify is active, runs only the checks it can't replace (reduced set).
// If fanotify is NOT active (fallback mode), runs the full deep tier for timer-mode parity.
func (d *Daemon) deepScanner() {
	defer d.wg.Done()

	interval := time.Duration(d.cfg.Thresholds.DeepScanIntervalMin) * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			// Update threat intelligence feeds (once per day)
			if db := checks.GetThreatDB(); db != nil {
				_ = db.UpdateFeeds()
			}
			// Prune expired attack DB records (90-day retention)
			if adb := attackdb.Global(); adb != nil {
				adb.PruneExpired()
			}

			// If fanotify is active, only run checks it can't replace.
			// If fanotify is NOT active, run the full deep tier.
			var findings []alert.Finding
			var deepTier checks.Tier
			if d.fileMonitor != nil {
				findings = checks.RunReducedDeep(d.cfg, d.store)
				deepTier = checks.TierDeep
			} else {
				deepTier = checks.TierDeep
				findings = checks.RunTier(d.cfg, d.store, deepTier)
			}
			if len(findings) > 0 {
				// Atomically purge stale perf findings and merge new ones.
				d.store.PurgeAndMergeFindings(checks.PerfCheckNamesForTier(deepTier), findings)
				for _, f := range findings {
					if strings.HasPrefix(f.Check, "perf_") && f.Severity == alert.Warning {
						continue
					}
					select {
					case d.alertCh <- f:
					default:
						atomic.AddInt64(&d.droppedAlerts, 1)
						fmt.Fprintf(os.Stderr, "[%s] alert channel full, dropping deep finding: %s\n", ts(), f.Check)
					}
				}
			}
		}
	}
}

func (d *Daemon) runPeriodicChecks(tier checks.Tier) {
	// Verify integrity
	if err := integrity.Verify(d.binaryPath, d.cfg); err != nil {
		select {
		case d.alertCh <- alert.Finding{
			Severity:  alert.Critical,
			Check:     "integrity",
			Message:   fmt.Sprintf("BINARY/CONFIG TAMPER DETECTED: %v", err),
			Timestamp: time.Now(),
		}:
		default:
			atomic.AddInt64(&d.droppedAlerts, 1)
			fmt.Fprintf(os.Stderr, "[%s] alert channel full, dropping integrity finding\n", ts())
		}
		return
	}

	findings := checks.RunTier(d.cfg, d.store, tier)
	if len(findings) > 0 {
		// Atomically purge stale perf findings and merge new ones.
		d.store.PurgeAndMergeFindings(checks.PerfCheckNamesForTier(tier), findings)
		for _, f := range findings {
			if strings.HasPrefix(f.Check, "perf_") && f.Severity == alert.Warning {
				continue
			}
			select {
			case d.alertCh <- f:
			default:
				atomic.AddInt64(&d.droppedAlerts, 1)
				fmt.Fprintf(os.Stderr, "[%s] alert channel full, dropping periodic finding: %s\n", ts(), f.Check)
			}
		}
	}
}

// heartbeat sends periodic pings to dead man's switch.
func (d *Daemon) heartbeat() {
	defer d.wg.Done()

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			alert.SendHeartbeat(d.cfg)
			d.hijackDetector.Cleanup()
			// Clean expired temporary allows
			if d.fwEngine != nil {
				d.fwEngine.CleanExpiredAllows()
				d.fwEngine.CleanExpiredSubnets()
			}
			// Clean expired temporary whitelist entries
			if tdb := checks.GetThreatDB(); tdb != nil {
				tdb.PruneExpiredWhitelist()
			}
		}
	}
}

func (d *Daemon) startLogWatchers() {
	// Session log handler wrapper - feeds events to both the alert handler and hijack detector
	sessionHandler := func(line string, cfg *config.Config) []alert.Finding {
		// Feed to hijack detector (tracks password changes + correlates with logins)
		ParseSessionLineForHijack(line, d.hijackDetector)
		// Regular session log handling
		return parseSessionLogLine(line, cfg)
	}

	hostInfo := platform.Detect()

	type logFile struct {
		path    string
		handler func(string, *config.Config) []alert.Finding
	}
	var logFiles []logFile

	// Generic Linux auth log. RHEL-family uses /var/log/secure, Debian
	// family uses /var/log/auth.log. Only register the log appropriate
	// for the detected OS so we don't spam "not found, retrying" forever.
	if hostInfo.IsDebianFamily() {
		logFiles = append(logFiles, logFile{"/var/log/auth.log", parseSecureLogLine})
	} else {
		logFiles = append(logFiles, logFile{"/var/log/secure", parseSecureLogLine})
	}

	// cPanel-specific logs — only watch these on cPanel hosts. On plain
	// Ubuntu/AlmaLinux they do not exist and the old code spammed
	// "not found, will retry every 60s" forever.
	if hostInfo.IsCPanel() {
		logFiles = append(logFiles,
			logFile{"/usr/local/cpanel/logs/session_log", sessionHandler},
			logFile{"/usr/local/cpanel/logs/access_log", parseAccessLogLineEnhanced},
			logFile{"/var/log/exim_mainlog", parseEximLogLine},
			logFile{"/var/log/messages", parseFTPLogLine},
			logFile{"/var/log/maillog", parseDovecotLogLine},
		)
	}

	// Only watch PHP Shield events if enabled in config
	if d.cfg.PHPShield.Enabled {
		logFiles = append(logFiles, logFile{phpEventsLogPath, parsePHPShieldLogLine})
	}

	// ModSecurity error log - auto-discover path based on detected web server.
	if modsecPath := discoverModSecLogPath(d.cfg); modsecPath != "" {
		logFiles = append(logFiles, logFile{modsecPath, parseModSecLogLineDeduped})
	} else if hostInfo.WebServer != platform.WSNone {
		// Only bother with the retry loop if a web server is actually
		// present. Headless hosts don't need this.
		fmt.Fprintf(os.Stderr, "[%s] ModSecurity error log not found (checked %v), will retry every 60s\n", ts(), hostInfo.ErrorLogPaths)
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			ticker := time.NewTicker(60 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-d.stopCh:
					return
				case <-ticker.C:
					path := discoverModSecLogPath(d.cfg)
					if path == "" {
						continue
					}
					w, err := NewLogWatcher(path, d.cfg, parseModSecLogLineDeduped, d.alertCh)
					if err != nil {
						continue
					}
					d.logWatchersMu.Lock()
					d.logWatchers = append(d.logWatchers, w)
					d.logWatchersMu.Unlock()
					d.wg.Add(1)
					go func(w *LogWatcher) {
						defer d.wg.Done()
						w.Run(d.stopCh)
					}(w)
					csmlog.Info("watching log (appeared after retry)", "path", path)
					return
				}
			}
		}()
	}

	// Real-time access log watcher for wp-login/xmlrpc brute force detection.
	// Auto-discover path from platform info (Apache/Nginx/cPanel aware).
	if accessLogPath := discoverAccessLogPath(); accessLogPath != "" {
		logFiles = append(logFiles, logFile{accessLogPath, parseAccessLogBruteForce})
	} else if hostInfo.WebServer != platform.WSNone && len(hostInfo.AccessLogPaths) > 0 {
		csmlog.Warn("access log not found, will retry every 60s", "candidates", fmt.Sprintf("%v", hostInfo.AccessLogPaths))
		d.wg.Add(1)
		go d.retryLogWatcher(hostInfo.AccessLogPaths[0], parseAccessLogBruteForce)
	}

	// Start background eviction for modsec dedup/escalation state
	StartModSecEviction(d.stopCh)

	// Start background eviction for access log brute force state
	StartAccessLogEviction(d.stopCh)

	// Start background eviction for email rate limiting state
	StartEmailRateEviction(d.stopCh)

	for _, lf := range logFiles {
		w, err := NewLogWatcher(lf.path, d.cfg, lf.handler, d.alertCh)
		if err != nil {
			if os.IsNotExist(err) {
				// File doesn't exist yet - retry periodically until it appears
				d.wg.Add(1)
				go d.retryLogWatcher(lf.path, lf.handler)
			} else {
				fmt.Fprintf(os.Stderr, "[%s] Warning: could not watch %s: %v\n", ts(), lf.path, err)
			}
			continue
		}
		d.logWatchers = append(d.logWatchers, w)
		d.wg.Add(1)
		go func(w *LogWatcher) {
			defer d.wg.Done()
			w.Run(d.stopCh)
		}(w)
		csmlog.Info("watching log", "path", lf.path)
	}
}

// retryLogWatcher polls for a missing log file every 60 seconds.
// When the file appears, it starts a watcher and returns.
func (d *Daemon) retryLogWatcher(path string, handler LogLineHandler) {
	defer d.wg.Done()
	csmlog.Warn("log not found, will retry every 60s", "path", path)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			w, err := NewLogWatcher(path, d.cfg, handler, d.alertCh)
			if err != nil {
				continue // still missing, keep retrying
			}
			d.logWatchersMu.Lock()
			d.logWatchers = append(d.logWatchers, w)
			d.logWatchersMu.Unlock()
			d.wg.Add(1)
			go func(w *LogWatcher) {
				defer d.wg.Done()
				w.Run(d.stopCh)
			}(w)
			csmlog.Info("watching log (appeared after retry)", "path", path)
			return
		}
	}
}

func (d *Daemon) startWebUI() {
	if !d.cfg.WebUI.Enabled {
		return
	}
	srv, err := webui.New(d.cfg, d.store)
	if err != nil {
		csmlog.Error("webui init error", "err", err)
		return
	}

	// Set version and signature count for status API
	srv.SetVersion(d.version)
	if scanner := signatures.Global(); scanner != nil {
		srv.SetSigCount(scanner.RuleCount())
	}

	d.webServer = srv
	d.logWatchersMu.Lock()
	numWatchers := len(d.logWatchers)
	d.logWatchersMu.Unlock()
	srv.SetHealthInfo(d.fileMonitor != nil, numWatchers)
	if d.fwEngine != nil {
		srv.SetIPBlocker(d.fwEngine)
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		if err := srv.Start(); err != nil {
			csmlog.Error("webui server error", "err", err)
		}
	}()
}

func (d *Daemon) startPAMListener() {
	pl, err := NewPAMListener(d.cfg, d.alertCh)
	if err != nil {
		csmlog.Warn("PAM listener not available", "err", err)
		return
	}
	d.pamListener = pl
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		pl.Run(d.stopCh)
	}()
	csmlog.Info("PAM listener active", "socket", pamSocketPath)
}

func (d *Daemon) startFileMonitor() {
	fm, err := NewFileMonitor(d.cfg, d.alertCh)
	if err != nil {
		csmlog.Warn("fanotify not available, falling back to periodic deep scan", "err", err)
		return
	}
	d.fileMonitor = fm
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		fm.Run(d.stopCh)
	}()
	csmlog.Info("fanotify file monitor active", "paths", "/home, /tmp, /dev/shm")
}

func (d *Daemon) startSpoolWatcher() {
	if !d.cfg.EmailAV.Enabled {
		return
	}

	// Create ClamAV scanner
	clamScanner := emailav.NewClamdScanner(d.cfg.EmailAV.ClamdSocket)

	// Create YARA-X scanner - share compiled rules from the global YARA scanner
	var yaraScanner *emailav.YaraXScanner
	if gs := yara.Global(); gs != nil {
		yaraScanner = emailav.NewYaraXScanner(gs)
	} else {
		yaraScanner = emailav.NewYaraXScanner(nil)
	}

	// Create orchestrator with both engines
	scanners := []emailav.Scanner{clamScanner, yaraScanner}
	orch := emailav.NewOrchestrator(scanners, d.cfg.EmailAV.ScanTimeoutDuration())

	// Create quarantine
	quar := emailav.NewQuarantine("/opt/csm/quarantine/email")
	d.emailQuarantine = quar

	// Create and start spool watcher
	sw, err := NewSpoolWatcher(d.cfg, d.alertCh, orch, quar)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Email AV spool watcher not available: %v\n", ts(), err)
		return
	}
	d.setSpoolWatcher(sw)

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.runSpoolWatcherLoop(sw, orch, quar)
	}()

	// Start quarantine cleanup goroutine
	d.wg.Add(1)
	go d.emailQuarantineCleanup()

	fmt.Fprintf(os.Stderr, "[%s] Email AV spool watcher active\n", ts())
}

func (d *Daemon) runSpoolWatcherLoop(sw *SpoolWatcher, orch *emailav.Orchestrator, quar *emailav.Quarantine) {
	current := sw
	for {
		current.Run()

		select {
		case <-d.stopCh:
			return
		default:
		}

		fmt.Fprintf(os.Stderr, "[%s] Email AV spool watcher stopped unexpectedly; restarting in 2s\n", ts())
		select {
		case <-d.stopCh:
			return
		case <-time.After(2 * time.Second):
		}

		next, err := NewSpoolWatcher(d.cfg, d.alertCh, orch, quar)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Email AV spool watcher restart failed: %v\n", ts(), err)
			continue
		}
		current = next
		d.setSpoolWatcher(next)
	}
}

func (d *Daemon) setSpoolWatcher(sw *SpoolWatcher) {
	d.spoolWatcherMu.Lock()
	d.spoolWatcher = sw
	d.spoolWatcherMu.Unlock()
	d.syncEmailAVWebState()
}

func (d *Daemon) getSpoolWatcher() *SpoolWatcher {
	d.spoolWatcherMu.Lock()
	defer d.spoolWatcherMu.Unlock()
	return d.spoolWatcher
}

// startForwarderWatcher starts the inotify watcher for /etc/valiases/.
func (d *Daemon) startForwarderWatcher() {
	fw, err := NewForwarderWatcher(d.alertCh, d.cfg.EmailProtection.KnownForwarders)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Warning: forwarder watcher not started: %v\n", ts(), err)
		return
	}
	d.forwarderWatcher = fw
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		fw.Run(d.stopCh)
	}()
	csmlog.Info("watching log (inotify forwarder watcher)", "path", "/etc/valiases/")
}

func (d *Daemon) syncEmailAVWebState() {
	if d.webServer == nil || d.emailQuarantine == nil {
		return
	}
	d.webServer.SetEmailQuarantine(d.emailQuarantine)
	if sw := d.getSpoolWatcher(); sw != nil {
		if sw.PermissionMode() {
			d.webServer.SetEmailAVWatcherMode("permission")
		} else {
			d.webServer.SetEmailAVWatcherMode("notification")
		}
	}
}

// emailQuarantineCleanup periodically removes expired quarantined email messages.
func (d *Daemon) emailQuarantineCleanup() {
	defer d.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			if d.emailQuarantine != nil {
				cleaned, err := d.emailQuarantine.CleanExpired(30 * 24 * time.Hour)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[%s] Email quarantine cleanup error: %v\n", ts(), err)
				} else if cleaned > 0 {
					fmt.Fprintf(os.Stderr, "[%s] Email quarantine cleanup: removed %d expired messages\n", ts(), cleaned)
				}
			}
		}
	}
}

func (d *Daemon) startChallengeServer() {
	if !d.cfg.Challenge.Enabled {
		return
	}

	if d.fwEngine == nil {
		fmt.Fprintf(os.Stderr, "[%s] Challenge server requires firewall to be enabled (for escalation and allow). Skipping.\n", ts())
		return
	}

	unblocker := challenge.IPUnblocker(d.fwEngine)

	d.ipList = challenge.NewIPList(d.cfg.StatePath)
	checks.SetChallengeIPList(d.ipList)
	srv := challenge.New(d.cfg, unblocker, d.ipList)
	d.challengeServer = srv
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		csmlog.Info("challenge server active", "port", d.cfg.Challenge.ListenPort)
		if err := srv.Start(); err != nil && err.Error() != "http: Server closed" {
			csmlog.Error("challenge server error", "err", err)
		}
	}()
}

func (d *Daemon) challengeEscalator() {
	defer d.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	expiry := parseBlockExpiry(d.cfg.AutoResponse.BlockExpiry)

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			if d.challengeServer != nil {
				d.challengeServer.CleanExpired()
			}

			expired := d.ipList.ExpiredEntries()
			for _, e := range expired {
				if d.fwEngine == nil {
					continue
				}
				reason := fmt.Sprintf("CSM challenge-timeout: %s", truncateStr(e.Reason, 100))
				if err := d.fwEngine.BlockIP(e.IP, reason, expiry); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] challenge-escalate: error blocking %s: %v\n", ts(), e.IP, err)
					continue
				}
				fmt.Fprintf(os.Stderr, "[%s] CHALLENGE-ESCALATE: %s timed out, hard-blocked\n", ts(), e.IP)
			}
		}
	}
}

func parseBlockExpiry(s string) time.Duration {
	if s == "" {
		return 24 * time.Hour
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func (d *Daemon) initGeoIP() {
	dbDir := filepath.Join(d.cfg.StatePath, "geoip")
	db := geoip.Open(dbDir)
	if db != nil {
		d.geoipDB = db
		setGeoIPDB(db) // make available to log watcher handlers for country filtering
		if d.webServer != nil {
			d.webServer.SetGeoIPDB(db)
		}
	}
}

// publishGeoIP reloads existing GeoIP databases or creates a new DB
// if databases were downloaded for the first time.
// Mutex-protected: safe to call from geoipUpdater goroutine and SIGHUP handler concurrently.
func (d *Daemon) publishGeoIP() {
	d.geoipMu.Lock()
	defer d.geoipMu.Unlock()

	if d.geoipDB != nil {
		if err := d.geoipDB.Reload(); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] GeoIP reload error: %v\n", ts(), err)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] GeoIP databases reloaded\n", ts())
		}
		return
	}

	// First-time: no DB existed at startup, try to open freshly downloaded files
	dbDir := filepath.Join(d.cfg.StatePath, "geoip")
	db := geoip.OpenFresh(dbDir)
	if db != nil {
		d.geoipDB = db
		setGeoIPDB(db)
		if d.webServer != nil {
			d.webServer.SetGeoIPDB(db)
		}
		fmt.Fprintf(os.Stderr, "[%s] GeoIP databases loaded for the first time\n", ts())
	}
}

// geoipUpdater periodically downloads updated GeoLite2 databases.
func (d *Daemon) geoipUpdater() {
	defer d.wg.Done()

	// Skip if no credentials configured
	if d.cfg.GeoIP.AccountID == "" || d.cfg.GeoIP.LicenseKey == "" {
		return
	}

	// Skip if auto_update is explicitly false
	if d.cfg.GeoIP.AutoUpdate != nil && !*d.cfg.GeoIP.AutoUpdate {
		return
	}

	interval := 24 * time.Hour
	if d.cfg.GeoIP.UpdateInterval != "" {
		if parsed, err := time.ParseDuration(d.cfg.GeoIP.UpdateInterval); err == nil && parsed >= time.Hour {
			interval = parsed
		}
	}

	// Wait 5 minutes before first update attempt (let the daemon stabilize)
	select {
	case <-d.stopCh:
		return
	case <-time.After(5 * time.Minute):
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		d.doGeoIPUpdate()

		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) doGeoIPUpdate() {
	results := geoip.Update(
		filepath.Join(d.cfg.StatePath, "geoip"),
		d.cfg.GeoIP.AccountID,
		d.cfg.GeoIP.LicenseKey,
		d.cfg.GeoIP.Editions,
	)
	if results == nil {
		return
	}

	anyUpdated := false
	for _, r := range results {
		switch r.Status {
		case "updated":
			fmt.Fprintf(os.Stderr, "[%s] GeoIP auto-update: %s updated\n", ts(), r.Edition)
			anyUpdated = true
		case "up_to_date":
			// silent
		case "error":
			fmt.Fprintf(os.Stderr, "[%s] GeoIP auto-update: %s error: %v\n", ts(), r.Edition, r.Err)
		}
	}

	if anyUpdated {
		d.publishGeoIP()
	}
}

func (d *Daemon) startFirewall() {
	if !d.cfg.Firewall.Enabled {
		return
	}

	// Merge top-level infra IPs into firewall's list. Top-level controls
	// alert suppression (tight: only admin IPs), firewall may include
	// additional CIDRs (e.g. server's own range) that need port access
	// but should still be tracked for security alerts.
	d.cfg.Firewall.InfraIPs = mergeInfraIPs(d.cfg.InfraIPs, d.cfg.Firewall.InfraIPs)

	engine, err := firewall.NewEngine(d.cfg.Firewall, d.cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Firewall engine init error: %v\n", ts(), err)
		return
	}

	if err := engine.Apply(); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Firewall apply error: %v\n", ts(), err)
		return
	}

	d.fwEngine = engine

	// Set firewall engine for auto-blocking
	checks.SetIPBlocker(engine)

	fwState, _ := firewall.LoadState(d.cfg.StatePath)
	csmlog.Info("firewall active",
		"blocked_ips", len(fwState.Blocked),
		"allowed_ips", len(fwState.Allowed),
	)

	// Start Dynamic DNS resolver if configured
	if len(d.cfg.Firewall.DynDNSHosts) > 0 {
		resolver := firewall.NewDynDNSResolver(d.cfg.Firewall.DynDNSHosts, engine)
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			resolver.Run(d.stopCh)
		}()
		csmlog.Info("DynDNS resolver active", "hosts", len(d.cfg.Firewall.DynDNSHosts))
	}

	// Start Cloudflare IP whitelist refresh if configured
	if d.cfg.Cloudflare.Enabled {
		d.wg.Add(1)
		go d.cloudflareRefreshLoop()
		csmlog.Info("cloudflare IP whitelist enabled", "refresh_hours", d.cfg.Cloudflare.RefreshHours)
	}
}

// cloudflareRefreshLoop fetches Cloudflare IPs and updates the firewall sets periodically.
func (d *Daemon) cloudflareRefreshLoop() {
	defer d.wg.Done()

	interval := time.Duration(d.cfg.Cloudflare.RefreshHours) * time.Hour

	// Fetch immediately on startup
	d.refreshCloudflareIPs()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.refreshCloudflareIPs()
		}
	}
}

func (d *Daemon) refreshCloudflareIPs() {
	ipv4, ipv6, err := firewall.FetchCloudflareIPs()
	if err != nil {
		csmlog.Error("cloudflare IP fetch error", "err", err)
		return
	}

	if d.fwEngine != nil {
		if err := d.fwEngine.UpdateCloudflareSet(ipv4, ipv6); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Cloudflare set update error: %v\n", ts(), err)
			return
		}
	}

	firewall.SaveCFState(d.cfg.StatePath, ipv4, ipv6, time.Now())

	// Update the checks package so AutoBlockIPs/ChallengeRouteIPs skip CF IPs.
	// Blocking a CF edge IP would block thousands of legitimate users.
	allCF := make([]string, 0, len(ipv4)+len(ipv6))
	allCF = append(allCF, ipv4...)
	allCF = append(allCF, ipv6...)
	checks.SetCloudflareNets(allCF)
}

// signatureUpdater periodically downloads new rules and reloads scanners.
func (d *Daemon) signatureUpdater() {
	defer d.wg.Done()

	yamlEnabled := d.cfg.Signatures.UpdateURL != ""
	forgeEnabled := d.cfg.Signatures.YaraForge.Enabled && yara.Available()

	if !yamlEnabled && !forgeEnabled {
		return
	}

	select {
	case <-d.stopCh:
		return
	case <-time.After(5 * time.Minute):
	}

	yamlInterval := 24 * time.Hour
	if d.cfg.Signatures.UpdateInterval != "" {
		if parsed, err := time.ParseDuration(d.cfg.Signatures.UpdateInterval); err == nil && parsed >= time.Hour {
			yamlInterval = parsed
		}
	}
	forgeInterval := 168 * time.Hour
	if d.cfg.Signatures.YaraForge.UpdateInterval != "" {
		if parsed, err := time.ParseDuration(d.cfg.Signatures.YaraForge.UpdateInterval); err == nil && parsed >= time.Hour {
			forgeInterval = parsed
		}
	}

	tickInterval := yamlInterval
	if forgeEnabled && forgeInterval < tickInterval {
		tickInterval = forgeInterval
	}
	if !yamlEnabled {
		tickInterval = forgeInterval
	}

	var lastYAML, lastForge time.Time

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		now := time.Now()
		if yamlEnabled && now.Sub(lastYAML) >= yamlInterval {
			d.doSignatureUpdate()
			lastYAML = now
		}
		if forgeEnabled && now.Sub(lastForge) >= forgeInterval {
			d.doForgeUpdate()
			lastForge = now
		}

		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) doSignatureUpdate() {
	count, err := signatures.Update(d.cfg.Signatures.RulesDir, d.cfg.Signatures.UpdateURL, d.cfg.Signatures.SigningKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Signature auto-update failed: %v\n", ts(), err)
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] Signature auto-update: %d rules downloaded\n", ts(), count)
	d.reloadSignatures()
}

func (d *Daemon) doForgeUpdate() {
	yaraScanner := yara.Global()
	if yaraScanner == nil {
		// No YARA scanner active (build without yara tag or no rules dir).
		// Skip Forge update - rules can't be loaded anyway.
		return
	}

	db := store.Global()
	currentVersion := ""
	if db != nil {
		currentVersion = db.GetMetaString("forge_version_" + d.cfg.Signatures.YaraForge.Tier)
	}

	newVersion, count, err := signatures.ForgeUpdate(
		d.cfg.Signatures.RulesDir,
		d.cfg.Signatures.YaraForge.Tier,
		currentVersion,
		d.cfg.Signatures.SigningKey,
		d.cfg.Signatures.DisabledRules,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] YARA Forge update failed: %v\n", ts(), err)
		return
	}
	if count == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "[%s] YARA Forge update: %d rules (version %s)\n", ts(), count, newVersion)

	// Record rule count before reload to detect conflicts with existing .yar files.
	prevCount := yaraScanner.RuleCount()

	if err := yaraScanner.Reload(); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] YARA rule reload after Forge update error: %v\n", ts(), err)
		return // don't store version - retry next cycle
	}

	newCount := yaraScanner.RuleCount()

	// If rule count dropped, the Forge file likely conflicts with existing rules.
	// Roll back: remove the Forge file, reload again, don't store version.
	if newCount < prevCount {
		forgeFile := filepath.Join(d.cfg.Signatures.RulesDir, fmt.Sprintf("yara-forge-%s.yar", d.cfg.Signatures.YaraForge.Tier))
		fmt.Fprintf(os.Stderr, "[%s] YARA Forge rollback: rule count dropped %d -> %d (conflict with existing rules), removing %s\n",
			ts(), prevCount, newCount, forgeFile)
		_ = os.Remove(forgeFile)
		_ = yaraScanner.Reload()
		return // don't store version
	}

	fmt.Fprintf(os.Stderr, "[%s] Reloaded %d YARA rules after Forge update\n", ts(), newCount)

	if db != nil {
		_ = db.SetMetaString("forge_version_"+d.cfg.Signatures.YaraForge.Tier, newVersion)
	}
}

func (d *Daemon) reloadSignatures() {
	if scanner := signatures.Global(); scanner != nil {
		if err := scanner.Reload(); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] YAML rule reload error: %v\n", ts(), err)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] Reloaded %d YAML rules (version %d)\n", ts(), scanner.RuleCount(), scanner.Version())
			if d.webServer != nil {
				d.webServer.SetSigCount(scanner.RuleCount())
			}
		}
	}
	if yaraScanner := yara.Global(); yaraScanner != nil {
		if err := yaraScanner.Reload(); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] YARA rule reload error: %v\n", ts(), err)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] Reloaded %d YARA rule file(s)\n", ts(), yaraScanner.RuleCount())
		}
	}
}

// deployConfigs writes embedded config files to their system locations on startup.
// Ensures WHM plugin CGI and ModSec rules stay current after binary upgrades.
func deployConfigs() {
	// WHM plugin CGI - embedded in binary
	if _, err := os.Stat("/usr/local/cpanel"); err == nil {
		dst := "/usr/local/cpanel/whostmgr/docroot/cgi/addon_csm.cgi"
		if err := os.WriteFile(dst, embeddedWHMCGI, 0755); err == nil {
			fmt.Fprintf(os.Stderr, "[%s] WHM plugin CGI deployed\n", ts())
		}
		_ = os.MkdirAll("/var/cpanel/apps", 0755)
		_ = os.WriteFile("/var/cpanel/apps/csm.conf", embeddedWHMConf, 0644)
	}

	// Deploy script (self-updating)
	_ = os.WriteFile("/opt/csm/deploy.sh", embeddedDeployScript, 0755)

	// ModSecurity virtual patches
	for _, dst := range []string{
		"/etc/apache2/conf.d/modsec/modsec2.user.conf",
		"/usr/local/apache/conf/modsec2.user.conf",
	} {
		if _, err := os.Stat(filepath.Dir(dst)); err == nil {
			_ = os.WriteFile(dst, embeddedModSec, 0644)
			overridesFile := filepath.Join(filepath.Dir(dst), "modsec2.csm-overrides.conf")
			modsec.EnsureOverridesInclude(dst, overridesFile)
			break
		}
	}
}

// watchdogNotifier sends systemd watchdog keepalives on its own ticker.
// Runs at half the WatchdogSec interval so there's always margin.
// Completely independent of scan goroutines — never blocks.
func (d *Daemon) watchdogNotifier() {
	defer d.wg.Done()

	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return // watchdog not configured
	}
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}

	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		return
	}

	// Notify at half the watchdog interval for safety margin
	interval := time.Duration(usec) * time.Microsecond / 2
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}

	csmlog.Info("systemd watchdog active", "interval", interval.String())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			sdNotify(addr, "WATCHDOG=1")
		}
	}
}

func sdNotify(addr, msg string) {
	conn, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return
	}
	defer func() { _ = syscall.Close(conn) }()
	sa := &syscall.SockaddrUnix{Name: addr}
	_ = syscall.Sendmsg(conn, []byte(msg), nil, sa, 0)
}

func ts() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func orNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
}
