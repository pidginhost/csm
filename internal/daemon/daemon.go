package daemon

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"context"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/attackdb"
	"github.com/pidginhost/cpanel-security-monitor/internal/challenge"
	"github.com/pidginhost/cpanel-security-monitor/internal/checks"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/emailav"
	"github.com/pidginhost/cpanel-security-monitor/internal/firewall"
	"github.com/pidginhost/cpanel-security-monitor/internal/geoip"
	"github.com/pidginhost/cpanel-security-monitor/internal/integrity"
	"github.com/pidginhost/cpanel-security-monitor/internal/signatures"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
	"github.com/pidginhost/cpanel-security-monitor/internal/webui"
	"github.com/pidginhost/cpanel-security-monitor/internal/yara"
)

// Daemon is the main persistent monitoring process.
type Daemon struct {
	cfg        *config.Config
	store      *state.Store
	lock       *state.LockFile
	binaryPath string

	logWatchers     []*LogWatcher
	logWatchersMu   sync.Mutex
	fileMonitor     *FileMonitor
	hijackDetector  *PasswordHijackDetector
	pamListener     *PAMListener
	spoolWatcher    *SpoolWatcher
	spoolWatcherMu  sync.Mutex
	emailQuarantine *emailav.Quarantine
	webServer       *webui.Server
	challengeServer *challenge.Server
	fwEngine        *firewall.Engine
	geoipDB         *geoip.DB
	geoipMu         sync.Mutex // protects geoipDB for publishGeoIP
	alertCh         chan alert.Finding
	stopCh          chan struct{}
	wg              sync.WaitGroup
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

// Run starts the daemon and blocks until stopped.
func (d *Daemon) Run() error {
	fmt.Fprintf(os.Stderr, "[%s] CSM daemon starting\n", ts())

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

	// Create password hijack detector
	d.hijackDetector = NewPasswordHijackDetector(d.cfg, d.alertCh)

	// Start inotify log watchers
	d.startLogWatchers()

	// Start PAM listener for real-time brute-force detection
	d.startPAMListener()

	// Start fanotify file monitor (real-time detection starts immediately)
	d.startFileMonitor()

	// Start email AV spool watcher (separate fanotify for Exim spool)
	d.startSpoolWatcher()

	// Start Web UI server — available immediately, before initial scan
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

	// Permission auto-fix runs on ALL findings (not just new) because
	// it's safe/idempotent and should fix baseline findings too.
	permActions, permFixedKeys := checks.AutoFixPermissions(d.cfg, initialFindings)

	// Other auto-response only on new findings
	if len(newFindings) > 0 {
		killActions := checks.AutoKillProcesses(d.cfg, newFindings)
		quarantineActions := checks.AutoQuarantineFiles(d.cfg, newFindings)
		blockActions := checks.AutoBlockIPs(d.cfg, initialFindings)
		newFindings = append(newFindings, killActions...)
		newFindings = append(newFindings, quarantineActions...)
		newFindings = append(newFindings, permActions...)
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
	// Full replace — initial scan runs all checks, so stale findings
	// from previous daemon runs must not persist.
	d.store.ClearLatestFindings()
	d.store.SetLatestFindings(initialFindings)
	fmt.Fprintf(os.Stderr, "[%s] Initial scan complete: %d findings (%d new)\n", ts(), len(initialFindings), len(newFindings))

	// NOW start the alert dispatcher — no more race with initial scan
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

	fmt.Fprintf(os.Stderr, "[%s] CSM daemon running\n", ts())

	// Wait for signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			fmt.Fprintf(os.Stderr, "[%s] SIGHUP received — reloading rules\n", ts())
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

	fmt.Fprintf(os.Stderr, "[%s] Shutting down\n", ts())
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
	_ = d.store.Close()
	d.lock.Release()
	fmt.Fprintf(os.Stderr, "[%s] CSM daemon stopped\n", ts())
	return nil
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
			// Flush remaining
			if len(batch) > 0 {
				d.dispatchBatch(batch)
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

	// Record ALL findings in attack database (before filtering —
	// repeated attacks from the same IP must still be counted even if
	// the alert is suppressed by FilterNew).
	if adb := attackdb.Global(); adb != nil {
		for _, f := range findings {
			adb.RecordFinding(f)
		}
	}

	// Auto-block and permission fix run on ALL findings (not just new ones).
	// These must execute BEFORE FilterNew because repeat offender IPs and
	// recurring permission issues need to be fixed even if the alert was
	// already sent in a previous cycle.
	blockActions := checks.AutoBlockIPs(d.cfg, findings)
	permActions, permFixedKeys := checks.AutoFixPermissions(d.cfg, findings)

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

	// Filter through state — only new findings get alerted and logged
	newFindings := d.store.FilterNew(findings)

	// Filter out suppressed findings — prevents email/webhook alerts for
	// paths the admin has explicitly suppressed (e.g. false positives).
	// Suppressions are stored in state/suppressions.json, not in rule files.
	suppressions := d.store.LoadSuppressions()
	if len(suppressions) > 0 {
		var unsuppressed []alert.Finding
		for _, f := range newFindings {
			if !d.store.IsSuppressed(f, suppressions) {
				unsuppressed = append(unsuppressed, f)
			}
		}
		newFindings = unsuppressed
	}

	// Append auto-response actions to new findings for alerting
	newFindings = append(newFindings, blockActions...)
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

	// Dispatch via email/webhook
	if err := alert.Dispatch(d.cfg, newFindings); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Alert dispatch error: %v\n", ts(), err)
	}

	d.store.Update(findings)
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
			// Notify systemd watchdog
			notifyWatchdog()
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
			if d.fileMonitor != nil {
				findings = checks.RunReducedDeep(d.cfg, d.store)
			} else {
				findings = checks.RunTier(d.cfg, d.store, checks.TierDeep)
			}
			if len(findings) > 0 {
				// Merge into Findings page (same as criticalScanner does)
				d.store.SetLatestFindings(findings)
				for _, f := range findings {
					select {
					case d.alertCh <- f:
					default:
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
			fmt.Fprintf(os.Stderr, "[%s] alert channel full, dropping integrity finding\n", ts())
		}
		return
	}

	findings := checks.RunTier(d.cfg, d.store, tier)
	if len(findings) > 0 {
		// Update latest findings for the Findings page
		d.store.SetLatestFindings(findings)
		for _, f := range findings {
			select {
			case d.alertCh <- f:
			default:
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
			}
			// Clean expired temporary whitelist entries
			if tdb := checks.GetThreatDB(); tdb != nil {
				tdb.PruneExpiredWhitelist()
			}
		}
	}
}

func (d *Daemon) startLogWatchers() {
	// Session log handler wrapper — feeds events to both the alert handler and hijack detector
	sessionHandler := func(line string, cfg *config.Config) []alert.Finding {
		// Feed to hijack detector (tracks password changes + correlates with logins)
		ParseSessionLineForHijack(line, d.hijackDetector)
		// Regular session log handling
		return parseSessionLogLine(line, cfg)
	}

	logFiles := []struct {
		path    string
		handler func(string, *config.Config) []alert.Finding
	}{
		{"/usr/local/cpanel/logs/session_log", sessionHandler},
		{"/usr/local/cpanel/logs/access_log", parseAccessLogLineEnhanced},
		{"/var/log/secure", parseSecureLogLine},
		{"/var/log/exim_mainlog", parseEximLogLine},
		{"/var/log/messages", parseFTPLogLine},
	}

	// Only watch PHP Shield events if enabled in config
	if d.cfg.PHPShield.Enabled {
		logFiles = append(logFiles, struct {
			path    string
			handler func(string, *config.Config) []alert.Finding
		}{phpEventsLogPath, parsePHPShieldLogLine})
	}

	for _, lf := range logFiles {
		w, err := NewLogWatcher(lf.path, d.cfg, lf.handler, d.alertCh)
		if err != nil {
			if os.IsNotExist(err) {
				// File doesn't exist yet — retry periodically until it appears
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
		fmt.Fprintf(os.Stderr, "[%s] Watching: %s\n", ts(), lf.path)
	}
}

// retryLogWatcher polls for a missing log file every 60 seconds.
// When the file appears, it starts a watcher and returns.
func (d *Daemon) retryLogWatcher(path string, handler LogLineHandler) {
	defer d.wg.Done()
	fmt.Fprintf(os.Stderr, "[%s] Warning: %s not found, will retry every 60s\n", ts(), path)
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
			fmt.Fprintf(os.Stderr, "[%s] Watching: %s (appeared after retry)\n", ts(), path)
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
		fmt.Fprintf(os.Stderr, "[%s] WebUI init error: %v\n", ts(), err)
		return
	}

	// Set signature count for status API
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
			fmt.Fprintf(os.Stderr, "[%s] WebUI server error: %v\n", ts(), err)
		}
	}()
}

func (d *Daemon) startPAMListener() {
	pl, err := NewPAMListener(d.cfg, d.alertCh)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] PAM listener not available: %v\n", ts(), err)
		return
	}
	d.pamListener = pl
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		pl.Run(d.stopCh)
	}()
	fmt.Fprintf(os.Stderr, "[%s] PAM listener active: %s\n", ts(), pamSocketPath)
}

func (d *Daemon) startFileMonitor() {
	fm, err := NewFileMonitor(d.cfg, d.alertCh)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] fanotify not available: %v (falling back to periodic deep scan)\n", ts(), err)
		return
	}
	d.fileMonitor = fm
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		fm.Run(d.stopCh)
	}()
	fmt.Fprintf(os.Stderr, "[%s] fanotify file monitor active on /home, /tmp, /dev/shm\n", ts())
}

func (d *Daemon) startSpoolWatcher() {
	if !d.cfg.EmailAV.Enabled {
		return
	}

	// Create ClamAV scanner
	clamScanner := emailav.NewClamdScanner(d.cfg.EmailAV.ClamdSocket)

	// Create YARA-X scanner — share compiled rules from the global YARA scanner
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

	var unblocker challenge.IPUnblocker
	if d.fwEngine != nil {
		unblocker = d.fwEngine
	}

	srv := challenge.New(d.cfg, unblocker)
	d.challengeServer = srv
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		fmt.Fprintf(os.Stderr, "[%s] Challenge server active on port %d\n", ts(), d.cfg.Challenge.ListenPort)
		if err := srv.Start(); err != nil && err.Error() != "http: Server closed" {
			fmt.Fprintf(os.Stderr, "[%s] Challenge server error: %v\n", ts(), err)
		}
	}()
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

	// Ensure firewall uses main config's infra IPs if its own list is empty
	if len(d.cfg.Firewall.InfraIPs) == 0 {
		d.cfg.Firewall.InfraIPs = d.cfg.InfraIPs
	}

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
	fmt.Fprintf(os.Stderr, "[%s] Firewall active: %d blocked, %d allowed IPs\n",
		ts(), len(fwState.Blocked), len(fwState.Allowed))

	// Start Dynamic DNS resolver if configured
	if len(d.cfg.Firewall.DynDNSHosts) > 0 {
		resolver := firewall.NewDynDNSResolver(d.cfg.Firewall.DynDNSHosts, engine)
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			resolver.Run(d.stopCh)
		}()
		fmt.Fprintf(os.Stderr, "[%s] DynDNS resolver active for %d host(s)\n",
			ts(), len(d.cfg.Firewall.DynDNSHosts))
	}
}

// signatureUpdater periodically downloads new rules and reloads scanners.
func (d *Daemon) signatureUpdater() {
	defer d.wg.Done()

	// Skip if no update URL configured
	if d.cfg.Signatures.UpdateURL == "" {
		return
	}

	interval := 24 * time.Hour
	if d.cfg.Signatures.UpdateInterval != "" {
		if parsed, err := time.ParseDuration(d.cfg.Signatures.UpdateInterval); err == nil && parsed >= time.Hour {
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
		d.doSignatureUpdate()

		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) doSignatureUpdate() {
	count, err := signatures.Update(d.cfg.Signatures.RulesDir, d.cfg.Signatures.UpdateURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Signature auto-update failed: %v\n", ts(), err)
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] Signature auto-update: %d rules downloaded\n", ts(), count)
	d.reloadSignatures()
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
	// WHM plugin CGI — embedded in binary
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
			break
		}
	}
}

func notifyWatchdog() {
	// systemd watchdog notification
	if os.Getenv("WATCHDOG_USEC") != "" {
		// Write to the notify socket
		addr := os.Getenv("NOTIFY_SOCKET")
		if addr != "" {
			conn, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
			if err == nil {
				sa := &syscall.SockaddrUnix{Name: addr}
				_ = syscall.Sendmsg(conn, []byte("WATCHDOG=1"), nil, sa, 0)
				_ = syscall.Close(conn)
			}
		}
	}
}

func ts() string {
	return time.Now().Format("2006-01-02 15:04:05")
}
