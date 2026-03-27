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
	"github.com/pidginhost/cpanel-security-monitor/internal/firewall"
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
	fileMonitor     *FileMonitor
	hijackDetector  *PasswordHijackDetector
	pamListener     *PAMListener
	webServer       *webui.Server
	challengeServer *challenge.Server
	fwEngine        *firewall.Engine
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
		fmt.Fprintf(os.Stderr, "[%s] Attack DB initialized (%s)\n", ts(), adb.FormatTopLine())
	}

	// Start firewall engine if enabled
	d.startFirewall()

	// Start challenge server if enabled (gray listing)
	d.startChallengeServer()

	// Create password hijack detector
	d.hijackDetector = NewPasswordHijackDetector(d.cfg, d.alertCh)

	// Start alert dispatcher
	d.wg.Add(1)
	go d.alertDispatcher()

	// Start inotify log watchers
	d.startLogWatchers()

	// Start PAM listener for real-time brute-force detection
	d.startPAMListener()

	// Start fanotify file monitor (real-time detection starts immediately)
	d.startFileMonitor()

	// Start Web UI server — available immediately, before initial scan
	d.startWebUI()

	// Run initial baseline scan in background (doesn't block startup)
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		fmt.Fprintf(os.Stderr, "[%s] Running initial baseline scan (background)\n", ts())
		initialFindings := checks.RunTier(d.cfg, d.store, checks.TierAll)
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
		d.store.SetLatestFindings(initialFindings)
		fmt.Fprintf(os.Stderr, "[%s] Initial scan complete: %d findings (%d new)\n", ts(), len(initialFindings), len(newFindings))
	}()

	// Start periodic scanners
	d.wg.Add(1)
	go d.criticalScanner()

	d.wg.Add(1)
	go d.deepScanner()

	// Start automatic signature updates
	d.wg.Add(1)
	go d.signatureUpdater()

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
	for _, w := range d.logWatchers {
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

	// Filter through state
	newFindings := d.store.FilterNew(findings)
	if len(newFindings) == 0 {
		return
	}

	// Log to history
	d.store.AppendHistory(newFindings)

	// Auto-response (kill, quarantine on new findings only)
	killActions := checks.AutoKillProcesses(d.cfg, newFindings)
	quarantineActions := checks.AutoQuarantineFiles(d.cfg, newFindings)
	// Permission fix runs on ALL findings — safe, idempotent, and must fix baseline findings too
	permActions, permFixedKeys := checks.AutoFixPermissions(d.cfg, findings)
	// Auto-block uses ALL findings — reputation IPs must be blocked even if previously seen
	blockActions := checks.AutoBlockIPs(d.cfg, findings)
	newFindings = append(newFindings, killActions...)
	newFindings = append(newFindings, quarantineActions...)
	newFindings = append(newFindings, permActions...)
	newFindings = append(newFindings, blockActions...)

	// Dismiss auto-fixed findings from the Findings page so they don't
	// remain visible after the underlying issue has been remediated.
	for _, key := range permFixedKeys {
		d.store.DismissLatestFinding(key)
	}

	// Record all findings in attack database
	if adb := attackdb.Global(); adb != nil {
		for _, f := range findings {
			adb.RecordFinding(f)
		}
		// Mark auto-blocked IPs
		for _, f := range blockActions {
			if ip := checks.ExtractIPFromFinding(f); ip != "" {
				adb.MarkBlocked(ip)
			}
		}
	}

	// Correlation
	extra := checks.CorrelateFindings(newFindings)
	now := time.Now()
	for i := range extra {
		if extra[i].Timestamp.IsZero() {
			extra[i].Timestamp = now
		}
	}
	newFindings = append(newFindings, extra...)

	// Broadcast to WebSocket clients
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

// deepScanner runs deep checks every 60 minutes.
// If fanotify is active, runs only the checks it can't replace (reduced set).
// If fanotify is NOT active (fallback mode), runs the full deep tier for timer-mode parity.
func (d *Daemon) deepScanner() {
	defer d.wg.Done()

	ticker := time.NewTicker(60 * time.Minute)
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
				for _, f := range findings {
					d.alertCh <- f
				}
			}
		}
	}
}

func (d *Daemon) runPeriodicChecks(tier checks.Tier) {
	// Verify integrity
	if err := integrity.Verify(d.binaryPath, d.cfg); err != nil {
		d.alertCh <- alert.Finding{
			Severity:  alert.Critical,
			Check:     "integrity",
			Message:   fmt.Sprintf("BINARY/CONFIG TAMPER DETECTED: %v", err),
			Timestamp: time.Now(),
		}
		return
	}

	findings := checks.RunTier(d.cfg, d.store, tier)
	if len(findings) > 0 {
		// Update latest findings for the Findings page
		d.store.SetLatestFindings(findings)
		for _, f := range findings {
			d.alertCh <- f
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
		{phpEventsLogPath, parsePHPShieldLogLine},
	}

	for _, lf := range logFiles {
		w, err := NewLogWatcher(lf.path, d.cfg, lf.handler, d.alertCh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Warning: could not watch %s: %v\n", ts(), lf.path, err)
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
	srv.SetHealthInfo(d.fileMonitor != nil, len(d.logWatchers))
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
