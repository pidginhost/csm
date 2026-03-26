package daemon

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/checks"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/integrity"
	"github.com/pidginhost/cpanel-security-monitor/internal/signatures"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// Daemon is the main persistent monitoring process.
type Daemon struct {
	cfg        *config.Config
	store      *state.Store
	lock       *state.LockFile
	binaryPath string

	logWatchers    []*LogWatcher
	fileMonitor    *FileMonitor
	hijackDetector *PasswordHijackDetector
	alertCh        chan alert.Finding
	stopCh         chan struct{}
	wg             sync.WaitGroup
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

	// Run initial baseline scan (catches existing files before fanotify starts)
	fmt.Fprintf(os.Stderr, "[%s] Running initial baseline scan\n", ts())
	initialFindings := checks.RunTier(d.cfg, d.store, checks.TierAll)
	d.store.AppendHistory(initialFindings)
	newFindings := d.store.FilterNew(initialFindings)
	if len(newFindings) > 0 {
		_ = alert.Dispatch(d.cfg, newFindings)
	}
	d.store.Update(initialFindings)
	fmt.Fprintf(os.Stderr, "[%s] Initial scan complete: %d findings (%d new)\n", ts(), len(initialFindings), len(newFindings))

	// Create password hijack detector
	d.hijackDetector = NewPasswordHijackDetector(d.cfg, d.alertCh)

	// Start alert dispatcher
	d.wg.Add(1)
	go d.alertDispatcher()

	// Start inotify log watchers
	d.startLogWatchers()

	// Start fanotify file monitor (falls back to periodic if kernel doesn't support it)
	d.startFileMonitor()

	// Start periodic scanners
	d.wg.Add(1)
	go d.criticalScanner()

	d.wg.Add(1)
	go d.deepScanner()

	// Start heartbeat
	d.wg.Add(1)
	go d.heartbeat()

	fmt.Fprintf(os.Stderr, "[%s] CSM daemon running\n", ts())

	// Wait for signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			// Reload signature rules on SIGHUP
			fmt.Fprintf(os.Stderr, "[%s] SIGHUP received — reloading signature rules\n", ts())
			if scanner := signatures.Global(); scanner != nil {
				if err := scanner.Reload(); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] Rule reload error: %v\n", ts(), err)
				} else {
					fmt.Fprintf(os.Stderr, "[%s] Reloaded %d rules (version %d)\n", ts(), scanner.RuleCount(), scanner.Version())
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
	if d.fileMonitor != nil {
		d.fileMonitor.Stop()
	}

	d.wg.Wait()
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

	// Auto-response (kill and quarantine on new findings only)
	killActions := checks.AutoKillProcesses(d.cfg, newFindings)
	quarantineActions := checks.AutoQuarantineFiles(d.cfg, newFindings)
	// Auto-block uses ALL findings — reputation IPs must be blocked even if previously seen
	blockActions := checks.AutoBlockIPs(d.cfg, findings)
	newFindings = append(newFindings, killActions...)
	newFindings = append(newFindings, quarantineActions...)
	newFindings = append(newFindings, blockActions...)

	// Correlation
	extra := checks.CorrelateFindings(newFindings)
	now := time.Now()
	for i := range extra {
		if extra[i].Timestamp.IsZero() {
			extra[i].Timestamp = now
		}
	}
	newFindings = append(newFindings, extra...)

	// Dispatch
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

// deepScanner runs reduced deep checks every 60 minutes.
// Only checks that fanotify can't replace: WP core, RPM, nulled plugins, open_basedir, symlinks.
func (d *Daemon) deepScanner() {
	defer d.wg.Done()

	ticker := time.NewTicker(60 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			// Only run the checks fanotify can't replace
			findings := checks.RunReducedDeep(d.cfg, d.store)
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
	for _, f := range findings {
		d.alertCh <- f
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
