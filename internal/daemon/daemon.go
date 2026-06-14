package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
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
	"github.com/pidginhost/csm/internal/auditd"
	"github.com/pidginhost/csm/internal/broadcast"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailav"
	"github.com/pidginhost/csm/internal/emailspool"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/firewall/rollback"
	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/integrity"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/sdnotify"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/threatintel"
	"github.com/pidginhost/csm/internal/updatecheck"
	"github.com/pidginhost/csm/internal/verdict"
	"github.com/pidginhost/csm/internal/webui"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraworker"
)

const eximMainlogPath = "/var/log/exim_mainlog"

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
	controlListener  *ControlListener
	spoolWatcher     *SpoolWatcher
	spoolWatcherMu   sync.Mutex
	forwarderWatcher *ForwarderWatcher
	emailQuarantine  *emailav.Quarantine
	webServer        *webui.Server
	challengeServer  *challenge.Server
	ipList           *challenge.IPList
	challengeGate    challenge.PortGate
	fwEngine         *firewall.Engine
	baselineMu       sync.Mutex // serialises CmdBaseline handler runs
	geoipDB          *geoip.DB
	geoipMu          sync.Mutex // protects geoipDB for publishGeoIP
	version          string
	alertCh          chan alert.Finding
	droppedAlerts    int64 // atomic counter for alert channel backpressure drops
	stopCh           chan struct{}
	scanCtx          context.Context
	scanCancel       context.CancelFunc // cancels in-flight periodic scans on shutdown
	abuseReportStop  chan struct{}
	abuseReportDone  chan struct{}
	wg               sync.WaitGroup
	smtpAuthTracker  *smtpAuthTracker
	smtpProbeTracker *smtpProbeTracker
	mailAuthTracker  *mailAuthTracker
	startTime        time.Time

	// yaraSup is the supervised YARA-X worker, wired up when
	// yaraWorkerOn(cfg) is true (the default; see ROADMAP item 2).
	// Nil when the in-process scanner is in use
	// (cfg.Signatures.YaraWorkerEnabled explicitly set to false).
	yaraSup            *yaraworker.Supervisor
	yaraCrashMu        sync.Mutex
	yaraLastCrashAlert time.Time

	// forceFullRescan is armed by the signature watcher
	// (sig_watch.go) when any tracked rule file's mtime advances.
	// The deep-tier scheduler reads + clears the flag at the start
	// of each tick; when set, the tick bypasses the fanotify
	// short-list and runs the full account tree against the new
	// ruleset.
	forceFullRescan atomic.Bool

	// policies holds the email PHP-relay pattern policies
	// (suspicious/safe x-mailer classes, HTTP proxy ranges) loaded
	// from EmailProtection.PHPRelay.PoliciesDir. Initialised in O2
	// (daemon wiring); stays nil until then. The SIGHUP path
	// nil-guards the Reload call so this commit is a no-op at
	// runtime until O2 lands.
	policies *emailspool.Policies

	// botVerifier is the async rDNS bot verifier. Retained so the SIGHUP
	// path can push reloaded reputation.verified_bots into it. nil when
	// bot verification is disabled or no store is available.
	botVerifier *threatintel.AsyncBotVerifier

	// PHP-relay components wired by startPHPRelay (Linux only). The fields are
	// declared cross-platform but stay nil on non-cPanel or non-Linux hosts.
	autoFreezer      *autoFreezer
	phpRelayShutdown []func() // ordered shutdown hooks

	// watcherStatus tracks which top-level watchers have successfully attached.
	// Keys are short stable names ("fanotify", "audit", "spool", "modsec",
	// "afalg"). Values flip from false-to-true when the watcher's setup
	// function completes without error. Used by /api/v1/status and the
	// sd_notify gate.
	//
	// watcherChangedAt records the wall-clock time of the most recent state
	// transition for the same key. Driven from MarkWatcher; consumed by the
	// /api/v1/components endpoint so operators can see how long a watcher
	// has been in its current state.
	watcherMu        sync.RWMutex
	watcherStatus    map[string]bool
	watcherChangedAt map[string]time.Time
	// watcherUpstream maps a watcher name to a probe function that reports
	// whether the upstream feeding the watcher is still active. The probe
	// runs at most once per /api/v1/components scrape; results compose with
	// WatcherStatuses to surface "deaf" (attached but no upstream traffic)
	// distinct from "idle" (attached and quiet) in the dashboard.
	watcherUpstream map[string]UpstreamProbe

	// findingBus fans out dispatched findings to passive observers like
	// the SSE event stream. Initialized in Run(); closed on shutdown.
	findingBus *broadcast.Bus

	// updateChecker polls upstream for new CSM releases. Wired in Run()
	// when updates.check_enabled is true (default). Nil when disabled
	// or before Run starts; UpdateInfo() handles that.
	updateChecker *updatecheck.Checker

	// lastAutomationActionCache memoises the newest automation-emitted
	// finding so /api/v1/status does not run a 100-row history cursor on
	// every poll. Invalidated after lastAutomationActionTTL elapses.
	automationActionMu     sync.Mutex
	automationActionCache  *health.AutomationAction
	automationActionCached time.Time
}

const lastAutomationActionTTL = 5 * time.Second

// New creates a new daemon instance.
func New(cfg *config.Config, store *state.Store, lock *state.LockFile, binaryPath string) *Daemon {
	d := &Daemon{
		cfg:        cfg,
		store:      store,
		lock:       lock,
		binaryPath: binaryPath,
		alertCh:    make(chan alert.Finding, 500),
		stopCh:     make(chan struct{}),
	}
	d.smtpAuthTracker = newSMTPAuthTracker(
		cfg.Thresholds.SMTPBruteForceThreshold,
		cfg.Thresholds.SMTPBruteForceSubnetThresh,
		cfg.Thresholds.SMTPAccountSprayThreshold,
		time.Duration(cfg.Thresholds.SMTPBruteForceWindowMin)*time.Minute,
		time.Duration(cfg.Thresholds.SMTPBruteForceSuppressMin)*time.Minute,
		cfg.Thresholds.SMTPBruteForceMaxTracked,
		time.Now,
	)
	d.smtpProbeTracker = newSMTPProbeTracker(
		cfg.Thresholds.SMTPProbeThreshold,
		time.Duration(cfg.Thresholds.SMTPProbeWindowMin)*time.Minute,
		time.Duration(cfg.Thresholds.SMTPProbeSuppressMin)*time.Minute,
		cfg.Thresholds.SMTPProbeMaxTracked,
		time.Now,
		smtpProbeBlockExpiryString,
	)
	d.mailAuthTracker = newMailAuthTracker(
		cfg.Thresholds.MailBruteForceThreshold,
		cfg.Thresholds.MailBruteForceSubnetThresh,
		cfg.Thresholds.MailAccountSprayThreshold,
		time.Duration(cfg.Thresholds.MailBruteForceWindowMin)*time.Minute,
		time.Duration(cfg.Thresholds.MailBruteForceSuppressMin)*time.Minute,
		cfg.Thresholds.MailBruteForceMaxTracked,
		time.Now,
	)
	return d
}

// SetVersion sets the application version for display in the web UI.
func (d *Daemon) SetVersion(v string) {
	d.version = v
}

// MarkWatcher records the attachment state of a named watcher.
// Call from each watcher's startup path: true on success, false on failure.
// The first record and any subsequent state transition stamps
// watcherChangedAt so the components view can show "since".
func (d *Daemon) MarkWatcher(name string, attached bool) {
	d.watcherMu.Lock()
	defer d.watcherMu.Unlock()
	if d.watcherStatus == nil {
		d.watcherStatus = make(map[string]bool)
	}
	if d.watcherChangedAt == nil {
		d.watcherChangedAt = make(map[string]time.Time)
	}
	prev, existed := d.watcherStatus[name]
	if !existed || prev != attached {
		d.watcherChangedAt[name] = time.Now()
	}
	d.watcherStatus[name] = attached
}

// WatcherStatuses returns a snapshot of every recorded watcher.
func (d *Daemon) WatcherStatuses() map[string]bool {
	d.watcherMu.RLock()
	defer d.watcherMu.RUnlock()
	out := make(map[string]bool, len(d.watcherStatus))
	for k, v := range d.watcherStatus {
		out[k] = v
	}
	return out
}

// WatcherChangedAt returns the wall-clock time at which each watcher last
// transitioned state. Watchers without a recorded change return the zero
// value.
func (d *Daemon) WatcherChangedAt() map[string]time.Time {
	d.watcherMu.RLock()
	defer d.watcherMu.RUnlock()
	out := make(map[string]time.Time, len(d.watcherChangedAt))
	for k, v := range d.watcherChangedAt {
		out[k] = v
	}
	return out
}

// UpstreamProbe reports whether a watcher's upstream input source is
// still feeding it. Return Fresh=false when the watcher is attached but
// can no longer hear from its source (PAM module not installed, log file
// rotated and never reappeared, fanotify marks lost, etc.) so the
// dashboard can surface "deaf" instead of conflating it with "idle".
type UpstreamProbe func() health.UpstreamResult

// RegisterUpstreamProbe wires a probe for a named watcher. Safe to call
// from any watcher's startup path; repeated calls overwrite the previous
// probe. Probes run on the request thread of /api/v1/components, so they
// must be cheap (single stat / atomic load, not a syscall storm).
func (d *Daemon) RegisterUpstreamProbe(name string, probe UpstreamProbe) {
	d.watcherMu.Lock()
	defer d.watcherMu.Unlock()
	if d.watcherUpstream == nil {
		d.watcherUpstream = make(map[string]UpstreamProbe)
	}
	d.watcherUpstream[name] = probe
}

// WatcherUpstream returns a snapshot of every probed watcher's upstream
// state. Watchers without a registered probe are absent from the map; the
// components API treats absence as "no probe wired, do not surface a
// deaf verdict for this watcher".
func (d *Daemon) WatcherUpstream() map[string]health.UpstreamResult {
	d.watcherMu.RLock()
	probes := make(map[string]UpstreamProbe, len(d.watcherUpstream))
	for k, v := range d.watcherUpstream {
		probes[k] = v
	}
	d.watcherMu.RUnlock()
	out := make(map[string]health.UpstreamResult, len(probes))
	for name, probe := range probes {
		if probe == nil {
			continue
		}
		out[name] = probe()
	}
	return out
}

// buildInfoOnce guards process-wide registration of the build_info
// gauge so repeated daemon construction in tests does not panic.
var buildInfoOnce sync.Once

// storeSizeOnce guards the csm_store_size_bytes gauge hook so tests
// that create multiple daemons share a single registration.
var storeSizeOnce sync.Once

// registerBuildInfo exposes build metadata on /metrics in the
// conventional Prometheus shape: a gauge fixed at 1, with the
// interesting fields as labels so scrapers can join on them.
func (d *Daemon) registerBuildInfo() {
	buildInfoOnce.Do(func() {
		g := metrics.NewGaugeVec(
			"csm_build_info",
			"CSM build metadata. Value is always 1; read version from the label.",
			[]string{"version"},
		)
		version := d.version
		if version == "" {
			version = "unknown"
		}
		g.With(version).Set(1)
		metrics.MustRegister("csm_build_info", g)
	})
}

// registerStoreSizeMetric exposes the bbolt on-disk size as a gauge
// that stats the file at scrape time. No caching: the expected scrape
// interval is 15+ seconds and stat is cheap.
func (d *Daemon) registerStoreSizeMetric() {
	storeSizeOnce.Do(func() {
		metrics.RegisterGaugeFunc(
			"csm_store_size_bytes",
			"On-disk size of the bbolt state database in bytes.",
			func() float64 {
				db := store.Global()
				if db == nil {
					return 0
				}
				info, err := os.Stat(db.Path())
				if err != nil {
					return 0
				}
				return float64(info.Size())
			},
		)
	})
}

// firewallMetricsOnce guards /metrics registration of the firewall +
// blocked-IP gauges so repeated daemon starts in a test binary are
// idempotent.
var firewallMetricsOnce sync.Once
var firewallMetricsMu sync.RWMutex
var firewallMetricsEngine *firewall.Engine

func setFirewallMetricsEngine(engine *firewall.Engine) {
	firewallMetricsMu.Lock()
	defer firewallMetricsMu.Unlock()
	firewallMetricsEngine = engine
}

func firewallMetricsRuleCounts() firewall.RuleCounts {
	firewallMetricsMu.RLock()
	engine := firewallMetricsEngine
	firewallMetricsMu.RUnlock()
	if engine == nil {
		return firewall.RuleCounts{}
	}
	return engine.RuleCounts()
}

func (d *Daemon) setFirewallEngine(engine *firewall.Engine) {
	d.fwEngine = engine
	setFirewallMetricsEngine(engine)
}

// registerFirewallMetrics exposes the count of blocked IPs and the
// total number of firewall rules (IPs + allowed + subnets + port
// allow entries). Both gauges read the firewall engine at scrape time:
// the engine state file is authoritative, while the parallel bbolt
// fw:* buckets are written only at migration, so reading the store
// would freeze the gauge at the migration-time snapshot.
func (d *Daemon) registerFirewallMetrics() {
	setFirewallMetricsEngine(d.fwEngine)
	firewallMetricsOnce.Do(func() {
		metrics.RegisterGaugeFunc(
			"csm_blocked_ips_total",
			"Number of IPs currently on the firewall block list (excluding expired temp bans).",
			func() float64 {
				return float64(firewallMetricsRuleCounts().Blocked)
			},
		)
		metrics.RegisterGaugeFunc(
			"csm_firewall_rules_total",
			"Total firewall rules across all categories (blocked IPs, allowed IPs, blocked subnets, port-specific allows).",
			func() float64 {
				return float64(firewallMetricsRuleCounts().Total())
			},
		)
	})
}

// Run starts the daemon and blocks until stopped.
func (d *Daemon) Run() error {
	d.startTime = time.Now()
	if d.store != nil {
		d.store.EnsureBaseline(d.startTime)
	}

	// Initialize structured logging from environment (CSM_LOG_FORMAT,
	// CSM_LOG_LEVEL). The default text handler preserves the legacy
	// "[YYYY-MM-DD HH:MM:SS] msg" format so operators mixing csmlog
	// with legacy fmt.Fprintf call sites see a uniform log stream.
	// CSM_LOG_FORMAT=json switches to structured JSON for log shipping.
	csmlog.Init()

	csmlog.Info("CSM daemon starting")

	// Periodic scans use this context so shutdown can abort an in-flight tier
	// instead of blocking the worker drain for the full check budget.
	scanCtx, scanCancel := context.WithCancel(context.Background())
	d.scanCtx = scanCtx
	d.scanCancel = scanCancel
	defer scanCancel()

	// Wire the active config to the incident-singleton's auto-close
	// loop BEFORE the singleton is constructed, so the loop reads the
	// operator-supplied thresholds on its first sweep. The closure
	// captures the Daemon to pick up reloaded configs without restart.
	SetIncidentConfigSource(func() *config.Config { return d.currentCfg() })

	// Initialize the findings broadcast bus so passive observers (SSE, etc.)
	// can subscribe before any findings are dispatched.
	d.findingBus = broadcast.NewBus(64)
	alert.FindingBus = d.findingBus

	// Install config-supplied platform overrides BEFORE the first Detect()
	// call so every check sees the merged view. Must happen before any
	// other code calls platform.Detect() in this daemon run.
	//
	// WebServer is a *platform.WebServer pointer — take address only when
	// the operator actually supplied a non-empty type, otherwise leave
	// the auto-detected value alone.
	var wsOverride *platform.WebServer
	if t := d.cfg.WebServer.Type; t != "" {
		ws := platform.WebServer(t)
		wsOverride = &ws
	}
	platform.SetOverrides(platform.Overrides{
		WebServer:           wsOverride,
		ApacheConfigDir:     d.cfg.WebServer.ConfigDir,
		AccessLogPaths:      d.cfg.WebServer.AccessLogs,
		ErrorLogPaths:       d.cfg.WebServer.ErrorLogs,
		ModSecAuditLogPaths: d.cfg.WebServer.ModSecAudits,
		DomlogGlobs:         d.cfg.WebServer.DomlogGlobs,
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

	// Build the ModSec rule-action registry before any log watcher starts
	// so the LiteSpeed classifier can tell pass-action vendor rules apart
	// from real denies on the very first parsed line.
	d.initModSecRegistry()

	// Wire the firewall tentative-apply manager. Recovery has to run
	// before integrity.Verify because a pending rollback whose deadline
	// passed while the daemon was down restores the previous csm.yaml
	// (and its integrity hash) to disk; verifying first would fail
	// against the still-on-disk new config the operator never confirmed.
	if sdb := store.Global(); sdb != nil {
		mgr := rollback.NewManager(sdb, d.cfg.ConfigFile, rollback.SystemctlRestart, time.Now)
		rollback.SetGlobal(mgr)
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		reverted, rerr := mgr.RecoverOnStartup(recoveryCtx)
		cancel()
		if rerr != nil {
			return fmt.Errorf("firewall rollback recovery failed: %w", rerr)
		}
		if reverted {
			csmlog.Warn("firewall rollback expired during downtime; previous config restored, restart issued")
			// systemctl restart csm.service from the manager will tear
			// us down momentarily; bail out cleanly so we do not race
			// the watchers we are about to start against the restart.
			return nil
		}
	}

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

	// Publish the verified config as the process-wide live pointer.
	// Hot paths (check ticks, alert dispatch, etc.) call
	// config.Active() to pick up the current snapshot so a SIGHUP
	// reload is visible on the next call without restart.
	publishActiveConfig(d.cfg, "startup")

	// Install the mail-brute account-key extractor selected by config.
	// Validation in config.Load() already rejected invalid specs, so the
	// error path here is defense-in-depth only.
	if err := installAccountExtractorFromConfig(d.cfg); err != nil {
		return err
	}

	// Self-heal the auditd rules file. Package upgrades sometimes ship
	// a new csm binary without re-running auditd.Deploy() (postinstall
	// hooks differ across apt/dnf and across operator deploy automation),
	// which leaves new rules — including detection layers like
	// csm_af_alg_socket — silently inactive on the upgraded host. The
	// startup compare-and-redeploy here closes that gap. Errors are
	// non-fatal: if auditd is absent or augenrules fails, the rest of
	// CSM still runs.
	if redeployed, err := auditd.EnsureDeployed(); err != nil {
		csmlog.Warn("auditd rules ensure failed", "err", err)
	} else if redeployed {
		csmlog.Info("auditd rules redeployed (drift from embedded constant)")
	}

	// Deploy WHM plugin and configs if cPanel is present
	deployConfigs()

	// Initialize signature scanners and threat DB (fast, no I/O scan)
	d.registerBuildInfo()
	d.registerStoreSizeMetric()
	d.registerFirewallMetrics()
	checks.RegisterDirectSMTPEgressMetrics(metrics.Default())
	RegisterBPFEnforcementMetrics(metrics.Default())
	if err := d.initYaraBackend(); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] YARA backend init: %v\n", ts(), err)
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

	// Construct the incident correlator after the firewall starts so the
	// credential_spray block hand-off is installed before the singleton
	// captures its config. This still happens before any finding is
	// dispatched.
	_ = IncidentCorrelator()

	// Start challenge server if enabled (gray listing)
	d.startChallengeServer()

	// Start challenge escalation ticker
	if d.ipList != nil {
		d.wg.Add(1)
		obs.Go("challenge-escalator", d.challengeEscalator)
	}

	// Create password hijack detector
	d.hijackDetector = NewPasswordHijackDetector(d.cfg, d.alertCh, d.stopCh)

	// Start inotify log watchers
	d.startLogWatchers()

	// Start PAM listener for real-time brute-force detection
	d.startPAMListener()

	// Start control socket listener for the thin-client CLI. The
	// daemon is the sole bbolt owner; CLI commands that previously
	// raced for the lock now route through this socket.
	d.startControlListener()

	// Start fanotify file monitor (real-time detection starts immediately)
	d.startFileMonitor()

	// Start email AV spool watcher (separate fanotify for Exim spool).
	// Spool and forwarder watchers are cPanel-only; they watch paths
	// (/var/spool/exim, /etc/valiases) that only exist on cPanel hosts.
	if platform.Detect().IsCPanel() {
		d.startSpoolWatcher()
		d.startForwarderWatcher()
	}

	// Wire the update checker before the Web UI starts so the
	// /api/v1/status handler always sees a non-nil checker (the
	// goroutine that polls upstream still warms up for 5 minutes
	// before the first poll, but UpdateInfo() returns zero values
	// without racing on the field assignment).
	d.startUpdateChecker()

	// Start Web UI server - available immediately, before initial scan
	d.startWebUI()

	// Wire email quarantine to web server (after both start)
	d.syncEmailAVWebState()

	// Initialize GeoIP databases (after webServer so SetGeoIPDB can attach)
	d.initGeoIP()

	// Signal systemd we're up as soon as the real-time watchers and the
	// control surfaces are attached. The initial baseline scan, the
	// kernel-state probes, and the BPF tracker wiring below all run
	// inline but no longer block `systemctl is-active` / `systemctl
	// restart`. The watchdog notifier has to start in the same step so
	// systemd's WatchdogSec doesn't trip while the baseline scan is
	// still running on a large host.
	d.wg.Add(1)
	obs.Go("watchdog-notifier", d.watchdogNotifier)

	if sent, err := sdnotify.Ready(); err != nil {
		fmt.Fprintf(os.Stderr, "sd_notify READY failed: %v\n", err)
	} else if sent {
		fmt.Fprintf(os.Stderr, "sd_notify: daemon ready\n")
	}
	_, _ = sdnotify.Status(fmt.Sprintf("watchers attached: %d", countAttachedWatchers(d.WatcherStatuses())))

	// Reconcile the opt-in email forward-guard to the current config (installs
	// the exim rule when enabled+enforcing, removes it otherwise), then keep its
	// bad-IP lookup fresh. Both no-op off cPanel and fail open on error.
	d.reconcileForwardGuard()
	d.wg.Add(1)
	obs.Go("forward-guard-refresh", d.forwardGuardRefresher)

	// Snapshot the live config ONCE for the entire initial-scan tick
	// (detection + auto-response). Earlier code called d.currentCfg()
	// for RunTier and then again later for the auto-response batch;
	// a SIGHUP landing between the two reads split the same tick
	// across old detection policy and new response policy.
	initialCfg := d.currentCfg()

	// Run initial scan synchronously (before dispatcher starts)
	fmt.Fprintf(os.Stderr, "[%s] Running initial baseline scan...\n", ts())
	initialFindings, initialPurge := checks.RunTierWithContext(d.scanContext(), initialCfg, d.store, checks.TierCritical)

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
	permActions, permFixedKeys := checks.AutoFixPermissions(initialCfg, initialAutoResponseFindings)

	// Challenge routing runs on ALL findings unconditionally when enabled, so an
	// eligible IP is on the challenge list before AutoBlockIPs (below, guarded by
	// newFindings) checks membership. Not folded into ChallengeThenBlock here:
	// challenge must route even with no new findings (re-establishing challenges
	// on restart) while the block stage stays gated on new findings.
	challengeActions := checks.ChallengeRouteIPs(initialCfg, initialAutoResponseFindings)

	// Other auto-response only on new findings
	if len(newFindings) > 0 {
		killActions := checks.AutoKillProcesses(initialCfg, newFindings)
		quarantineActions := checks.AutoQuarantineFiles(initialCfg, newFindings)
		blockActions := checks.AutoBlockIPs(initialCfg, initialAutoResponseFindings)
		newFindings = append(newFindings, killActions...)
		newFindings = append(newFindings, quarantineActions...)
		newFindings = append(newFindings, permActions...)
		newFindings = append(newFindings, challengeActions...)
		newFindings = append(newFindings, blockActions...)
		// Cross-account correlation runs on the initial batch too, not
		// just on subsequent ticks. Otherwise three account compromises
		// landing in the first scan slip past with no synthetic alert.
		newFindings = expandWithCorrelation(newFindings, time.Now())
		co := IncidentCorrelator()
		for _, f := range newFindings {
			_, _, _ = co.OnFinding(f)
		}
		_ = alert.Dispatch(initialCfg, newFindings)
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
	d.store.MarkAlerted(newFindings)
	// Merge initial scan findings into the existing set. Previous deep scan
	// results (outdated_plugins, wp_core, etc.) persist across restarts until
	// the next deep scan replaces them. ClearLatestFindings is NOT called
	// here - it would wipe deep scan findings that haven't re-run yet.
	checks.StoreLatestScanFindings(d.store, initialPurge, initialFindings)
	csmlog.Info("initial scan complete", "findings", len(initialFindings), "new", len(newFindings))

	// NOW start the alert dispatcher - no more race with initial scan
	d.wg.Add(1)
	obs.Go("alert-dispatcher", d.alertDispatcher)

	// Retrospective cloud-relay scan: replay the last 24h of exim_mainlog
	// through the compromise-detection rule so any in-progress credential
	// abuse is surfaced within seconds of daemon start, not after the
	// realtime watcher sees a new line. Gated on cPanel because
	// exim_mainlog is cPanel-specific; safe to run in a goroutine so
	// startup isn't delayed by parsing a large log.
	if platform.Detect().IsCPanel() {
		d.wg.Add(1)
		obs.Go("cloud-relay-retro-scan", func() {
			defer d.wg.Done()
			cfg := d.currentCfg()
			retro := ScanEximHistoryForCloudRelay(cfg, "", time.Now(), 24*time.Hour)
			for _, f := range retro {
				// Enqueue the finding FIRST; only after it is
				// accepted by the dispatcher do we trigger the
				// account-suspend side-effect. This prevents a
				// silent mailbox suspension if the daemon begins
				// shutting down between these two operations.
				select {
				case d.alertCh <- f:
				case <-d.stopCh:
					return
				}
				sender := extractSenderFromCloudRelayMessage(f.Message)
				if sender == "" {
					continue
				}
				handleCloudRelayCredentialAbuse(cfg, sender)
			}
		})
	}

	// Start periodic scanners
	d.wg.Add(1)
	obs.Go("critical-scanner", d.criticalScanner)

	d.wg.Add(1)
	obs.Go("deep-scanner", d.deepScanner)

	// Async bot-rDNS verifier: runs PTR+forward-A verification for
	// claimed search-engine bot IPs that are not in a static range.
	// Gated on reputation.bot_verify_enabled (default true) and on a
	// non-nil store so the result can be persisted.
	// Operator-configured verified bots extend the built-in allowlist.
	// Install them before the verifier so ClaimedBotFromUA / classifyUA
	// recognise them even when rDNS verification is disabled.
	botEntries := verifiedBotEntries(d.cfg)
	threatintel.SetOperatorBots(botEntries)

	if d.cfg.BotVerifyEnabled() {
		if db := store.Global(); db != nil {
			ver := threatintel.OperatorBotsCacheVersion(threatintel.LogicVersion, botEntries)
			if dropped, err := db.EnsureBotVerifyLogicVersion(ver); err != nil {
				csmlog.Warn("bot-verify cache version check failed", "err", err)
			} else if dropped {
				csmlog.Info("bot-verify cache dropped after logic or verified_bots change")
			}
			d.startBotVerifier(db, botEntries)
		}
	}

	// Live AF_ALG listener (Copy Fail / CVE-2026-31431) — only started
	// when the kernel is actually exploitable. Hosts with a KernelCare
	// livepatch covering CVE-2026-31431, OR built without the AF_ALG
	// aead interface entirely, skip the listener: there's nothing to
	// detect, and the inotify watch + 500ms tick would just burn cycles.
	// The hardening audit + periodic critical-tier check stay active
	// either way, so re-introduction of the vulnerability (e.g., a
	// kernel rollback) is still surfaced via the slower path.
	kstate := checks.ObserveAFAlgKernelState()
	switch {
	case !kstate.IsCopyFailExploitable():
		csmlog.Info("af_alg live listener: skipped",
			"reason", "kernel not exploitable",
			"state", kstate.String(),
		)
	default:
		if mon := StartAFAlgLiveMonitor(d.alertCh, d.cfg); mon == nil {
			csmlog.Warn("af_alg live listener: not started",
				"reason", "no backend available",
				"state", kstate.String(),
			)
			d.MarkWatcher("afalg", false)
		} else {
			csmlog.Info("af_alg live listener: started",
				"backend", mon.Mode(),
				"state", kstate.String(),
			)
			d.wg.Add(1)
			obs.Go("af-alg-listener", func() {
				defer d.wg.Done()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go func() { <-d.stopCh; cancel() }()
				mon.Run(ctx)
			})
			d.MarkWatcher("afalg", true)
		}
	}

	d.startPHPRelay()

	if mon := StartConnectionTracker(d.alertCh, d.cfg); mon != nil {
		csmlog.Info("connection_tracker: started", "backend", mon.Mode())
		d.wg.Add(1)
		obs.Go("connection-tracker", func() {
			defer d.wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { <-d.stopCh; cancel() }()
			mon.Run(ctx)
		})
	}

	if mon := StartExecMonitor(d.alertCh, d.cfg); mon != nil {
		csmlog.Info("exec_monitor: started", "backend", mon.Mode())
		d.wg.Add(1)
		obs.Go("exec-monitor", func() {
			defer d.wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { <-d.stopCh; cancel() }()
			mon.Run(ctx)
		})
	}

	if mon := StartSensitiveFileMonitor(d.alertCh, d.cfg, d.store); mon != nil {
		csmlog.Info("sensitive_files: started", "backend", mon.Mode())
		d.wg.Add(1)
		obs.Go("sensitive-files", func() {
			defer d.wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { <-d.stopCh; cancel() }()
			mon.Run(ctx)
		})
	}

	// Start automatic signature updates
	d.wg.Add(1)
	obs.Go("signature-updater", d.signatureUpdater)

	// Start signature mtime watcher: arms forceFullRescan when any
	// rule file's mtime advances. Disabled wholesale via
	// detection.rescan_on_signature_update: false.
	d.wg.Add(1)
	obs.Go("signature-watcher", d.signatureWatcher)

	d.wg.Add(1)
	obs.Go("geoip-updater", d.geoipUpdater)

	// Start heartbeat
	d.wg.Add(1)
	obs.Go("heartbeat", d.heartbeat)

	// One-shot: stagger CSM-managed WP-Cron crontab lines left behind by
	// older releases. The perf_wp_cron finding never re-fires once a site
	// is fixed, so this is the only path that reaches them.
	d.wg.Add(1)
	obs.Go("wpcron-migrate", func() {
		defer d.wg.Done()
		if n := checks.MigrateWPCronCrontabs(d.cfg); n > 0 {
			csmlog.Info("wp-cron: staggered legacy system cron entries", "upgraded", n)
		}
	})

	// Start abuse reporting (opt-in). startAbuseReporting installs the alert
	// hook and returns the spool drain loop, or nil when disabled. The reporter
	// stops after the final shutdown alert flush so late findings can still be
	// queued before the bbolt spool closes.
	if reportLoop := d.startAbuseReporting(); reportLoop != nil {
		obs.Go("abuse-reporter", reportLoop)
	}

	// Start the central scored-set consumer (opt-in). Maintains the verified
	// set and escalates findings whose IP is listed; nil when disabled.
	if centralLoop := d.startCentralConsume(); centralLoop != nil {
		d.wg.Add(1)
		obs.Go("central-intel", func() {
			defer d.wg.Done()
			centralLoop()
		})
	}

	// Start the retention sweep only when opted in. Compaction is not
	// run from this goroutine; see internal/daemon/retention.go for why.
	if d.cfg != nil && d.cfg.Retention.Enabled {
		d.wg.Add(1)
		obs.Go("retention-scanner", d.retentionScanner)
	}

	// Refresh the sd_notify status line now that AF_ALG, BPF trackers,
	// and the periodic scanners have all reported in. The initial
	// READY=1 fired earlier so systemctl restart didn't have to wait
	// on the baseline scan; this is the operator-visible summary.
	_, _ = sdnotify.Status(fmt.Sprintf("watchers attached: %d", countAttachedWatchers(d.WatcherStatuses())))

	csmlog.Info("CSM daemon running")

	// Wait for signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			fmt.Fprintf(os.Stderr, "[%s] SIGHUP received - reloading config and rules\n", ts())
			d.reloadConfig()
			d.reloadSignatures()
			if d.policies != nil {
				if err := d.policies.Reload(d.cfg.EmailProtection.PHPRelay.PoliciesDir); err != nil {
					// Previous valid version stays in effect; surface the failure
					// via the existing alert pipeline so operators see partial reload.
					d.emitReloadFinding(alert.Warning, "email_php_relay_policies_reload",
						fmt.Sprintf("policies/email reload encountered errors: %v", err))
				}
			}
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
	shutdownStart := time.Now()
	close(d.stopCh)

	// Abort any in-flight periodic scan so d.wg.Wait below is not held for a
	// whole tier. Scanners observe d.stopCh between cycles; this cancels the
	// scan currently executing inside RunTier.
	if d.scanCancel != nil {
		d.scanCancel()
	}

	// Log watchers own their files and close them when their Run loop exits on
	// d.stopCh; d.wg.Wait below blocks until that happens. Calling Stop here
	// would race the still-running Run on w.file.
	if d.webServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = d.webServer.Shutdown(ctx)
		cancel()
	}
	if d.challengeServer != nil {
		d.challengeServer.Shutdown()
	}
	if d.challengeGate != nil {
		if err := d.challengeGate.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] challenge port-gate close: %v\n", ts(), err)
		}
		d.challengeGate = nil
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
	if d.controlListener != nil {
		d.controlListener.Stop()
	}
	d.stopYaraBackend()
	csmlog.Info("watchers signalled", "elapsed_ms", time.Since(shutdownStart).Milliseconds())

	d.wg.Wait()
	csmlog.Info("workers drained", "elapsed_ms", time.Since(shutdownStart).Milliseconds())
	// Some producers can finish a tick after alertDispatcher observes stopCh.
	// Drain again once tracked workers are gone and before state is closed.
	d.flushPendingAlertsOnShutdown()
	d.stopAbuseReporting()
	if d.findingBus != nil {
		d.findingBus.Close()
		alert.FindingBus = nil
	}
	for i := len(d.phpRelayShutdown) - 1; i >= 0; i-- {
		d.phpRelayShutdown[i]()
	}
	d.phpRelayShutdown = nil
	if adb := attackdb.Global(); adb != nil {
		adb.Stop()
	}
	// Stop the incident auto-close and retention goroutines before closing the
	// store so neither writes to an already-closed bbolt database.
	StopIncidentBackgroundLoops()
	if err := d.store.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] error closing state store: %v\n", ts(), err)
	}
	d.lock.Release()
	csmlog.Info("daemon stopped", "elapsed_ms", time.Since(shutdownStart).Milliseconds())
	fmt.Fprintf(os.Stderr, "[%s] CSM daemon stopped\n", ts())
	return nil
}

// DroppedAlerts returns the total number of alerts dropped due to
// channel backpressure since the daemon started.
func (d *Daemon) DroppedAlerts() int64 {
	return atomic.LoadInt64(&d.droppedAlerts)
}

func (d *Daemon) scanContext() context.Context {
	if d.scanCtx != nil {
		return d.scanCtx
	}
	return context.Background()
}

// FindingBus returns the per-daemon broadcast.Bus used by passive
// observers like the SSE event stream. Returns nil before Run starts.
func (d *Daemon) FindingBus() *broadcast.Bus {
	return d.findingBus
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
			batch = d.drainAlertChannel(batch)
			d.persistPendingFindingsOnShutdown(batch)
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

func (d *Daemon) drainAlertChannel(batch []alert.Finding) []alert.Finding {
	for {
		select {
		case f, ok := <-d.alertCh:
			if !ok {
				return batch
			}
			batch = append(batch, f)
		default:
			return batch
		}
	}
}

func (d *Daemon) flushPendingAlertsOnShutdown() {
	d.persistPendingFindingsOnShutdown(d.drainAlertChannel(nil))
}

// persistPendingFindingsOnShutdown records findings still queued at shutdown to
// the history log for forensics, then returns. It deliberately does NOT run the
// auto-response pipeline (nftables blocks, permission fixes, kill/quarantine,
// DB cleanup) or network alert dispatch: that work blocked the service stop for
// tens of seconds -- up to twice, once here and once in the dispatcher's stop
// branch -- while systemd waited. It is also redundant, because the next
// startup baseline scan re-detects and re-acts on the same conditions. Writing
// history only also leaves each finding re-alertable (it is not marked sent via
// store.Update), so the restart's dispatch is not suppressed.
func (d *Daemon) persistPendingFindingsOnShutdown(batch []alert.Finding) {
	if len(batch) == 0 {
		return
	}
	d.store.AppendHistory(batch)
}

func (d *Daemon) dispatchBatch(findings []alert.Finding) {
	// Snapshot the live config once at the top of the batch. Every
	// cfg.X read below picks up the last-reloaded value (ROADMAP
	// item 7); taking one snapshot avoids the weirder case of a
	// SIGHUP landing mid-batch and splitting some auto-response
	// actions between old and new policy.
	cfg := d.currentCfg()

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
	// One ordered helper guarantees that ordering on every auto-response path.
	challengeActions, blockActions := checks.ChallengeThenBlock(cfg, autoResponseFindings)
	permActions, permFixedKeys := checks.AutoFixPermissions(cfg, autoResponseFindings)

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

	// PHP-relay AutoFreeze: emit any new findings produced by post-emit
	// freeze decisions back into the dispatched batch so operators see
	// the action outcome alongside the original finding. Nil-guard for
	// non-cPanel / non-linux hosts where wiring is skipped.
	if d.autoFreezer != nil {
		if freezeFindings := d.autoFreezer.Apply(autoResponseFindings); len(freezeFindings) > 0 {
			newFindings = append(newFindings, freezeFindings...)
		}
	}

	if len(newFindings) == 0 {
		d.store.Update(findings)
		return
	}

	// Log to history
	d.store.AppendHistory(newFindings)

	// Kill, quarantine, and DB cleanup only run on NEW findings
	killActions := checks.AutoKillProcesses(cfg, newFindings)
	quarantineActions := checks.AutoQuarantineFiles(cfg, newFindings)
	dbCleanActions := checks.AutoRespondDBMalware(cfg, newFindings)
	newFindings = append(newFindings, killActions...)
	newFindings = append(newFindings, quarantineActions...)
	newFindings = append(newFindings, dbCleanActions...)

	// Correlation
	newFindings = expandWithCorrelation(newFindings, time.Now())

	co := IncidentCorrelator()
	for _, f := range newFindings {
		_, _, _ = co.OnFinding(f)
	}

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
		case "modsec_block_realtime", "modsec_warning_realtime", "modsec_block_escalation", "modsec_csm_block_escalation":
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
	if err := alert.Dispatch(cfg, alertable); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Alert dispatch error: %v\n", ts(), err)
	}

	d.store.Update(findings)
	d.store.MarkAlerted(newFindings)
}

// autoFixWPCron lets daemon wiring tests avoid real wp-config.php and crontab
// edits; the checks package covers those side effects directly.
var autoFixWPCron = checks.AutoFixWPCron

// processScanFindings handles the output of a deep or periodic scan: it persists
// the findings to the latest-findings surface, runs the auto-responses that act
// on warning-severity perf findings, then forwards the remaining findings to the
// alert dispatcher. Warning-severity perf findings stay off the alert channel so
// they never page an operator; that is exactly why the WP-Cron auto-fix runs
// here and not in dispatchBatch, which only ever sees what the channel carries.
func (d *Daemon) processScanFindings(cfg *config.Config, findings []alert.Finding, purgeChecks []string, label string) {
	checks.StoreLatestScanFindings(d.store, purgeChecks, findings)
	d.applyWPCronAutoFix(cfg, findings)
	d.enqueueScanAlerts(findings, label)
}

// enqueueScanAlerts forwards a scan's findings to the alert dispatcher.
// Warning-severity perf findings stay off the channel so they never page an
// operator; that is also why the WP-Cron auto-fix runs against the scan
// findings directly rather than in dispatchBatch, which only sees the channel.
func (d *Daemon) enqueueScanAlerts(findings []alert.Finding, label string) {
	for _, f := range findings {
		if strings.HasPrefix(f.Check, "perf_") && f.Severity == alert.Warning {
			continue
		}
		select {
		case d.alertCh <- f:
		default:
			atomic.AddInt64(&d.droppedAlerts, 1)
			fmt.Fprintf(os.Stderr, "[%s] alert channel full, dropping %s finding: %s\n", ts(), label, f.Check)
		}
	}
}

// applyWPCronAutoFix disables WP-Cron and installs a per-user system cron for
// every perf_wp_cron finding, then clears the fixed findings from the
// latest-findings surface and records the actions in history. Findings the
// operator has suppressed are left untouched, so a suppression also stops the
// automated edit of that account's wp-config.php.
func (d *Daemon) applyWPCronAutoFix(cfg *config.Config, findings []alert.Finding) {
	if d.store != nil {
		if suppressions := d.store.LoadSuppressions(); len(suppressions) > 0 {
			findings = filterUnsuppressedFindings(d.store, findings, suppressions)
		}
	}
	actions, fixedKeys := autoFixWPCron(cfg, findings)
	for _, key := range fixedKeys {
		d.store.DismissLatestFinding(key)
	}
	if len(actions) > 0 {
		d.store.AppendHistory(actions)
	}
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

	// Re-read the interval on each iteration so a SIGHUP that changes
	// thresholds.deep_scan_interval_min takes effect on the next scan.
	// A ticker captured at startup can't be re-sized cleanly without
	// a reset path; time.After recomputes.
	for {
		interval := time.Duration(d.currentCfg().Thresholds.DeepScanIntervalMin) * time.Minute
		if interval <= 0 {
			// Defensive: an operator who zeroes the threshold would
			// otherwise get a tight spin loop. 60 minutes matches the
			// default from config.Load.
			interval = 60 * time.Minute
		}

		select {
		case <-d.stopCh:
			return
		case <-time.After(interval):
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
			//
			// One exception: forceFullRescan is armed by the
			// signature watcher when any rule file's mtime advances.
			// In that case we bypass the fanotify short-list so the
			// new ruleset gets a full sweep against existing files;
			// without this, only files that change AFTER the rule
			// update would catch the new patterns.
			cfg := d.currentCfg()
			rescan := d.forceFullRescan.CompareAndSwap(true, false)
			var findings []alert.Finding
			var purgeChecks []string
			switch {
			case rescan:
				findings, purgeChecks = checks.RunTierWithContext(d.scanContext(), cfg, d.store, checks.TierDeep)
				observeSignatureRescan()
			case d.fileMonitor != nil:
				findings, purgeChecks = checks.RunReducedDeepWithContext(d.scanContext(), cfg, d.store)
			default:
				findings, purgeChecks = checks.RunTierWithContext(d.scanContext(), cfg, d.store, checks.TierDeep)
			}
			d.processScanFindings(cfg, findings, purgeChecks, "deep")
		}
	}
}

func (d *Daemon) runPeriodicChecks(tier checks.Tier) {
	// Snapshot the live config ONCE for the whole tick. Calling
	// d.currentCfg() twice (once for integrity, once for RunTier)
	// lets a SIGHUP land between the two reads and split the tick
	// between old-policy integrity verification and new-policy
	// detection. Matches the snapshot pattern in dispatchBatch.
	cfg := d.currentCfg()

	// Verify integrity against the snapshot. A SIGHUP reload re-signs
	// integrity.config_hash on disk and updates config.Active; using
	// d.cfg (the startup snapshot) here would fire a Critical tamper
	// alert on every tick after a successful reload because the stored
	// hash in d.cfg is stale. If a reload completes while Verify is
	// hashing, retry once against the latest live config to avoid a
	// false tamper alert from a stale snapshot.
	var err error
	cfg, err = d.verifyPeriodicIntegritySnapshot(cfg)
	if err != nil {
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

	// Age out stale dry-run-block records so the status surface
	// reflects recent activity instead of months-old entries left
	// over from a previous dry-run window. Keeping a 7-day rolling
	// window matches the operator workflow of reviewing a week of
	// would-have-been-blocks before flipping to live.
	if sdb := store.Global(); sdb != nil {
		sdb.PurgeDryRunBlocksOlderThan(time.Now().Add(-7 * 24 * time.Hour))
	}

	findings, purgeChecks := checks.RunTierWithContext(d.scanContext(), cfg, d.store, tier)
	d.processScanFindings(cfg, findings, purgeChecks, "periodic")
}

func (d *Daemon) verifyPeriodicIntegritySnapshot(cfg *config.Config) (*config.Config, error) {
	if err := integrity.Verify(d.binaryPath, cfg); err != nil {
		latest := d.currentCfg()
		if latest != nil && latest != cfg {
			retryErr := integrity.Verify(d.binaryPath, latest)
			if retryErr == nil {
				return latest, nil
			}
			return latest, retryErr
		}
		return cfg, err
	}
	return cfg, nil
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
			alert.SendHeartbeat(d.currentCfg())
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

// startPHPRelay implements the platform gate from Stage 1 spec section
// 9 (O1). Emits a Warning if the host is not cPanel; otherwise locates
// the exim binary for AutoFreeze and (in O2) wires the spool watcher,
// pipeline, and Flow E ticker.
func (d *Daemon) startPHPRelay() {
	info := platform.Detect()
	if !info.IsCPanel() {
		select {
		case d.alertCh <- alert.Finding{
			Severity:  alert.Warning,
			Check:     "email_php_relay_disabled",
			Message:   "php_relay disabled: not a cPanel host",
			Timestamp: time.Now(),
		}:
		default:
		}
		return
	}
	if !d.cfg.EmailProtection.PHPRelay.Enabled {
		return
	}
	if path, err := exec.LookPath("exim"); err == nil {
		eximBinary = path
	} else {
		select {
		case d.alertCh <- alert.Finding{
			Severity:  alert.Warning,
			Check:     "email_php_relay_no_exim",
			Message:   "php_relay auto-action disabled: exim binary not in PATH",
			Timestamp: time.Now(),
		}:
		default:
		}
	}
	// Bridge to the linux-only wiring (Phase O2). On non-linux GOOS
	// the stub in php_relay_wiring_other.go is a no-op.
	startPHPRelayLinux(d)
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
		name    string
		path    string
		handler func(string, *config.Config) []alert.Finding
	}
	var logFiles []logFile

	// Generic Linux auth log. RHEL-family uses /var/log/secure, Debian
	// family uses /var/log/auth.log. Only register the log appropriate
	// for the detected OS so we don't spam "not found, retrying" forever.
	if hostInfo.IsDebianFamily() {
		logFiles = append(logFiles, logFile{"", "/var/log/auth.log", parseSecureLogLine})
	} else {
		logFiles = append(logFiles, logFile{"", "/var/log/secure", parseSecureLogLine})
	}

	// eximHandler wraps parseEximLogLine (unchanged) and augments the result
	// with smtpAuthTracker findings for dovecot authenticator failures and
	// smtpProbeTracker findings for raw connect-rate abuse (scanners that
	// probe-and-disconnect without ever reaching AUTH).
	eximHandler := func(line string, cfg *config.Config) []alert.Finding {
		findings := parseEximLogLine(line, cfg)

		// Connect-rate signal fires before any AUTH attempt.
		if probeIP := parseEximSMTPConnectIP(line); probeIP != "" {
			if parsed := net.ParseIP(probeIP); parsed != nil {
				if v4 := parsed.To4(); v4 != nil {
					probeIP = v4.String()
				}
			}
			if !isInfraIPDaemon(probeIP, cfg.InfraIPs) && !isPrivateOrLoopback(probeIP) {
				if d.smtpProbeTracker != nil {
					findings = append(findings, d.smtpProbeTracker.Record(probeIP)...)
				}
			}
		}

		if strings.Contains(line, "authenticator failed") && strings.Contains(line, "dovecot") {
			ip := extractBracketedIP(line)
			account := extractSetID(line)

			// Canonicalize IPv4-mapped IPv6 (::ffff:a.b.c.d) to plain IPv4 so the
			// tracker doesn't double-count the same attacker as two IPs.
			if ip != "" {
				if parsed := net.ParseIP(ip); parsed != nil {
					if v4 := parsed.To4(); v4 != nil {
						ip = v4.String()
					}
				}
			}

			if ip != "" && !isInfraIPDaemon(ip, cfg.InfraIPs) && !isPrivateOrLoopback(ip) {
				if d.smtpAuthTracker != nil {
					findings = append(findings, d.smtpAuthTracker.Record(ip, account)...)
				}
			}
		}
		return findings
	}

	// mailHandler composes parseDovecotLogLine (preserving email_suspicious_geo)
	// with mailAuthTracker augmentation for IMAP/POP3/ManageSieve brute-force,
	// subnet spray, account spray, and compromise detection.
	mailHandler := func(line string, cfg *config.Config) []alert.Finding {
		findings := parseDovecotLogLine(line, cfg)
		if !isMailAuthLine(line) {
			return findings
		}
		ip, account, success := extractMailLoginEvent(line)
		if ip == "" {
			return findings
		}
		if parsed := net.ParseIP(ip); parsed != nil {
			if v4 := parsed.To4(); v4 != nil {
				ip = v4.String()
			}
		}
		if isInfraIPDaemon(ip, cfg.InfraIPs) || isPrivateOrLoopback(ip) {
			return findings
		}
		if d.mailAuthTracker == nil {
			return findings
		}
		if success {
			findings = append(findings, d.mailAuthTracker.RecordSuccess(ip, account)...)
		} else {
			findings = append(findings, d.mailAuthTracker.Record(ip, account)...)
		}
		return findings
	}

	// cPanel-specific logs only watch these on cPanel hosts. On plain
	// Ubuntu/AlmaLinux they do not exist and the old code spammed
	// "not found, will retry every 60s" forever.
	if hostInfo.IsCPanel() {
		logFiles = append(logFiles,
			logFile{"", "/usr/local/cpanel/logs/session_log", sessionHandler},
			logFile{"", "/usr/local/cpanel/logs/access_log", parseAccessLogLineEnhanced},
			logFile{"", "/var/log/messages", parseFTPLogLine},
		)
	}
	if shouldWatchEximMainlog(hostInfo, os.Stat) {
		logFiles = append(logFiles, logFile{"", eximMainlogPath, eximHandler})
	}

	// Mail-log reader: factory selects file vs journal based on cfg.MailLogs.
	// Replaces the old cPanel-only /var/log/maillog registration; now works
	// on all platforms using the platform-default path or journal fallback.
	{
		mailReader, mlErr := maillog.New(d.cfg.MailLogs, hostInfo.MailLogPath())
		if mlErr != nil {
			csmlog.Warn("mail log reader disabled", "err", mlErr)
			d.MarkWatcher("maillog", false)
		} else {
			// A file-backed reader can go dark if its log path disappears
			// mid-run (syslog->journald migration). Surface that instead of
			// silently tailing a dead fd: mark the watcher unhealthy and
			// emit a finding so the operator knows mail detection degraded.
			if fr, ok := mailReader.(*maillog.FileReader); ok {
				fr.SetOnGone(d.handleMailLogSourceGone)
				fr.SetOnRestored(d.handleMailLogSourceRestored)
			}
			ctx, cancel := context.WithCancel(context.Background())
			go func() { <-d.stopCh; cancel() }()
			mailLines, mlErr := mailReader.Run(ctx)
			if mlErr != nil {
				cancel()
				csmlog.Warn("mail log reader failed to start", "err", mlErr)
				d.MarkWatcher("maillog", false)
			} else {
				d.MarkWatcher("maillog", true)
				d.wg.Add(1)
				obs.Go("maillog-consumer", func() {
					defer d.wg.Done()
					for line := range mailLines {
						if !d.dispatchMailLogLine(line, mailHandler) {
							return
						}
					}
				})
			}
		}
	}

	// Only watch PHP Shield events if enabled in config
	if d.cfg.PHPShield.Enabled {
		logFiles = append(logFiles, logFile{"", phpEventsLogPath, parsePHPShieldLogLine})
	}

	// ModSecurity error log - auto-discover path based on detected web server.
	if modsecPath := discoverModSecLogPath(d.cfg); modsecPath != "" {
		logFiles = append(logFiles, logFile{"modsec", modsecPath, parseModSecLogLineDeduped})
	} else if hostInfo.WebServer != platform.WSNone {
		// Only bother with the retry loop if a web server is actually
		// present. Headless hosts don't need this.
		fmt.Fprintf(os.Stderr, "[%s] ModSecurity error log not found (checked %v), will retry every 60s\n", ts(), hostInfo.ErrorLogPaths)
		d.MarkWatcher("modsec", false)
		d.wg.Add(1)
		obs.Go("logwatch-modsec-retry", func() {
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
					obs.Go("logwatch-modsec", func() {
						defer d.wg.Done()
						w.Run(d.stopCh)
					})
					csmlog.Info("watching log (appeared after retry)", "path", path)
					d.MarkWatcher("modsec", true)
					return
				}
			}
		})
	}

	// Real-time access log watcher for wp-login/xmlrpc brute force detection.
	// Auto-discover path from platform info (Apache/Nginx/cPanel aware).
	if accessLogPath := discoverAccessLogPath(); accessLogPath != "" {
		logFiles = append(logFiles, logFile{"", accessLogPath, parseAccessLogBruteForce})
	} else if hostInfo.WebServer != platform.WSNone && len(hostInfo.AccessLogPaths) > 0 {
		csmlog.Warn("access log not found, will retry every 60s", "candidates", fmt.Sprintf("%v", hostInfo.AccessLogPaths))
		d.wg.Add(1)
		accessPath := hostInfo.AccessLogPaths[0]
		obs.Go("logwatch-access-retry", func() { d.retryLogWatcher(accessPath, parseAccessLogBruteForce) })
	}

	// Start background eviction for modsec dedup/escalation state
	StartModSecEviction(d.stopCh, func() *config.Config { return d.currentCfg() })

	// Start background eviction for access log brute force state
	StartAccessLogEviction(d.stopCh)

	// Start background eviction for email rate limiting state
	StartEmailRateEviction(d.stopCh)

	// Start background eviction for cloud-relay per-user windows so the
	// sync.Map does not grow linearly with every distinct authenticated
	// sender ever seen.
	StartCloudRelayEviction(d.stopCh)

	// Start background purge for SMTP brute-force tracker
	d.wg.Add(1)
	obs.Go("smtp-tracker-purge", func() {
		defer d.wg.Done()
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		tick := 0
		for {
			select {
			case <-d.stopCh:
				return
			case <-ticker.C:
				if d.smtpAuthTracker != nil {
					d.smtpAuthTracker.Purge()
				}
				if d.smtpProbeTracker != nil {
					d.smtpProbeTracker.Purge()
				}
				// Diagnostic: surface whether the SMTP/mail brute-force
				// trackers are actually seeing auth failures and emitting
				// blockable findings. A nonzero record_calls with zero
				// findings_emitted over a sustained attack means the
				// threshold path, not the wiring, is the gap to chase.
				tick++
				if tick%10 == 0 {
					if d.smtpAuthTracker != nil {
						sc, se := d.smtpAuthTracker.Stats()
						csmlog.Info("smtp brute tracker stats",
							"record_calls", sc, "findings_emitted", se, "tracked", d.smtpAuthTracker.Size())
					}
					if d.mailAuthTracker != nil {
						mc, me := d.mailAuthTracker.Stats()
						csmlog.Info("mail brute tracker stats",
							"record_calls", mc, "findings_emitted", me, "tracked", d.mailAuthTracker.Size())
					}
				}
			}
		}
	})

	// Start background purge for mail (IMAP/POP3) brute-force tracker
	d.wg.Add(1)
	obs.Go("mail-tracker-purge", func() {
		defer d.wg.Done()
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-d.stopCh:
				return
			case <-ticker.C:
				if d.mailAuthTracker != nil {
					d.mailAuthTracker.Purge()
				}
			}
		}
	})

	for _, lf := range logFiles {
		w, err := NewLogWatcher(lf.path, d.cfg, lf.handler, d.alertCh)
		if err != nil {
			if os.IsNotExist(err) {
				// File doesn't exist yet - retry periodically until it appears
				if lf.name != "" {
					d.MarkWatcher(lf.name, false)
				}
				d.wg.Add(1)
				path, handler, name := lf.path, lf.handler, lf.name
				obs.Go("logwatch-retry", func() { d.retryLogWatcherNamed(path, handler, name) })
			} else {
				fmt.Fprintf(os.Stderr, "[%s] Warning: could not watch %s: %v\n", ts(), lf.path, err)
				if lf.name != "" {
					d.MarkWatcher(lf.name, false)
				}
			}
			continue
		}
		d.logWatchers = append(d.logWatchers, w)
		d.wg.Add(1)
		watcher := w
		obs.Go("logwatch", func() {
			defer d.wg.Done()
			watcher.Run(d.stopCh)
		})
		csmlog.Info("watching log", "path", lf.path)
		if lf.name != "" {
			d.MarkWatcher(lf.name, true)
		}
	}
}

func (d *Daemon) handleMailLogSourceGone(err error) {
	d.MarkWatcher("maillog", false)
	finding := alert.Finding{
		Severity:  alert.Warning,
		Check:     "mail_log_source_unavailable",
		Message:   fmt.Sprintf("Mail log source unavailable: %v; brute-force and rate detection degraded until it returns or the daemon restarts", err),
		Timestamp: time.Now(),
	}
	select {
	case d.alertCh <- finding:
	case <-d.stopCh:
	default:
		atomic.AddInt64(&d.droppedAlerts, 1)
		fmt.Fprintf(os.Stderr, "[%s] alert channel full, dropping maillog source finding\n", ts())
	}
}

func (d *Daemon) handleMailLogSourceRestored() {
	d.MarkWatcher("maillog", true)
}

func (d *Daemon) dispatchMailLogLine(line maillog.Line, handler LogLineHandler) bool {
	findings := handler(line.Message, d.currentCfg())
	for _, f := range findings {
		select {
		case d.alertCh <- f:
		case <-d.stopCh:
			return false
		}
	}
	return true
}

// retryLogWatcher polls for a missing log file every 60 seconds.
// When the file appears, it starts a watcher and returns.
func (d *Daemon) retryLogWatcher(path string, handler LogLineHandler) {
	d.retryLogWatcherNamed(path, handler, "")
}

func shouldWatchEximMainlog(hostInfo platform.Info, stat func(string) (os.FileInfo, error)) bool {
	if hostInfo.IsCPanel() {
		return true
	}
	if stat == nil {
		stat = os.Stat
	}
	if _, err := stat(eximMainlogPath); err != nil {
		return !os.IsNotExist(err)
	}
	return true
}

func (d *Daemon) retryLogWatcherNamed(path string, handler LogLineHandler, name string) {
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
			watcher := w
			obs.Go("logwatch-late", func() {
				defer d.wg.Done()
				watcher.Run(d.stopCh)
			})
			csmlog.Info("watching log (appeared after retry)", "path", path)
			if name != "" {
				d.MarkWatcher(name, true)
			}
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
	srv.SetHealthProvider(d)
	srv.SetFindingBus(d.findingBus)
	srv.SetIncidentCorrelator(IncidentCorrelator())
	d.logWatchersMu.Lock()
	numWatchers := len(d.logWatchers)
	d.logWatchersMu.Unlock()
	srv.SetHealthInfo(d.fileMonitor != nil, numWatchers)
	if d.fwEngine != nil {
		srv.SetIPBlocker(d.fwEngine)
	}
	d.wg.Add(1)
	obs.Go("webui", func() {
		defer d.wg.Done()
		if err := srv.Start(); err != nil {
			csmlog.Error("webui server error", "err", err)
		}
	})
}

func (d *Daemon) startPAMListener() {
	pl, err := NewPAMListener(d.cfg, d.alertCh)
	if err != nil {
		csmlog.Warn("PAM listener not available", "err", err)
		d.MarkWatcher("pamlistener", false)
		return
	}
	d.pamListener = pl
	d.MarkWatcher("pamlistener", true)
	d.RegisterUpstreamProbe("pamlistener", pl.UpstreamResult)
	d.wg.Add(1)
	obs.Go("pam-listener", func() {
		defer d.wg.Done()
		pl.Run(d.stopCh)
	})
	csmlog.Info("PAM listener active", "socket", pamSocketPath)
}

func (d *Daemon) startControlListener() {
	cl, err := NewControlListener(d)
	if err != nil {
		// The daemon can still function without the socket — periodic
		// scans and webui keep running — but the CLI will hard-error
		// because the socket is the expected path. Log loudly.
		csmlog.Error("control listener not available", "err", err)
		return
	}
	d.controlListener = cl
	d.wg.Add(1)
	obs.Go("control-listener", func() {
		defer d.wg.Done()
		cl.Run(d.stopCh)
	})
	csmlog.Info("control listener active", "socket", controlSocketPath)
}

func (d *Daemon) startFileMonitor() {
	fm, err := NewFileMonitor(d.cfg, d.alertCh)
	if err != nil {
		csmlog.Warn("fanotify not available, falling back to periodic deep scan", "err", err)
		d.MarkWatcher("fanotify", false)
		return
	}
	fm.registerMetrics()
	d.fileMonitor = fm
	d.wg.Add(1)
	obs.Go("fanotify", func() {
		defer d.wg.Done()
		fm.Run(d.stopCh)
	})
	csmlog.Info("fanotify file monitor active", "paths", "/home, /tmp, /dev/shm")
	d.MarkWatcher("fanotify", true)
}

func (d *Daemon) startSpoolWatcher() {
	if !d.cfg.EmailAV.Enabled {
		return
	}

	// Create ClamAV scanner
	clamScanner := emailav.NewClamdScanner(d.cfg.EmailAV.ClamdSocket)

	// YARA-X scanner over whichever backend initYaraBackend installed.
	// Active() transparently resolves to the in-process *yara.Scanner
	// or to the out-of-process supervisor depending on
	// signatures.yara_worker_enabled; severity metadata now travels on
	// matches so either backend yields the same verdict shape.
	yaraScanner := emailav.NewYaraXScanner(yara.Active())

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
		d.MarkWatcher("email_av_spool", false)
		return
	}
	d.setSpoolWatcher(sw)
	d.MarkWatcher("email_av_spool", true)

	d.wg.Add(1)
	obs.Go("spool-watcher", func() {
		defer d.wg.Done()
		d.runSpoolWatcherLoop(sw, orch, quar)
	})

	// Start quarantine cleanup goroutine
	d.wg.Add(1)
	obs.Go("email-quarantine-cleanup", d.emailQuarantineCleanup)

	fmt.Fprintf(os.Stderr, "[%s] Email AV spool watcher active\n", ts())
}

// superviseWatcherRun runs run() to completion. If daemonStop closes while
// run() is still blocked, stop() is invoked so run() can return. The helper
// goroutine is reaped when run() returns on its own. This guarantees the live
// watcher instance is stopped on shutdown even after a crash-restart swapped a
// fresh instance in, which the external shutdown path (it only stops the
// instance registered via setSpoolWatcher) can miss, hanging wg.Wait forever.
func superviseWatcherRun(daemonStop <-chan struct{}, run, stop func()) {
	done := make(chan struct{})
	helperDone := make(chan struct{})
	go func() {
		defer close(helperDone)
		select {
		case <-daemonStop:
			stop()
		case <-done:
		}
	}()
	run()
	close(done)
	<-helperDone
}

type spoolWatcherRuntime interface {
	Run()
	Stop()
}

func (d *Daemon) runSpoolWatcherLoop(sw *SpoolWatcher, orch *emailav.Orchestrator, quar *emailav.Quarantine) {
	d.runSpoolWatcherLoopWithFactory(sw, 2*time.Second, func() (spoolWatcherRuntime, error) {
		next, err := NewSpoolWatcher(d.cfg, d.alertCh, orch, quar)
		if err != nil {
			return nil, err
		}
		d.setSpoolWatcher(next)
		return next, nil
	})
}

func (d *Daemon) runSpoolWatcherLoopWithFactory(current spoolWatcherRuntime, restartDelay time.Duration, newWatcher func() (spoolWatcherRuntime, error)) {
	for {
		superviseWatcherRun(d.stopCh, current.Run, current.Stop)

		select {
		case <-d.stopCh:
			return
		default:
		}

		fmt.Fprintf(os.Stderr, "[%s] Email AV spool watcher stopped unexpectedly; restarting in %s\n", ts(), restartDelay)
		for {
			select {
			case <-d.stopCh:
				return
			case <-time.After(restartDelay):
			}

			next, err := newWatcher()
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] Email AV spool watcher restart failed: %v\n", ts(), err)
				continue
			}
			current = next
			break
		}
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
		d.MarkWatcher("forwarder", false)
		return
	}
	d.forwarderWatcher = fw
	d.wg.Add(1)
	obs.Go("forwarder-watcher", func() {
		defer d.wg.Done()
		fw.Run(d.stopCh)
	})
	csmlog.Info("watching log (inotify forwarder watcher)", "path", "/etc/valiases/")
	d.MarkWatcher("forwarder", true)
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

	d.ipList = challenge.NewIPListWithMapPath(d.cfg.StatePath, challenge.DefaultMapPath)
	if platform.Detect().WebServer == platform.WSNginx {
		d.ipList.SetNginxMap(challenge.DefaultNginxMapPath, d.reloadChallengeNginxMap)
	}
	d.attachChallengePortGate()
	checks.SetChallengeIPList(d.ipList)
	srv := challenge.New(d.cfg, unblocker, d.ipList)
	d.challengeServer = srv
	d.wg.Add(1)
	obs.Go("challenge-server", func() {
		defer d.wg.Done()
		csmlog.Info("challenge server active", "port", d.cfg.Challenge.ListenPort)
		if err := srv.Start(); err != nil && err.Error() != "http: Server closed" {
			csmlog.Error("challenge server error", "err", err)
		}
	})
}

// attachChallengePortGate installs the nftables port-gate for the
// challenge listener when the operator opts in. The gate is silently
// absent when the listener is loopback-only (no off-host traffic can
// reach it anyway) or on non-Linux builds.
func (d *Daemon) attachChallengePortGate() {
	if !d.cfg.Challenge.PortGate.Enabled {
		return
	}
	gate, err := challenge.NewPortGate(challenge.PortGateConfig{
		ListenAddr: d.cfg.Challenge.ListenAddr,
		ListenPort: d.cfg.Challenge.ListenPort,
		InfraCIDRs: d.cfg.InfraIPs,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] challenge port-gate install failed: %v (listener stays publicly reachable)\n", ts(), err)
		return
	}
	if gate == nil {
		csmlog.Info("challenge port-gate skipped (loopback listener or non-Linux build)",
			"listen_addr", d.cfg.Challenge.ListenAddr)
		return
	}
	d.challengeGate = gate
	d.ipList.SetPortGate(gate)
	csmlog.Info("challenge port-gate active", "port", d.cfg.Challenge.ListenPort)
}

func (d *Daemon) reloadChallengeNginxMap() error {
	// #nosec G204 -- static binary and arguments; no operator input is passed.
	out, err := exec.Command("nginx", "-s", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -s reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *Daemon) challengeEscalator() {
	defer d.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			// Re-read the block expiry each tick so a SIGHUP that
			// changes auto_response.block_expiry takes effect on the
			// next escalation without requiring a restart.
			expiry := parseBlockExpiry(d.currentCfg().AutoResponse.BlockExpiry)

			if d.challengeServer != nil {
				d.challengeServer.CleanExpired()
			}

			expired := d.ipList.ExpiredEntries()
			for _, e := range expired {
				if d.fwEngine == nil {
					continue
				}
				reason := fmt.Sprintf("CSM challenge-timeout: %s", truncateStr(e.Reason, 100))
				outcome, err := d.fwEngine.BlockIPOutcome(e.IP, reason, expiry)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[%s] challenge-escalate: error blocking %s: %v\n", ts(), e.IP, err)
					continue
				}
				observeChallengeEscalated(outcome)
				fmt.Fprintf(os.Stderr, "[%s] %s\n", ts(), challengeEscalateLogLine(e.IP, outcome))
			}
		}
	}
}

var (
	challengeEscalatedMetric     *metrics.CounterVec
	challengeEscalatedMetricOnce sync.Once
)

// observeChallengeEscalated counts one challenge-timeout escalation, labelled by
// the firewall outcome (live=a new hard block landed, noop=the IP was already
// blocked, plus dry_run/allowed). It lets operators see how many challenges
// became real blocks versus no-ops. Registered lazily on first use.
func observeChallengeEscalated(outcome firewall.BlockOutcome) {
	challengeEscalatedMetricOnce.Do(func() {
		challengeEscalatedMetric = metrics.NewCounterVec(
			"csm_challenge_escalated_total",
			"Challenge-timeout escalations, by firewall outcome (live, noop, dry_run, allowed).",
			[]string{"outcome"},
		)
		metrics.MustRegister("csm_challenge_escalated_total", challengeEscalatedMetric)
	})
	challengeEscalatedMetric.With(string(outcome)).Inc()
}

// challengeEscalatedCount returns how many challenge timeouts escalated to a new
// hard block (outcome=live) since daemon start, for the web UI challenge panel.
// Zero before the first escalation registers the metric.
func challengeEscalatedCount() int {
	if challengeEscalatedMetric == nil {
		return 0
	}
	return int(challengeEscalatedMetric.With(string(firewall.BlockOutcomeLive)).Value())
}

// challengeEscalateLogLine renders the stderr line for one challenge-timeout
// escalation. Only a live block claims "hard-blocked"; a no-op (the IP was
// already hard-blocked, e.g. a confirmed-threat finding blocked it while it sat
// on the challenge list) or a verdict downgrade must not, so incident review is
// not misled by a block that never landed.
func challengeEscalateLogLine(ip string, outcome firewall.BlockOutcome) string {
	switch outcome {
	case firewall.BlockOutcomeLive:
		return fmt.Sprintf("CHALLENGE-ESCALATE: %s timed out, hard-blocked", ip)
	case firewall.BlockOutcomeDryRun:
		return fmt.Sprintf("CHALLENGE-ESCALATE [dry-run]: %s timed out, would be hard-blocked", ip)
	default:
		return fmt.Sprintf("challenge-escalate: %s timed out, no new block (outcome: %s)", ip, outcome)
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
	//
	// Use a shallow copy rather than mutating d.cfg.Firewall in place.
	// Mutating the live config poisons config.Diff during a SIGHUP
	// reload: reload loads a fresh Config whose firewall.infra_ips has
	// NOT been merged, and reflect.DeepEqual then reports the firewall
	// subtree as changed even when nothing in csm.yaml was edited. The
	// reload is classified restart_required and every operator reload
	// turns into a spurious warning.
	mergedFirewall := *d.cfg.Firewall
	mergedFirewall.InfraIPs = mergeInfraIPs(d.cfg.InfraIPs, d.cfg.Firewall.InfraIPs)
	ensureChallengePortGateFirewallAccess(d.cfg, &mergedFirewall)

	engine, err := firewall.NewEngine(&mergedFirewall, d.cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Firewall engine init error: %v\n", ts(), err)
		return
	}

	// Wire dry-run + verdict callbacks BEFORE Apply() and before the
	// engine is exposed via d.fwEngine / checks.SetIPBlocker. The
	// auto_response.dry_run safety default is "on": if any code path
	// reaches engine.BlockIP while these callbacks are still nil, the
	// engine treats dry-run as off and the block lands live, defeating
	// the operator's stated intent. Wiring before exposure removes the
	// boot-time race window entirely.
	engine.SetDryRunRecorder(func(ip, reason string, timeout time.Duration) {
		if db := store.Global(); db != nil {
			db.RecordDryRunBlock(ip, reason, timeout)
		}
	})
	engine.SetDryRunEnabledFunc(d.autoResponseDryRunEnabled)
	engine.SetVerdictAsker(d.askVerdictCallback)

	if err := engine.Apply(); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Firewall apply error: %v\n", ts(), err)
		return
	}

	// Apply does not consult the verdict callback. Install the shutdown
	// context only after a successful firewall setup so a failed init
	// does not leave behind a stopCh waiter.
	verdictCtx, cancelVerdict := context.WithCancel(context.Background())
	go func() {
		<-d.stopCh
		cancelVerdict()
	}()
	engine.SetShutdownContext(verdictCtx)

	d.setFirewallEngine(engine)

	// Set firewall engine for auto-blocking
	checks.SetIPBlocker(engine)
	// Wire the incident firewall hand-off through BlockIPOutcome so the
	// correlator can distinguish live nftables mutation from dry-run,
	// verdict-allow, and other no-op outcomes.
	SetIncidentSprayBlocker(func(ip, reason string, timeout time.Duration) (bool, error) {
		outcome, err := engine.BlockIPOutcome(ip, reason, timeout)
		return outcome == firewall.BlockOutcomeLive, err
	})

	fwState, _ := firewall.LoadState(d.cfg.StatePath)
	csmlog.Info("firewall active",
		"blocked_ips", len(fwState.Blocked),
		"allowed_ips", len(fwState.Allowed),
	)

	// Start Dynamic DNS resolver if configured. The same resolver
	// loop also services hostnames listed under infra_ips so they get
	// DNS-refreshed into the engine's infra-block guard; otherwise the
	// hostname entries would only protect operators whose IPs never
	// move, which defeats the point of listing them by name.
	infraHosts := infraHostnames(mergedFirewall.InfraIPs)
	dynHosts := append([]string{}, d.cfg.Firewall.DynDNSHosts...)
	for _, h := range infraHosts {
		if !containsString(dynHosts, h) {
			dynHosts = append(dynHosts, h)
		}
	}
	if len(dynHosts) > 0 {
		resolver := firewall.NewDynDNSResolver(dynHosts, engine)
		resolver.SetInfraEngine(engine)
		for _, h := range infraHosts {
			resolver.RegisterInfraHost(h)
		}
		resolver.SetFindingSink(func(host string) {
			select {
			case d.alertCh <- dynDNSUnresolvableFinding(host):
			default:
				atomic.AddInt64(&d.droppedAlerts, 1)
				fmt.Fprintf(os.Stderr, "[%s] alert channel full, dropping dyndns guard finding: %s\n", ts(), host)
			}
		})
		d.wg.Add(1)
		obs.Go("dyndns-resolver", func() {
			defer d.wg.Done()
			resolver.Run(d.stopCh)
		})
		csmlog.Info("DynDNS resolver active", "hosts", len(dynHosts), "infra_hosts", len(infraHosts))
	}

	// Start Cloudflare IP whitelist refresh if configured
	if d.cfg.Cloudflare.Enabled {
		d.wg.Add(1)
		obs.Go("cloudflare-refresh", d.cloudflareRefreshLoop)
		csmlog.Info("cloudflare IP whitelist enabled", "refresh_hours", d.cfg.Cloudflare.RefreshHours)
	}
}

func ensureChallengePortGateFirewallAccess(cfg *config.Config, fw *firewall.FirewallConfig) {
	if cfg == nil || fw == nil {
		return
	}
	if !cfg.Challenge.Enabled || !cfg.Challenge.PortGate.Enabled {
		return
	}
	if cfg.Challenge.ListenPort <= 0 || challengeListenAddrIsLoopback(cfg.Challenge.ListenAddr) {
		return
	}
	fw.TCPIn = appendUniquePort(fw.TCPIn, cfg.Challenge.ListenPort)
	fw.RestrictedTCP = removePort(fw.RestrictedTCP, cfg.Challenge.ListenPort)
}

func challengeListenAddrIsLoopback(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return true
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func appendUniquePort(ports []int, port int) []int {
	for _, p := range ports {
		if p == port {
			return ports
		}
	}
	out := append([]int(nil), ports...)
	return append(out, port)
}

func removePort(ports []int, port int) []int {
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p != port {
			out = append(out, p)
		}
	}
	return out
}

func (d *Daemon) autoResponseDryRunEnabled() bool {
	return d.activeOrStartupCfg().AutoResponseDryRunEnabled()
}

func (d *Daemon) askVerdictCallback(ctx context.Context, ip, reason string) (string, string, string, error) {
	cfg := d.activeOrStartupCfg()
	if cfg == nil || !cfg.AutoResponse.VerdictCallback.Enabled {
		return "", "", "", nil
	}
	vcCfg := cfg.AutoResponse.VerdictCallback
	vc := verdict.New(verdict.Config{
		URL:                      vcCfg.URL,
		HMACSecret:               vcCfg.HMACSecret,
		HMACSecretEnv:            vcCfg.HMACSecretEnv,
		RequireResponseSignature: vcCfg.RequireResponseSignature,
		AllowUnsigned:            vcCfg.AllowUnsigned,
		Timeout:                  time.Duration(vcCfg.TimeoutSec) * time.Second,
	})
	resp, err := vc.Ask(ctx, verdict.Request{
		IP:       ip,
		Reason:   reason,
		Severity: "auto",
		Source:   "auto_response",
	})
	if err != nil {
		return "", "", "", err
	}
	return resp.Verdict, resp.TenantID, resp.Note, nil
}

func dynDNSUnresolvableFinding(host string) alert.Finding {
	return alert.Finding{
		Check:     "infra_ips_unresolvable",
		Severity:  alert.Warning,
		Message:   fmt.Sprintf("dynamic firewall host %s has not resolved within grace period", host),
		Details:   "Verify DNS for the host or remove it from infra_ips or firewall.dyndns_hosts. While unresolvable, the previous resolved IP remains protected and a rotated IP will not be protected.",
		Timestamp: time.Now(),
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
	// yara.Active() resolves to the in-process scanner or the worker
	// supervisor depending on signatures.yara_worker_enabled; both
	// satisfy the Reload/RuleCount calls this routine makes, so the
	// forge update path is backend-agnostic.
	yaraScanner := yara.Active()
	if yaraScanner == nil {
		// No YARA backend active (build without yara tag or no rules
		// dir). Skip Forge update - rules can't be loaded anyway.
		return
	}

	db := store.Global()
	currentVersion := ""
	if db != nil {
		currentVersion = db.GetMetaString("forge_version_" + d.cfg.Signatures.YaraForge.Tier)
	}

	newVersion, count, err := signatures.ForgeUpdateFromURL(
		d.cfg.Signatures.RulesDir,
		d.cfg.Signatures.YaraForge.Tier,
		currentVersion,
		d.cfg.Signatures.SigningKey,
		d.cfg.Signatures.YaraForge.DownloadURL,
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
	if yaraScanner := yara.Active(); yaraScanner != nil {
		if err := yaraScanner.Reload(); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] YARA rule reload error: %v\n", ts(), err)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] Reloaded %d YARA rule file(s)\n", ts(), yaraScanner.RuleCount())
		}
	}
}

// deployConfigs writes embedded config files to their system locations on startup.
// Ensures WHM plugin CGI and ModSec rules stay current after binary upgrades.
//
// Every file written here is a system integration point consumed by a
// different process (WHM, Apache, nginx); the permissions intentionally
// allow the right external reader. Gosec G301/G306 warnings on this
// function are suppressed inline with the specific integration target.
func deployConfigs() {
	// WHM plugin CGI - embedded in binary
	if _, err := os.Stat("/usr/local/cpanel"); err == nil {
		dst := "/usr/local/cpanel/whostmgr/docroot/cgi/addon_csm.cgi"
		// #nosec G306 -- WHM CGI endpoint; 0755 is required so cPanel's
		// webserver can execute it.
		if err := os.WriteFile(dst, embeddedWHMCGI, 0755); err == nil {
			csmlog.Info("WHM plugin CGI deployed", "path", dst)
		}
		// Write the AppConfig file, then register it with WHM.
		// Writing the file alone does NOT make the plugin appear in the
		// sidebar — WHM's AppConfig system maintains a registration
		// database that is updated via `register_appconfig`. Skipping
		// that step was a long-standing bug; the plugin file existed on
		// disk but never showed up in the menu.
		// #nosec G301 -- cPanel standard /var/cpanel/apps directory.
		_ = os.MkdirAll("/var/cpanel/apps", 0755)
		confPath := "/var/cpanel/apps/csm.conf"
		// #nosec G306 -- WHM AppConfig; read by cPanel tooling, 0644 is convention.
		if err := os.WriteFile(confPath, embeddedWHMConf, 0644); err != nil {
			csmlog.Error("WHM AppConfig write failed", "path", confPath, "err", err)
		} else if err := registerWHMPlugin(confPath); err != nil {
			// Non-fatal: the conf is on disk, register_appconfig failure is
			// logged so operators can fix it manually. Most common failure
			// is register_appconfig not being in PATH (old cPanel versions).
			csmlog.Warn("WHM plugin registration failed", "err", err)
		} else {
			csmlog.Info("WHM plugin registered with AppConfig")
		}
	}

	// Deploy script (self-updating)
	// #nosec G306 -- Shell script executed by operators and by the CSM
	// upgrade path; needs to be executable, not private.
	_ = os.WriteFile("/opt/csm/deploy.sh", embeddedDeployScript, 0755)

	// ModSecurity virtual patches
	for _, dst := range []string{
		"/etc/apache2/conf.d/modsec/modsec2.user.conf",
		"/usr/local/apache/conf/modsec2.user.conf",
	} {
		if _, err := os.Stat(filepath.Dir(dst)); err == nil {
			// #nosec G306 -- Apache reads this ModSecurity config; webserver
			// runs as a different user.
			_ = os.WriteFile(dst, embeddedModSec, 0644)
			overridesFile := filepath.Join(filepath.Dir(dst), "modsec2.csm-overrides.conf")
			modsec.EnsureOverridesInclude(dst, overridesFile)
			break
		}
	}
}

// registerWHMPlugin runs cPanel's register_appconfig helper to add the CSM
// plugin to the WHM sidebar. WHM maintains a cached registration database
// separate from the /var/cpanel/apps/ conf files; without running this
// helper, the plugin file exists on disk but the menu never shows it.
//
// Idempotent: re-running against an already-registered plugin just updates
// the entry. Non-fatal on failure — deployment continues and the operator
// can rerun manually.
func registerWHMPlugin(confPath string) error {
	bin := "/usr/local/cpanel/bin/register_appconfig"
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("register_appconfig not found at %s: %w", bin, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 -- bin is the fixed cPanel path validated by os.Stat above;
	// confPath was just written by deployConfigs from an embedded constant.
	cmd := exec.CommandContext(ctx, bin, confPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", bin, confPath, err, strings.TrimSpace(string(out)))
	}
	return nil
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
			if _, err := sdnotify.Watchdog(); err != nil {
				csmlog.Warn("systemd watchdog notify failed", "err", err)
			}
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

// countAttachedWatchers returns how many watchers are currently attached
// (value == true). Used for the systemd one-line status string.
func countAttachedWatchers(statuses map[string]bool) int {
	n := 0
	for _, attached := range statuses {
		if attached {
			n++
		}
	}
	return n
}
