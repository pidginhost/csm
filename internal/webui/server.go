package webui

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/broadcast"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailav"
	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/mailfwd/intel"
	"github.com/pidginhost/csm/internal/mailfwd/inventory"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/state"
)

// IPBlocker abstracts the firewall engine for block/unblock operations.
type IPBlocker interface {
	BlockIP(ip string, reason string, timeout time.Duration) error
	UnblockIP(ip string) error
}

// forceBlocker is an optional extension of IPBlocker for operator-initiated
// blocks that must bypass the auto_response.dry_run gate. The firewall engine
// implements this; test stubs need not.
type forceBlocker interface {
	BlockIPForce(ip string, reason string, timeout time.Duration) error
}

// blockIPForOperator calls BlockIPForce when the blocker supports it (engine
// on live systems), otherwise falls back to BlockIP (test stubs). This ensures
// operator-initiated blocks from the Web UI are never silenced by dry_run.
func blockIPForOperator(b IPBlocker, ip, reason string, timeout time.Duration) error {
	if fb, ok := b.(forceBlocker); ok {
		return fb.BlockIPForce(ip, reason, timeout)
	}
	return b.BlockIP(ip, reason, timeout)
}

// noListDir wraps an http.FileSystem so http.FileServer cannot serve a
// directory index. Opening a directory returns fs.ErrNotExist, which the
// FileServer turns into a 404, while individual files are served normally.
// This keeps the unauthenticated /static/ assets reachable for the login
// page without letting anyone enumerate the shipped file set.
type noListDir struct{ fs http.FileSystem }

func (d noListDir) Open(name string) (http.File, error) {
	f, err := d.fs.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.IsDir() {
		_ = f.Close()
		return nil, fs.ErrNotExist
	}
	return f, nil
}

// Server is the web UI HTTP server. Serves API always; serves HTML pages
// and static files only if the UI directory exists on disk.
type Server struct {
	cfg                *config.Config
	store              *state.Store
	httpSrv            *http.Server
	templates          map[string]*template.Template
	hasUI              bool   // true if UI directory with templates exists
	uiDir              string // path to UI directory on disk
	startTime          time.Time
	sigCount           int // loaded signature rule count
	fanotifyActive     bool
	logWatcherCount    int
	blocker            IPBlocker
	geoIPDB            atomic.Pointer[geoip.DB]
	emailQuarantine    *emailav.Quarantine
	emailAVWatcherMode string
	forwarderSource    inventory.Source
	deferralReporter   intel.Reporter
	queueReporter      intel.QueueReporter
	queueFlusher       intel.QueueFlusher
	forwardHeld        heldForwardStore
	version            string
	perfSnapshot       atomic.Pointer[perfMetrics]
	perfCancel         context.CancelFunc
	incidentCorrelator *incident.Correlator

	// Rate limiting
	loginMu       sync.Mutex
	loginAttempts map[string][]time.Time
	apiMu         sync.Mutex
	apiRequests   map[string][]time.Time // per-IP API rate limiting
	scanMu        sync.Mutex
	scanRunning   bool       // only one scan at a time
	modSecApplyMu sync.Mutex // serializes modsec rules apply (write+reload+rollback)

	provider health.Provider // set by Daemon when it starts the WebUI

	mu         sync.RWMutex
	findingBus *broadcast.Bus // set by Daemon via SetFindingBus

	// Graceful shutdown signal for background goroutines and streaming handlers.
	// shutdownOnce makes Shutdown idempotent; closing pruneDone twice panics.
	pruneDone    chan struct{}
	shutdownOnce sync.Once

	// restartDaemon is called by apiSettingsRestart. Tests override this.
	restartDaemon func() (output []byte, err error)
}

// New creates a new web UI server.
func New(cfg *config.Config, store *state.Store) (*Server, error) {
	s := &Server{
		cfg:              cfg,
		store:            store,
		startTime:        time.Now(),
		loginAttempts:    make(map[string][]time.Time),
		apiRequests:      make(map[string][]time.Time),
		pruneDone:        make(chan struct{}),
		forwarderSource:  selectForwarderSource(),
		deferralReporter: selectDeferralReporter(),
		queueReporter:    selectQueueReporter(),
		queueFlusher:     selectQueueFlusher(),
		forwardHeld:      selectForwardHeld(),
	}

	// Check if UI directory exists on disk
	s.uiDir = cfg.WebUI.UIDir
	if s.uiDir == "" {
		s.uiDir = "/opt/csm/ui"
	}

	funcMap := template.FuncMap{
		"severityClass": severityClass,
		"severityLabel": severityLabel,
		"timeAgo":       timeAgo,
		"formatTime":    formatTime,
		"csrfToken":     s.csrfToken,
		"csmConfig":     func() template.JS { return jsonForScript(s.csmConfig()) },
		"json":          jsonForScript,
		"multiply":      func(a, b int) int { return a * b },
		"add":           func(a, b int) int { return a + b },
		"subtract":      func(a, b int) int { return a - b },
		"divisibleBy":   func(a, b int) bool { return b != 0 && a%b == 0 },
	}

	// Try to load templates from disk
	templateDir := filepath.Join(s.uiDir, "templates")
	staticDir := filepath.Join(s.uiDir, "static")
	if _, err := os.Stat(templateDir); err == nil {
		s.templates = make(map[string]*template.Template)
		layoutPath := filepath.Join(templateDir, "layout.html")
		for _, page := range []string{"dashboard", "findings", "quarantine", "cleanup-history", "firewall", "modsec", "modsec-rules", "threat", "rules", "audit", "account", "incident", "email", "performance", "hardening", "settings"} {
			pagePath := filepath.Join(templateDir, page+".html")
			t, err := template.New(page+".html").Funcs(funcMap).ParseFiles(layoutPath, pagePath)
			if err != nil {
				return nil, fmt.Errorf("parsing template %s from %s: %w", page, templateDir, err)
			}
			s.templates[page+".html"] = t
		}
		loginPath := filepath.Join(templateDir, "login.html")
		loginTmpl, err := template.New("login.html").Funcs(funcMap).ParseFiles(loginPath)
		if err != nil {
			return nil, fmt.Errorf("parsing login template: %w", err)
		}
		s.templates["login.html"] = loginTmpl
		s.hasUI = true
		fmt.Fprintf(os.Stderr, "WebUI: loaded templates from %s\n", templateDir)
	} else {
		fmt.Fprintf(os.Stderr, "WebUI: UI directory not found at %s - running in API-only mode\n", s.uiDir)
	}

	// Set up routes
	mux := http.NewServeMux()

	// Static files and HTML pages - only if UI directory exists
	if s.hasUI {
		// Static assets must stay reachable pre-auth (the login page loads its
		// own CSS/JS), so they are not behind requireAuth. They must not be
		// enumerable, though: noListDir makes directory requests 404 instead of
		// returning an index listing of every shipped file.
		mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(noListDir{http.Dir(staticDir)})))
		mux.HandleFunc("/login", s.handleLogin)
		mux.Handle("/", s.requireAuth(http.HandlerFunc(s.handleDashboard)))
		mux.Handle("/dashboard", s.requireAuth(http.HandlerFunc(s.handleDashboard)))
		mux.Handle("/findings", s.requireAuth(http.HandlerFunc(s.handleFindings)))
		mux.Handle("/history", s.requireAuth(http.HandlerFunc(s.handleHistoryRedirect)))
		mux.Handle("/quarantine", s.requireAuth(http.HandlerFunc(s.handleQuarantine)))
		mux.Handle("/cleanup-history", s.requireAuth(http.HandlerFunc(s.handleCleanupHistory)))
		mux.Handle("/blocked", s.requireAuth(http.HandlerFunc(s.handleFirewall))) // redirect old URL
		mux.Handle("/firewall", s.requireAuth(http.HandlerFunc(s.handleFirewall)))
		mux.Handle("/threat", s.requireAuth(http.HandlerFunc(s.handleThreat)))
		mux.Handle("/rules", s.requireAuth(http.HandlerFunc(s.handleRules)))
		mux.Handle("/audit", s.requireAuth(http.HandlerFunc(s.handleAudit)))
		mux.Handle("/account", s.requireAuth(http.HandlerFunc(s.handleAccount)))
		mux.Handle("/incident", s.requireAuth(http.HandlerFunc(s.handleIncident)))
		mux.Handle("/email", s.requireAuth(http.HandlerFunc(s.handleEmail)))
		mux.Handle("/performance", s.requireAuth(http.HandlerFunc(s.handlePerformance)))
		mux.Handle("/hardening", s.requireAuth(http.HandlerFunc(s.handleHardening)))
		mux.Handle("/settings", s.requireAuth(http.HandlerFunc(s.handleSettings)))
		mux.Handle("/modsec", s.requireAuth(http.HandlerFunc(s.handleModSec)))
		mux.Handle("/modsec/rules", s.requireAuth(http.HandlerFunc(s.handleModSecRules)))
	}

	// Auth-protected API - read (read-scope tokens accepted)
	mux.Handle("/api/v1/events", s.requireRead(http.HandlerFunc(s.apiEvents)))
	mux.Handle("/api/v1/status", s.requireRead(http.HandlerFunc(s.apiStatus)))
	mux.Handle("/api/v1/challenge/stats", s.requireRead(http.HandlerFunc(s.apiChallengeStats)))
	mux.Handle("/api/v1/findings", s.requireRead(http.HandlerFunc(s.apiFindings)))
	mux.Handle("/api/v1/findings/enriched", s.requireRead(http.HandlerFunc(s.apiFindingsEnriched)))
	mux.Handle("/api/v1/history", s.requireRead(http.HandlerFunc(s.apiHistory)))
	mux.Handle("/api/v1/stats", s.requireRead(http.HandlerFunc(s.apiStats)))
	mux.Handle("/api/v1/stats/trend", s.requireRead(http.HandlerFunc(s.apiStatsTrend)))
	mux.Handle("/api/v1/stats/timeline", s.requireRead(http.HandlerFunc(s.apiStatsTimeline)))
	mux.Handle("/api/v1/blocked-ips", s.requireRead(http.HandlerFunc(s.apiBlockedIPs)))
	mux.Handle("/api/v1/capabilities", s.requireRead(http.HandlerFunc(s.apiCapabilities)))
	mux.Handle("/api/v1/health", s.requireRead(http.HandlerFunc(s.apiHealth)))
	mux.Handle("/api/v1/components", s.requireRead(http.HandlerFunc(s.apiComponents)))
	// Auth-protected API - admin-only reads (data with write-adjacent sensitivity)
	mux.Handle("/api/v1/quarantine", s.requireAuth(http.HandlerFunc(s.apiQuarantine)))
	mux.Handle("/api/v1/modsec/stats", s.requireRead(http.HandlerFunc(s.apiModSecStats)))
	mux.Handle("/api/v1/modsec/blocks", s.requireRead(http.HandlerFunc(s.apiModSecBlocks)))
	mux.Handle("/api/v1/modsec/events", s.requireRead(http.HandlerFunc(s.apiModSecEvents)))
	mux.Handle("/api/v1/modsec/rules", s.requireAuth(http.HandlerFunc(s.apiModSecRules)))
	mux.Handle("/api/v1/modsec/rules/apply", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiModSecRulesApply))))
	mux.Handle("/api/v1/modsec/rules/escalation", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiModSecRulesEscalation))))
	mux.Handle("/api/v1/accounts", s.requireAuth(http.HandlerFunc(s.apiAccounts)))
	mux.Handle("/api/v1/account", s.requireAuth(http.HandlerFunc(s.apiAccountDetail)))
	mux.Handle("/api/v1/history/csv", s.requireAuth(http.HandlerFunc(s.apiHistoryCSV)))
	mux.Handle("/api/v1/export", s.requireAuth(http.HandlerFunc(s.apiExport)))
	mux.Handle("/api/v1/import", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiImport))))
	mux.Handle("/api/v1/incident", s.requireAuth(http.HandlerFunc(s.apiIncident)))
	// Admin-scope on both routes: ServeMux cannot disambiguate by HTTP method,
	// so the POST .../status mutator forces admin; reads under the same prefix
	// inherit it (admin is a superset of read). The sub-path also runs CSRF
	// because the router can dispatch POST .../status; requireCSRF only acts
	// on unsafe methods so GET .../<id> still passes through.
	mux.Handle("/api/v1/incidents", s.requireAuth(http.HandlerFunc(s.apiIncidentList)))
	mux.Handle("/api/v1/incidents/groups", s.requireRead(http.HandlerFunc(s.apiIncidentGroups)))
	mux.Handle("/api/v1/incidents/", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiIncidentRouter))))
	mux.Handle("/api/v1/email/stats", s.requireAuth(http.HandlerFunc(s.apiEmailStats)))
	mux.Handle("/api/v1/email/quarantine", s.requireAuth(http.HandlerFunc(s.apiEmailQuarantineList)))
	mux.Handle("/api/v1/email/quarantine/", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiEmailQuarantineAction))))
	mux.Handle("/api/v1/email/av/status", s.requireAuth(http.HandlerFunc(s.apiEmailAVStatus)))
	mux.Handle("/api/v1/email/groups", s.requireRead(http.HandlerFunc(s.apiEmailGroups)))
	mux.Handle("/api/v1/email/relay-abuse", s.requireRead(http.HandlerFunc(s.apiEmailRelayAbuse)))
	mux.Handle("/api/v1/email/forwarders", s.requireRead(http.HandlerFunc(s.apiEmailForwarders)))
	mux.Handle("/api/v1/email/deferrals", s.requireRead(http.HandlerFunc(s.apiEmailDeferrals)))
	mux.Handle("/api/v1/email/queue-composition", s.requireRead(http.HandlerFunc(s.apiEmailQueueComposition)))
	mux.Handle("/api/v1/email/queue/flush-backscatter", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiEmailFlushBackscatter))))
	mux.Handle("/api/v1/email/held", s.requireAuth(http.HandlerFunc(s.apiEmailHeldList)))
	mux.Handle("/api/v1/email/held/", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiEmailHeldAction))))
	mux.Handle("/api/v1/performance", s.requireAuth(http.HandlerFunc(s.apiPerformance)))
	mux.Handle("/api/v1/perf/fix-error-log", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiPerfFixErrorLog))))
	mux.Handle("/api/v1/perf/fix-display-errors", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiPerfFixDisplayErrors))))
	mux.Handle("/api/v1/perf/fix-wp-cron", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiPerfFixWPCron))))
	mux.Handle("/api/v1/hardening", s.requireAuth(http.HandlerFunc(s.apiHardening)))
	mux.Handle("/api/v1/hardening/run", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiHardeningRun))))

	// Threat Intelligence API
	mux.Handle("/api/v1/threat/stats", s.requireAuth(http.HandlerFunc(s.apiThreatStats)))
	mux.Handle("/api/v1/threat/top-attackers", s.requireAuth(http.HandlerFunc(s.apiThreatTopAttackers)))
	mux.Handle("/api/v1/threat/ip", s.requireAuth(http.HandlerFunc(s.apiThreatIP)))
	mux.Handle("/api/v1/threat/events", s.requireAuth(http.HandlerFunc(s.apiThreatEvents)))
	mux.Handle("/api/v1/threat/db-stats", s.requireAuth(http.HandlerFunc(s.apiThreatDBStats)))
	mux.Handle("/api/v1/audit", s.requireAuth(http.HandlerFunc(s.apiUIAudit)))
	mux.Handle("/api/v1/finding-detail", s.requireAuth(http.HandlerFunc(s.apiFindingDetail)))
	mux.Handle("/api/v1/threat/whitelist-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatWhitelistIP))))
	mux.Handle("/api/v1/threat/whitelist", s.requireAuth(http.HandlerFunc(s.apiThreatWhitelist)))
	mux.Handle("/api/v1/threat/unwhitelist-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatUnwhitelistIP))))
	mux.Handle("/api/v1/threat/block-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatBlockIP))))
	mux.Handle("/api/v1/threat/clear-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatClearIP))))
	mux.Handle("/api/v1/threat/temp-whitelist-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatTempWhitelistIP))))
	mux.Handle("/api/v1/threat/bulk-action", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiThreatBulkAction))))

	// Rules API
	mux.Handle("/api/v1/rules/status", s.requireAuth(http.HandlerFunc(s.apiRulesStatus)))
	mux.Handle("/api/v1/rules/list", s.requireAuth(http.HandlerFunc(s.apiRulesList)))
	mux.Handle("/api/v1/rules/reload", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiRulesReload))))
	mux.Handle("/api/v1/rules/modsec-escalation", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiModSecEscalation))))

	// Suppressions API
	mux.Handle("/api/v1/suppressions", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiSuppressions))))

	// Firewall API
	mux.Handle("/api/v1/firewall/status", s.requireAuth(http.HandlerFunc(s.apiFirewallStatus)))
	mux.Handle("/api/v1/firewall/allowed", s.requireAuth(http.HandlerFunc(s.apiFirewallAllowed)))
	mux.Handle("/api/v1/firewall/audit", s.requireAuth(http.HandlerFunc(s.apiFirewallAudit)))
	mux.Handle("/api/v1/firewall/subnets", s.requireAuth(http.HandlerFunc(s.apiFirewallSubnets)))
	mux.Handle("/api/v1/firewall/check", s.requireAuth(http.HandlerFunc(s.apiFirewallCheck)))

	// Settings API
	mux.Handle("/api/v1/settings/restart", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiSettingsRestart))))
	mux.Handle("/api/v1/settings/firewall/tentative-apply", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallTentativeApply))))
	mux.Handle("/api/v1/settings/firewall/confirm", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallRollbackConfirm))))
	mux.Handle("/api/v1/settings/firewall/revert", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallRollbackRevert))))
	mux.Handle("/api/v1/settings/firewall/rollback", s.requireAuth(http.HandlerFunc(s.apiFirewallRollbackStatus)))
	mux.Handle("/api/v1/settings", s.requireAuth(http.HandlerFunc(s.apiSettingsSections)))
	mux.Handle("/api/v1/settings/", s.requireAuth(http.HandlerFunc(s.apiSettings)))

	// GeoIP API
	mux.Handle("/api/v1/geoip", s.requireAuth(http.HandlerFunc(s.apiGeoIPLookup)))
	mux.Handle("/api/v1/geoip/batch", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiGeoIPBatch))))

	// Auth-protected API - actions (with CSRF validation)
	mux.Handle("/api/v1/fix", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFix))))
	mux.Handle("/api/v1/fix-bulk", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiBulkFix))))
	mux.Handle("/api/v1/scan-account", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiScanAccount))))
	mux.Handle("/api/v1/test-alert", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiTestAlert))))
	mux.Handle("/api/v1/block-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiBlockIP))))
	mux.Handle("/api/v1/unblock-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiUnblockIP))))
	mux.Handle("/api/v1/unblock-bulk", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiUnblockBulk))))
	mux.Handle("/api/v1/dismiss", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiDismissFinding))))
	mux.Handle("/api/v1/quarantine-preview", s.requireAuth(http.HandlerFunc(s.apiQuarantinePreview)))
	mux.Handle("/api/v1/quarantine-restore", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiQuarantineRestore))))
	mux.Handle("/api/v1/quarantine/bulk-delete", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiQuarantineBulkDelete))))
	mux.Handle("/api/v1/db-object-backups", s.requireAuth(http.HandlerFunc(s.apiDBObjectBackups)))
	mux.Handle("/api/v1/db-object-backup-preview", s.requireAuth(http.HandlerFunc(s.apiDBObjectBackupPreview)))
	mux.Handle("/api/v1/db-object-backup-restore", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiDBObjectBackupRestore))))
	mux.Handle("/api/v1/firewall/deny-subnet", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallDenySubnet))))
	mux.Handle("/api/v1/firewall/allow-ip", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallAllowIP))))
	mux.Handle("/api/v1/firewall/remove-allow", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallRemoveAllow))))
	mux.Handle("/api/v1/firewall/remove-subnet", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallRemoveSubnet))))
	mux.Handle("/api/v1/firewall/cphulk-clear", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallFlushCphulk))))
	mux.Handle("/api/v1/firewall/flush", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallFlush))))
	mux.Handle("/api/v1/firewall/unban", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiFirewallUnban))))

	// Operator preferences (P5.2 saved views, P5.4 user prefs).
	mux.Handle("/api/v1/prefs/user", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiPrefsUser))))
	mux.Handle("/api/v1/prefs/views", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiPrefsViews))))

	// Bulk-action undo (P5.3).
	mux.Handle("/api/v1/undo/pending", s.requireAuth(http.HandlerFunc(s.apiUndoPending)))
	mux.Handle("/api/v1/undo/run", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.apiUndoRun))))

	// Logout (clears cookie, requires auth to prevent logout CSRF)
	mux.Handle("/logout", s.requireAuth(http.HandlerFunc(s.handleLogout)))

	// /metrics (ROADMAP item 4) has its own auth: the handler accepts
	// cfg.WebUI.MetricsToken as a dedicated Bearer token so Prometheus
	// scrapers get a credential that does not also unlock the UI, and
	// falls back to the existing AuthToken/session path so the UI can
	// self-scrape. No CSRF: read-only endpoint.
	mux.HandleFunc("/metrics", s.handleMetrics)

	s.httpSrv = &http.Server{
		Addr:              cfg.WebUI.Listen,
		Handler:           s.securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,  // slowloris protection
		ReadTimeout:       30 * time.Second,  // max time to read full request
		WriteTimeout:      300 * time.Second, // account scans can take several minutes
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Disable HTTP/2: Go's HTTP/2 implementation applies WriteTimeout
			// to the entire connection, not per-stream. Long-running handlers
			// (account scans ~5min) cause ERR_HTTP2_PROTOCOL_ERROR in browsers
			// when the timeout fires. HTTP/1.1 handles per-request deadlines
			// correctly via ResponseController.SetWriteDeadline.
			NextProtos: []string{"http/1.1"},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
	}

	s.restartDaemon = defaultRestartDaemon

	return s, nil
}

// pruneLoginAttempts periodically cleans up stale rate-limit entries.
// It returns when s.pruneDone is closed.
func (s *Server) pruneLoginAttempts() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.pruneDone:
			return
		case <-ticker.C:
			s.loginMu.Lock()
			cutoff := time.Now().Add(-time.Minute)
			for ip, attempts := range s.loginAttempts {
				var recent []time.Time
				for _, t := range attempts {
					if t.After(cutoff) {
						recent = append(recent, t)
					}
				}
				if len(recent) == 0 {
					delete(s.loginAttempts, ip)
				} else {
					s.loginAttempts[ip] = recent
				}
			}
			s.loginMu.Unlock()

			// Also prune API rate-limit entries
			s.apiMu.Lock()
			for ip, reqs := range s.apiRequests {
				var recent []time.Time
				for _, t := range reqs {
					if t.After(cutoff) {
						recent = append(recent, t)
					}
				}
				if len(recent) == 0 {
					delete(s.apiRequests, ip)
				} else {
					s.apiRequests[ip] = recent
				}
			}
			s.apiMu.Unlock()
		}
	}
}

// Start starts the HTTPS server. Blocks until shutdown.
func (s *Server) Start() error {
	certPath := s.cfg.WebUI.TLSCert
	keyPath := s.cfg.WebUI.TLSKey

	if certPath == "" {
		certPath = filepath.Join(s.cfg.StatePath, "webui.crt")
		keyPath = filepath.Join(s.cfg.StatePath, "webui.key")
	}

	if err := EnsureTLSCert(certPath, keyPath, s.cfg.Hostname); err != nil {
		return fmt.Errorf("TLS cert setup: %w", err)
	}

	obs.Go("webui-prune-logins", s.pruneLoginAttempts)

	perfCtx, perfCancel := context.WithCancel(context.Background())
	s.perfCancel = perfCancel
	obs.Go("webui-metrics-sample", func() { s.sampleMetricsLoop(perfCtx) })

	fmt.Fprintf(os.Stderr, "WebUI listening on https://%s\n", s.cfg.WebUI.Listen)
	return s.httpSrv.ListenAndServeTLS(certPath, keyPath)
}

// Shutdown gracefully stops the server. Safe to call more than once;
// the underlying pruneDone close is guarded so duplicate shutdown does
// not panic.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.perfCancel != nil {
		s.perfCancel()
	}
	s.shutdownOnce.Do(func() { close(s.pruneDone) })
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// canonicalAllowedOrigin returns the single CORS origin the web UI
// will accept on /api/ requests. Built from cfg.Hostname plus the
// listen port so a forged HTTP Host header cannot redirect the check.
func (s *Server) canonicalAllowedOrigin() string {
	host := canonicalOriginHost(s.cfg.Hostname)
	port := webUIListenPort(s.cfg.WebUI.Listen)
	if port != "" && port != "443" {
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		host = net.JoinHostPort(host, port)
	}
	return "https://" + host
}

func canonicalOriginHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") {
		if end := strings.Index(host, "]"); end > 0 {
			if ip := net.ParseIP(host[1:end]); ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					return ip4.String()
				}
				return "[" + ip.String() + "]"
			}
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
		return "[" + ip.String() + "]"
	}
	return strings.ToLower(host)
}

func webUIListenPort(listen string) string {
	if _, port, err := net.SplitHostPort(listen); err == nil {
		return port
	}
	if idx := strings.LastIndex(listen, ":"); idx >= 0 {
		return listen[idx+1:]
	}
	return ""
}

func sameOrigin(got, want string) bool {
	gotURL, err := url.Parse(got)
	if err != nil || !originHeaderURL(gotURL) {
		return false
	}
	wantURL, err := url.Parse(want)
	if err != nil || !originHeaderURL(wantURL) {
		return false
	}
	return strings.EqualFold(gotURL.Scheme, wantURL.Scheme) &&
		strings.EqualFold(gotURL.Hostname(), wantURL.Hostname()) &&
		originPort(gotURL) == originPort(wantURL)
}

func originHeaderURL(u *url.URL) bool {
	return u.Scheme != "" && u.Host != "" && u.User == nil &&
		u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}

func originPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// Broadcast is a no-op kept for daemon compatibility; dashboard uses polling.
func (s *Server) Broadcast(_ []alert.Finding) {}

// SetSigCount sets the loaded signature count for the status API.
func (s *Server) SetSigCount(count int) {
	s.sigCount = count
}

// HasUI returns true if UI templates were loaded from disk.
func (s *Server) HasUI() bool {
	return s.hasUI
}

// SetIPBlocker sets the firewall engine for block/unblock operations.
func (s *Server) SetIPBlocker(b IPBlocker) {
	s.blocker = b
}

// SetHealthInfo sets daemon health info for the health API.
func (s *Server) SetHealthInfo(fanotifyActive bool, logWatchers int) {
	s.fanotifyActive = fanotifyActive
	s.logWatcherCount = logWatchers
}

// SetEmailQuarantine sets the email quarantine for the email AV API endpoints.
func (s *Server) SetEmailQuarantine(q *emailav.Quarantine) {
	s.emailQuarantine = q
}

// SetEmailAVWatcherMode sets the watcher mode string for the email AV status API.
func (s *Server) SetEmailAVWatcherMode(mode string) {
	s.emailAVWatcherMode = mode
}

// SetVersion sets the application version for display in the UI.
func (s *Server) SetVersion(v string) {
	s.version = v
}

// SetHealthProvider installs the daemon's health provider. The webui
// constructs without one so unit tests can run without a daemon; the
// daemon must call this before any request hits /api/v1/status.
func (s *Server) SetHealthProvider(p health.Provider) {
	s.provider = p
}

// SetFindingBus installs the broadcaster the SSE event stream subscribes
// to. The webui constructs without one so unit tests work without a
// daemon; the daemon must call this before any request hits /api/v1/events.
func (s *Server) SetFindingBus(bus *broadcast.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findingBus = bus
}

// SetIncidentCorrelator wires the incident correlator. Called once at
// startup; treated as immutable after first set.
func (s *Server) SetIncidentCorrelator(c *incident.Correlator) {
	s.incidentCorrelator = c
}

// csmConfigJSON returns a JSON string of feature flags for the frontend.
func (s *Server) csmConfigJSON() string {
	b, _ := json.Marshal(s.csmConfig())
	return string(b)
}

// csmConfig returns the feature-flag map used by the frontend. Template
// rendering goes through jsonForScript; the csmConfigJSON wrapper exists
// for code paths that need a pre-marshaled JSON string.
func (s *Server) csmConfig() map[string]interface{} {
	return map[string]interface{}{
		"version":      s.version,
		"emailAV":      s.cfg.EmailAV.Enabled,
		"firewall":     s.cfg.Firewall != nil && s.cfg.Firewall.Enabled,
		"autoResponse": s.cfg.AutoResponse.Enabled,
		"threatIntel":  s.cfg.Reputation.AbuseIPDBKey != "",
		"signatures":   s.cfg.Signatures.RulesDir != "",
		"challenge":    s.cfg.Challenge.Difficulty > 0,
		"fanotify":     s.fanotifyActive,
		"hostname":     s.cfg.Hostname,
		"authScope":    "admin",
		// #nosec G101 -- Not credentials. This is a lookup from
		// finding-type ID (waf_block, credential_leak, etc.) to the
		// human-readable label rendered in the UI.
		"checkNames": map[string]string{
			"waf_block":                      "WAF Block",
			"brute_force":                    "Brute Force",
			"webshell":                       "Web Shell",
			"phishing":                       "Phishing",
			"spam":                           "Spam",
			"cpanel_login":                   "cPanel Login",
			"file_upload":                    "File Upload",
			"recon":                          "Reconnaissance",
			"c2":                             "C2 Communication",
			"other":                          "Other",
			"perf_load":                      "Load",
			"perf_php_processes":             "PHP Processes",
			"perf_memory":                    "Memory",
			"perf_php_handler":               "PHP Handler",
			"perf_mysql_config":              "MySQL Config",
			"perf_redis_config":              "Redis Config",
			"perf_error_logs":                "Error Logs",
			"perf_wp_config":                 "WP Config",
			"perf_wp_transients":             "WP Transients",
			"perf_wp_cron":                   "WP Cron",
			"integrity":                      "Integrity",
			"db_siteurl_hijack":              "DB URL Hijack",
			"db_options_injection":           "DB Options Injection",
			"db_post_injection":              "DB Post Injection",
			"db_spam_injection":              "DB Spam Injection",
			"db_rogue_admin":                 "DB Rogue Admin",
			"db_suspicious_admin_email":      "DB Suspicious Admin",
			"mail_queue":                     "Mail Queue",
			"mail_per_account":               "Mail Volume",
			"email_phishing_content":         "Email Phishing",
			"email_malware":                  "Email Malware",
			"email_compromised_account":      "Compromised Account",
			"email_cloud_relay_abuse":        "Cloud-Relay Credential Abuse",
			"email_spam_outbreak":            "Spam Outbreak",
			"email_defer_fail_governor":      "Defer/Fail Governor",
			"email_credential_leak":          "Credential Leak",
			"email_auth_failure_realtime":    "Auth Failure",
			"smtp_bruteforce":                "SMTP Brute Force",
			"smtp_subnet_spray":              "SMTP Subnet Spray",
			"smtp_account_spray":             "SMTP Account Spray",
			"mail_bruteforce":                "Mail Brute Force",
			"mail_subnet_spray":              "Mail Subnet Spray",
			"admin_panel_bruteforce":         "Admin Panel Brute Force",
			"mail_account_spray":             "Mail Account Spray",
			"mail_account_compromised":       "Mail Account Compromised",
			"http_request_flood":             "HTTP Request Flood",
			"http_scanner_profile":           "HTTP Scanner Profile",
			"http_ua_spoof":                  "HTTP UA Spoof",
			"http_distributed_flood":         "Distributed HTTP Flood",
			"exim_frozen_realtime":           "Frozen Message",
			"email_suspicious_geo":           "Suspicious Geo Login",
			"email_rate_critical":            "Email Rate Critical",
			"email_rate_warning":             "Email Rate Warning",
			"email_dkim_failure":             "DKIM Failure",
			"email_spf_rejection":            "SPF Rejection",
			"email_pipe_forwarder":           "Pipe Forwarder",
			"email_suspicious_forwarder":     "Suspicious Forwarder",
			"cpanel_login_realtime":          "cPanel Login",
			"cpanel_password_purge_realtime": "Password Purge",
			"ssh_login_realtime":             "SSH Login",
			"pam_login":                      "PAM Login",
			"pam_bruteforce":                 "PAM Brute Force",
			"modsec_block_escalation":        "ModSec Escalation",
			"modsec_csm_block_escalation":    "ModSec Escalation",
			"whm_password_change_noninfra":   "WHM Password Change",
			"password_hijack_confirmed":      "Password Hijack",
		},
	}
}

// --- Authentication ---

// tokenHasScope reports whether the credentials in r grant at least the
// requested scope. "read" is granted by any token; "admin" is granted only
// by admin-scope tokens. Constant-time compare against every configured
// token. Cookie credentials get treated as their token's scope (browser
// session uses the admin login form, which only matches admin tokens).
func (s *Server) tokenHasScope(r *http.Request, want string) bool {
	// Browser cookie session
	if _, ok := s.cookieTokenWithScope(r, want); ok {
		return true
	}

	// Bearer token
	_, ok := s.bearerTokenWithScope(r, want)
	return ok
}

func (s *Server) cookieTokenWithScope(r *http.Request, want string) (string, bool) {
	c, err := r.Cookie("csm_auth")
	if err != nil || c.Value == "" {
		return "", false
	}
	for _, tok := range s.cfg.WebUI.Tokens {
		if webUITokenMatches(c.Value, tok) && webUITokenAllows(tok, want) {
			return c.Value, true
		}
	}
	return "", false
}

func (s *Server) bearerTokenWithScope(r *http.Request, want string) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	supplied := strings.TrimPrefix(auth, "Bearer ")
	if supplied == "" {
		return "", false
	}
	for _, tok := range s.cfg.WebUI.Tokens {
		if webUITokenMatches(supplied, tok) && webUITokenAllows(tok, want) {
			return supplied, true
		}
	}
	return "", false
}

func webUITokenMatches(supplied string, tok config.WebUIToken) bool {
	return supplied != "" &&
		tok.Token != "" &&
		subtle.ConstantTimeCompare([]byte(supplied), []byte(tok.Token)) == 1
}

func webUITokenAllows(tok config.WebUIToken, want string) bool {
	switch want {
	case "read":
		return tok.Scope == "read" || tok.Scope == "admin"
	case "admin":
		return tok.Scope == "admin"
	default:
		return false
	}
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.tokenHasScope(r, "admin") {
			next.ServeHTTP(w, r)
			return
		}
		// API calls get 401 JSON; browser requests get redirect to login
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSONError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}

func (s *Server) requireRead(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.tokenHasScope(r, "read") {
			if r.Method != http.MethodGet {
				writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		// API calls get 401 JSON; browser requests get redirect to login
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSONError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}

// isAuthenticated is a thin shim used by handleLogin and metrics_api.
// New callers should prefer tokenHasScope directly.
func (s *Server) isAuthenticated(r *http.Request) bool {
	return s.tokenHasScope(r, "admin")
}

// clientIPKey strips the port from a net/http RemoteAddr for use as a
// per-client rate-limit key, handling bracketed IPv6 ([::1]:443 -> ::1).
// Falls back to the raw value when there is no host:port to split, so a
// missing port never collapses distinct clients onto one key.
func clientIPKey(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Redirect already-authenticated users to dashboard
	if s.isAuthenticated(r) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		s.renderTemplate(w, "login.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit: 5 attempts per minute per IP (strip port from RemoteAddr)
	ip := clientIPKey(r.RemoteAddr)
	s.loginMu.Lock()
	now := time.Now()
	attempts := s.loginAttempts[ip]
	var recent []time.Time
	for _, t := range attempts {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 5 {
		s.loginMu.Unlock()
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}
	s.loginAttempts[ip] = append(recent, now)
	s.loginMu.Unlock()

	token := r.FormValue("token")
	// Only admin-scope tokens may log in via the browser form.
	validLogin := false
	if token != "" {
		for _, tok := range s.cfg.WebUI.Tokens {
			if tok.Scope == "admin" && webUITokenMatches(token, tok) {
				validLogin = true
				break
			}
		}
	}
	if !validLogin {
		s.renderTemplate(w, "login.html", map[string]string{"Error": "Invalid token"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "csm_auth",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// --- Template helpers ---

func severityClass(sev alert.Severity) string {
	switch sev {
	case alert.Critical:
		return "critical"
	case alert.High:
		return "high"
	case alert.Warning:
		return "warning"
	default:
		return "info"
	}
}

func severityLabel(sev alert.Severity) string {
	switch sev {
	case alert.Critical:
		return "CRITICAL"
	case alert.High:
		return "HIGH"
	case alert.Warning:
		return "WARNING"
	default:
		return "INFO"
	}
}

// severityRank returns a numeric rank for severity labels (higher = more severe).
func severityRank(label string) int {
	switch label {
	case "CRITICAL":
		return 3
	case "HIGH":
		return 2
	case "WARNING":
		return 1
	default:
		return 0
	}
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// --- Security headers middleware ---

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("Cache-Control", "no-store")

		// CORS/origin validation: reject cross-origin API requests.
		// The allowed origin is derived from configuration, not from
		// the request's Host header. Reading r.Host would let a proxy
		// attacker forge a Host that matches their forged Origin and
		// trivially pass the equality check.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			origin := r.Header.Get("Origin")
			if origin != "" {
				allowed := s.canonicalAllowedOrigin()
				if !sameOrigin(origin, allowed) {
					http.Error(w, "Cross-origin request blocked", http.StatusForbidden)
					return
				}
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			// Deny CORS preflight from unknown origins
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		// API rate limiting: 600 requests per minute per IP
		if strings.HasPrefix(r.URL.Path, "/api/") {
			ip := clientIPKey(r.RemoteAddr)
			s.apiMu.Lock()
			now := time.Now()
			cutoff := now.Add(-time.Minute)
			var recent []time.Time
			for _, t := range s.apiRequests[ip] {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			if len(recent) >= 600 {
				s.apiMu.Unlock()
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			s.apiRequests[ip] = append(recent, now)
			s.apiMu.Unlock()
		}

		next.ServeHTTP(w, r)
	})
}

// --- CSRF protection ---

// csrfToken generates a deterministic CSRF token from an active admin secret.
// This is safe because the credential is secret and the CSRF token is derived
// via HMAC - knowing the CSRF token doesn't reveal the credential.
func (s *Server) csrfToken() string {
	secret := s.csrfSecret()
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	// Include start time so token rotates on each daemon restart
	fmt.Fprintf(mac, "csm-csrf-v1:%d", s.startTime.Unix())
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

func (s *Server) csrfSecret() string {
	for _, tok := range s.cfg.WebUI.Tokens {
		if tok.Scope == "admin" && tok.Token != "" {
			return tok.Token
		}
	}
	if len(s.cfg.WebUI.Tokens) == 0 {
		return s.cfg.WebUI.AuthToken
	}
	return ""
}

// validateCSRF enforces the browser-session CSRF boundary on state-changing
// routes. Bearer-authenticated requests skip the check because cross-origin
// browser requests cannot attach the Authorization header without script access
// to the bearer token.
func (s *Server) validateCSRF(r *http.Request) bool {
	if !isUnsafeCSRFMethod(r.Method) {
		return true // only validate state-changing methods
	}

	// Skip CSRF only when the bearer token itself grants admin writes. A
	// read-scope bearer presented alongside an admin cookie must not turn
	// the cookie-authenticated request into a CSRF-exempt API call.
	// CSRF protection is only needed for cookie-based browser sessions.
	if s.isAdminBearerAuth(r) {
		return true
	}

	expected := s.csrfToken()
	// A request without an active admin secret cannot prove it came from a
	// browser session, so the mutating path stays closed.
	if expected == "" {
		return false
	}

	// Check header (API calls from JS use this)
	if token := r.Header.Get("X-CSRF-Token"); token != "" {
		return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
	}

	// Check form field (traditional form posts)
	if token := r.FormValue("csrf_token"); token != "" {
		return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
	}

	return false
}

// requireCSRF wraps a handler to validate CSRF on POST, PUT, PATCH, and DELETE
// requests. PUT joined the unsafe set when /api/v1/prefs/user landed; the
// existing list pre-dates that endpoint.
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF for admin Bearer token auth. API-to-API callers do not
		// need CSRF protection, but read-scope bearer tokens never authorize
		// mutating handlers on their own.
		if isUnsafeCSRFMethod(r.Method) && !s.isAdminBearerAuth(r) && !s.validateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isUnsafeCSRFMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	default:
		return false
	}
}

func (s *Server) isBearerAuth(r *http.Request) bool {
	_, ok := s.bearerTokenWithScope(r, "read")
	return ok
}

func (s *Server) isAdminBearerAuth(r *http.Request) bool {
	_, ok := s.bearerTokenWithScope(r, "admin")
	return ok
}

// --- Logout ---

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csm_auth",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // delete cookie
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// --- Scan rate limiting ---

// acquireScan tries to start a scan. Returns false if a scan is already running.
func (s *Server) acquireScan() bool {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if s.scanRunning {
		return false
	}
	s.scanRunning = true
	return true
}

func (s *Server) releaseScan() {
	s.scanMu.Lock()
	s.scanRunning = false
	s.scanMu.Unlock()
}
