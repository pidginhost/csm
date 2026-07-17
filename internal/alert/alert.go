package alert

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/processctx"
)

const alertDispatchFailuresMetric = "csm_alert_dispatch_failures_total"

// alertDispatchFailures counts individual channel send failures (email,
// webhook, phpanel) so an operator can see when alerts are silently failing
// to deliver instead of the daemon looking healthy while findings never
// reach anyone.
var alertDispatchFailures = metrics.NewCounter(
	alertDispatchFailuresMetric,
	"Alert deliveries that failed (email/webhook/phpanel). Sustained growth means findings are being detected but not reaching operators -- check SMTP/webhook reachability and credentials.",
)

func init() {
	metrics.MustRegister(alertDispatchFailuresMetric, alertDispatchFailures)
}

func addDispatchError(errs *[]error, err error) {
	*errs = append(*errs, err)
	alertDispatchFailures.Inc()
}

// Severity levels for findings.
type Severity int

const (
	Warning  Severity = iota
	High     Severity = iota
	Critical Severity = iota
)

func (s Severity) String() string {
	switch s {
	case Warning:
		return "WARNING"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

// Finding represents a single security check result.
type Finding struct {
	Severity    Severity `json:"severity"`
	Check       string   `json:"check"`
	Message     string   `json:"message"`
	Details     string   `json:"details,omitempty"`
	FilePath    string   `json:"file_path,omitempty"`
	ProcessInfo string   `json:"process_info,omitempty"` // "pid=N cmd=name uid=N" from fanotify
	PID         int      `json:"pid,omitempty"`          // structured PID for auto-response

	// Content fingerprint for re-verifiable content findings (PHP heuristics,
	// signature, YARA). Set at emit time by content-family checks; empty for
	// all other finding kinds and for findings emitted before this field
	// existed. The re-verification re-check uses it to tell a superseded-
	// heuristic false positive (identical bytes, current logic no longer
	// flags) from a file edited after detection (never auto-cleared).
	ContentSHA256 string `json:"content_sha256,omitempty"`
	// DetectLogic is the checks.ContentDetectionVersion() token in effect when
	// this content finding was emitted. Optional; used for sweep gating and
	// audit explainability.
	DetectLogic string `json:"detect_logic,omitempty"`

	// PHP-relay structured fields (Stage 1 email_php_relay_abuse). All optional;
	// zero values mean "this finding does not carry that dimension".
	Path      string   `json:"path,omitempty"`       // path1 trigger label: "header" | "volume" | "volume_account" | "fanout" | "baseline" | "reputation"
	MsgIDs    []string `json:"msg_ids,omitempty"`    // sample of in-flight msgIDs (auto-action acts on the live snapshot, not this list)
	ScriptKey string   `json:"script_key,omitempty"` // host:path from X-PHP-Script
	SourceIP  string   `json:"source_ip,omitempty"`  // IP after "for " in X-PHP-Script
	CPUser    string   `json:"cp_user,omitempty"`    // cPanel user from spool -H line 2

	// RelayTotal is the trigger count for the PHP-relay path that fired
	// (qualifying/volume/fanout/account-window count). RelayBreakdown lists
	// the scripts that contributed, with per-script hit counts and a sample
	// subject. Both optional; volume_account carries RelayTotal with no
	// breakdown (account log-tail path has no trustworthy script key).
	RelayTotal     int              `json:"relay_total,omitempty"`
	RelayBreakdown []RelayScriptHit `json:"relay_breakdown,omitempty"`

	// Tenant context (added v2.12.0). Optional - populated when the check
	// has enough info to attribute the finding to a specific tenant within
	// a multi-tenant host. Empty strings render as omitted JSON keys so
	// existing webhook consumers see no diff.
	TenantID string `json:"tenant_id,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Mailbox  string `json:"mailbox,omitempty"`
	// SprayTargets carries the per-account targets for aggregate auth
	// findings. It is internal-only so API payloads keep the public Finding
	// contract while the incident correlator can count distinct targets.
	SprayTargets []string `json:"-"`
	// CIDRs carries the collapsed offending subnets for subnet-scoped
	// findings (http_asn_crawl). Internal-only so the public Finding/webhook
	// contract is unchanged; the subnet auto-response reads this, never the
	// Message/Details text.
	CIDRs []string `json:"-"`

	// Process context (Phase 1 process-ancestry enrichment). Optional.
	// Populated by exec/connection live monitors when cache or enricher
	// has data. Omitted from JSON when nil so existing webhook consumers
	// see no diff.
	Process *processctx.ProcessContext `json:"process,omitempty"`

	Timestamp time.Time `json:"timestamp"`

	// Full-scan quarantine outcome (Phase 2). Set ONLY on findings produced by a
	// `--full --quarantine` job; empty for all report-only findings so existing
	// consumers see no JSON diff.
	RemediationStatus string `json:"remediation_status,omitempty"` // "quarantined" | "left_for_review" | "failed"
	RemediationDetail string `json:"remediation_detail,omitempty"` // action description or error
}

// RelayScriptHit is one script's contribution to a PHP-relay finding.
type RelayScriptHit struct {
	ScriptKey     string    `json:"script_key"` // "host:/path" from X-PHP-Script
	Hits          int       `json:"hits"`       // messages counted in the path window
	LastSeen      time.Time `json:"last_seen"`
	SampleSubject string    `json:"sample_subject,omitempty"` // attacker-controlled; render escaped
}

func (f Finding) String() string {
	ts := f.Timestamp.Format("2006-01-02 15:04:05")
	s := fmt.Sprintf("[%s] %s - %s", f.Severity, f.Check, f.Message)
	if f.Details != "" {
		s += "\n  " + strings.ReplaceAll(f.Details, "\n", "\n  ")
	}
	if f.ProcessInfo != "" {
		s += fmt.Sprintf("\n  Process: %s", f.ProcessInfo)
	}
	s += fmt.Sprintf("\n  Time: %s", ts)
	return s
}

// Key returns a unique key for deduplication.
func (f Finding) Key() string {
	if key := f.sourceIPKey(); key != "" {
		return key
	}
	if f.Details == "" {
		return fmt.Sprintf("%s:%s", f.Check, f.Message)
	}
	h := sha256.Sum256([]byte(f.Details))
	return fmt.Sprintf("%s:%s:%x", f.Check, f.Message, h[:4])
}

// Fingerprint returns the content hash used by alert-state deduplication.
func (f Finding) Fingerprint() string {
	if key := f.sourceIPKey(); key != "" {
		h := sha256.Sum256([]byte(key))
		return fmt.Sprintf("%x", h[:8])
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", f.Check, f.Message, f.Details)))
	return fmt.Sprintf("%x", h[:8])
}

func (f Finding) sourceIPKey() string {
	switch f.Check {
	case "admin_panel_bruteforce", "wp_login_bruteforce", "wp_user_enumeration", "xmlrpc_abuse",
		"http_request_flood", "http_scanner_profile", "http_claimed_bot_unverified", "http_ua_spoof",
		"ftp_bruteforce":
	default:
		return ""
	}

	ip := normalizeFindingIP(f.SourceIP)
	if ip == "" {
		ip = sourceIPFromFindingMessage(f.Message)
	}
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("%s:ip:%s", f.Check, ip)
}

func normalizeFindingIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func sourceIPFromFindingMessage(msg string) string {
	for _, sep := range []string{" from ", ": "} {
		idx := strings.LastIndex(msg, sep)
		if idx < 0 {
			continue
		}
		rest := msg[idx+len(sep):]
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		candidate := strings.TrimRight(fields[0], ",:;)([]")
		if ip := normalizeFindingIP(candidate); ip != "" {
			return ip
		}
	}
	return ""
}

// SplitEmail returns (localpart, domain) from an email address. Returns
// ("", "") when the input doesn't look like an email.
func SplitEmail(addr string) (localpart, domain string) {
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return "", ""
	}
	return addr[:at], addr[at+1:]
}

// Deduplicate removes findings with the same Check+Message, keeping the first.
func Deduplicate(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var result []Finding
	for _, f := range findings {
		key := f.Key()
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}

// FormatAlert formats a list of findings into a human-readable alert body.
// Sensitive data (passwords, tokens) is redacted before sending.
func FormatAlert(hostname string, findings []Finding) string {
	var b strings.Builder

	critCount := 0
	highCount := 0
	warnCount := 0
	for _, f := range findings {
		switch f.Severity {
		case Critical:
			critCount++
		case High:
			highCount++
		case Warning:
			warnCount++
		}
	}

	fmt.Fprintf(&b, "SECURITY ALERT - %s\n", hostname)
	fmt.Fprintf(&b, "Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "Findings: %d critical, %d high, %d warning\n", critCount, highCount, warnCount)
	b.WriteString(strings.Repeat("─", 60) + "\n\n")

	for _, sev := range []Severity{Critical, High, Warning} {
		for _, f := range findings {
			if f.Severity == sev {
				b.WriteString(sanitizeFinding(f).String())
				b.WriteString("\n\n")
			}
		}
	}

	b.WriteString(strings.Repeat("─", 60) + "\n")
	b.WriteString("CSM - Continuous Security Monitor\n")

	return b.String()
}

// sanitizeFinding redacts sensitive data (passwords, tokens, secrets)
// from finding messages and details before including them in alerts.
func sanitizeFinding(f Finding) Finding {
	f.Message = redactSensitive(f.Message)
	f.Details = redactSensitive(f.Details)
	return f
}

// redactSensitive replaces password values and tokens in text with [REDACTED].
func redactSensitive(s string) string {
	if s == "" {
		return s
	}

	// Redact password= values in URLs and POST data.
	// Matches: password=X, pass=X, passwd=X (up to next & or space or quote).
	//
	// The search base advances past each replacement (or past an
	// empty-value occurrence) so we never re-match the same prefix
	// position on the next iteration. An earlier version of this code
	// restarted the search at position 0 after every replacement, which
	// re-found the same prefix and re-wrote `[REDACTED]` -> `[REDACTED]`
	// forever whenever the replacement was non-empty. That infinite
	// loop would hang the daemon's alert dispatch on any log line that
	// contained a populated password field.
	for _, prefix := range []string{
		"password=", "pass=", "passwd=", "new_password=",
		"old_password=", "confirmpassword=",
	} {
		searchFrom := 0
		for searchFrom < len(s) {
			lower := strings.ToLower(s[searchFrom:])
			rel := strings.Index(lower, prefix)
			if rel < 0 {
				break
			}
			idx := searchFrom + rel
			valStart := idx + len(prefix)
			valEnd := valStart
			for valEnd < len(s) {
				c := s[valEnd]
				if c == '&' || c == ' ' || c == '\n' || c == '"' || c == '\'' || c == ',' {
					break
				}
				valEnd++
			}
			if valEnd > valStart {
				s = s[:valStart] + "[REDACTED]" + s[valEnd:]
				searchFrom = valStart + len("[REDACTED]")
			} else {
				// Empty value (e.g. `password=&`): advance past this
				// occurrence so a later populated field is still redacted.
				searchFrom = valStart
			}
		}
	}

	// Redact API token values (long alphanumeric strings after token-like keys)
	for _, prefix := range []string{"token_value=", "api_token="} {
		lower := strings.ToLower(s)
		if idx := strings.Index(lower, prefix); idx >= 0 {
			valStart := idx + len(prefix)
			valEnd := valStart
			for valEnd < len(s) && s[valEnd] != ' ' && s[valEnd] != '\n' && s[valEnd] != '&' {
				valEnd++
			}
			if valEnd > valStart {
				s = s[:valStart] + "[REDACTED]" + s[valEnd:]
			}
		}
	}

	return s
}

func filterChecks(findings []Finding, disabledChecks []string) []Finding {
	if len(findings) == 0 || len(disabledChecks) == 0 {
		return findings
	}

	disabled := make(map[string]bool, len(disabledChecks))
	for _, check := range disabledChecks {
		check = strings.TrimSpace(check)
		if check != "" {
			disabled[check] = true
		}
	}
	if len(disabled) == 0 {
		return findings
	}

	filtered := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if !disabled[f.Check] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func buildSubject(hostname string, findings []Finding) string {
	subject := fmt.Sprintf("[CSM] %s - %d security finding(s)", hostname, len(findings))
	for _, f := range findings {
		if f.Severity == Critical {
			return fmt.Sprintf("[CSM] CRITICAL - %s - %d finding(s)", hostname, len(findings))
		}
	}
	return subject
}

// rateLimitState tracks alerts sent per hour.
type rateLimitState struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// FindingBus is set by the daemon at startup to the broadcast.Bus that
// passive observers (e.g. SSE subscribers) drain. nil-safe: Dispatch
// only publishes if non-nil. Importing the broadcast package directly
// would create an import cycle (broadcast imports alert), so this is
// declared as an interface satisfied by *broadcast.Bus.
var FindingBus interface {
	Publish(Finding)
}

// ReportHook, when set by the daemon at startup, is called once per
// deduplicated finding so the abuse reporter can consider it for submission to
// a central abuse database or collector. It must not block. Declared as a func
// to avoid an import cycle (the reporting package imports alert for the
// Finding type).
//
// Install or clear it with SetReportHook so Dispatch reads a consistent value.
var ReportHook func(Finding)

var reportHookMu sync.RWMutex

// SetReportHook installs or clears the abuse-reporting hook used by Dispatch.
func SetReportHook(h func(Finding)) {
	reportHookMu.Lock()
	ReportHook = h
	reportHookMu.Unlock()
}

func currentReportHook() func(Finding) {
	reportHookMu.RLock()
	h := ReportHook
	reportHookMu.RUnlock()
	return h
}

func callReportHook(f Finding) {
	h := currentReportHook()
	if h == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "alert: report hook panic")
		}
	}()
	h(f)
}

// CentralHook, when set by the daemon, is called once per deduplicated finding
// so the central-intel consumer can escalate (challenge/block) when the
// finding's IP is in the verified central scored-set. A finding firing on an IP
// is the node's own local signal, so this is the local-corroboration path.
// Must not block. Install or clear with SetCentralHook.
var CentralHook func(Finding)

var centralHookMu sync.RWMutex

// SetCentralHook installs or clears the central-intel hook used by Dispatch.
func SetCentralHook(h func(Finding)) {
	centralHookMu.Lock()
	CentralHook = h
	centralHookMu.Unlock()
}

func currentCentralHook() func(Finding) {
	centralHookMu.RLock()
	h := CentralHook
	centralHookMu.RUnlock()
	return h
}

func callCentralHook(f Finding) {
	h := currentCentralHook()
	if h == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "alert: central hook panic")
		}
	}()
	h(f)
}

type rateLimitKey struct {
	StatePath string
	Hour      string
}

type rateLimitReservation struct {
	key    rateLimitKey
	active bool
}

var (
	rateLimitMu      sync.Mutex
	rateLimitPending = make(map[rateLimitKey]int)
)

// reserveRateLimit reports whether the per-hour alert budget can absorb
// another send without committing the slot. The in-memory reservation
// prevents concurrent dispatches from all taking the same final slot while
// the outbound channel is still blocked on SMTP or webhook I/O.
func reserveRateLimit(statePath string, maxPerHour int) (*rateLimitReservation, bool) {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	if maxPerHour <= 0 {
		return nil, false
	}

	currentHour := time.Now().Format("2006-01-02T15")
	rlPath := filepath.Join(statePath, "ratelimit.json")

	var rl rateLimitState
	// #nosec G304 -- filepath.Join(statePath, "ratelimit.json"); statePath from operator config.
	data, err := os.ReadFile(rlPath)
	if err == nil {
		_ = json.Unmarshal(data, &rl)
	}
	count := 0
	if rl.Hour != currentHour {
		count = 0
	} else {
		count = rl.Count
	}

	key := rateLimitKey{StatePath: statePath, Hour: currentHour}
	if count+rateLimitPending[key] >= maxPerHour {
		return nil, false
	}
	rateLimitPending[key]++
	return &rateLimitReservation{key: key, active: true}, true
}

func releaseRateLimit(reservation *rateLimitReservation) {
	if reservation == nil {
		return
	}
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()
	releaseRateLimitLocked(reservation)
}

func releaseRateLimitLocked(reservation *rateLimitReservation) {
	if reservation == nil || !reservation.active {
		return
	}
	if pending := rateLimitPending[reservation.key]; pending <= 1 {
		delete(rateLimitPending, reservation.key)
	} else {
		rateLimitPending[reservation.key] = pending - 1
	}
	reservation.active = false
}

// commitRateLimit records one successful dispatch toward the hourly
// budget. Logs the WriteFile error so a disk-full or perm regression
// surfaces in the daemon log instead of silently letting the counter
// drift from the on-disk record.
func commitRateLimit(statePath string, reservation *rateLimitReservation) {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	releaseRateLimitLocked(reservation)

	currentHour := time.Now().Format("2006-01-02T15")
	rlPath := filepath.Join(statePath, "ratelimit.json")

	var rl rateLimitState
	// #nosec G304 -- filepath.Join under operator-configured statePath.
	if data, err := os.ReadFile(rlPath); err == nil {
		_ = json.Unmarshal(data, &rl)
	}
	if rl.Hour != currentHour {
		rl = rateLimitState{Hour: currentHour}
	}
	rl.Count++
	newData, err := json.Marshal(rl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "alert: rate-limit marshal failed: %v\n", err)
		return
	}
	if err := os.WriteFile(rlPath, newData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "alert: rate-limit write failed for %s: %v\n", rlPath, err)
	}
}

// checkRateLimit returns true if we can send more alerts this hour.
//
// Deprecated: kept for callers that expect the check-and-increment pattern.
// New code should use reserveRateLimit and commitRateLimit so a failed
// dispatch does not consume the operator's budget.
func checkRateLimit(statePath string, maxPerHour int) bool {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	rlPath := filepath.Join(statePath, "ratelimit.json")

	currentHour := time.Now().Format("2006-01-02T15")

	var rl rateLimitState
	// #nosec G304 -- filepath.Join(statePath, "ratelimit.json"); statePath from operator config.
	data, err := os.ReadFile(rlPath)
	if err == nil {
		_ = json.Unmarshal(data, &rl)
	}

	// Reset if new hour
	if rl.Hour != currentHour {
		rl = rateLimitState{Hour: currentHour, Count: 0}
	}

	if rl.Count >= maxPerHour {
		return false
	}

	rl.Count++
	newData, _ := json.Marshal(rl)
	_ = os.WriteFile(rlPath, newData, 0600)

	return true
}

func formatDispatchErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return fmt.Errorf("alert dispatch errors: %s", strings.Join(msgs, "; "))
}

// Dispatch sends alerts via all configured channels.
func Dispatch(cfg *config.Config, findings []Finding) error {
	// Deduplicate
	findings = Deduplicate(findings)

	// Audit log captures every (deduplicated) finding before
	// FilterBlockedAlerts and the rate limiter, so SIEMs see the
	// complete picture even when email/webhook are throttled or
	// when "this IP is already blocked" suppression hides a finding
	// from the operator-facing channels.
	emitAudit(cfg, findings)

	// Publish to passive observers (e.g. SSE subscribers) immediately after
	// auditing, before rate-limit and webhook delivery, so subscribers see
	// the complete picture even when operator-facing channels are throttled.
	if FindingBus != nil {
		for _, f := range findings {
			FindingBus.Publish(f)
		}
	}

	// Offer every finding to the abuse reporter (it gates and minimizes
	// internally, queueing only confirmed-abuse findings for the drain loop)
	// and to the central-intel consumer (it escalates findings whose IP is in
	// the verified central scored-set).
	for _, f := range findings {
		callReportHook(f)
		callCentralHook(f)
	}

	var errs []error

	// Phpanel consumes this webhook as a signed data-plane stream. Send the
	// full deduplicated stream before operator notification suppression and
	// rate limiting, otherwise fleet correlation can miss attacker spread.
	phpanelWebhook := cfg.Alerts.Webhook.Enabled && cfg.Alerts.Webhook.Type == "phpanel"
	if phpanelWebhook {
		if err := enqueuePhpanelFindings(cfg, findings); err != nil {
			addDispatchError(&errs, err)
		}
	}

	// Filter out blocked IP alerts if configured
	findings = FilterBlockedAlerts(cfg, findings)

	if len(findings) == 0 {
		return formatDispatchErrors(errs)
	}

	emailFindings := []Finding(nil)
	if cfg.Alerts.Email.Enabled {
		emailFindings = filterChecks(findings, cfg.Alerts.Email.DisabledChecks)
	}

	webhookFindings := []Finding(nil)
	if cfg.Alerts.Webhook.Enabled && !phpanelWebhook {
		webhookFindings = findings
	}

	if len(emailFindings) == 0 && len(webhookFindings) == 0 {
		return formatDispatchErrors(errs)
	}

	// Critical realtime findings always get through. Reputation delivery is
	// also check-keyed: its surface-based severity is presentation metadata and
	// must not make sightings that previously bypassed this gate disappear.
	bypassRateLimit := false
	for _, f := range findings {
		if f.Severity == Critical || f.Check == "ip_reputation" {
			bypassRateLimit = true
			break
		}
	}
	var reservation *rateLimitReservation
	if !bypassRateLimit {
		var ok bool
		reservation, ok = reserveRateLimit(cfg.StatePath, cfg.Alerts.MaxPerHour)
		if !ok {
			fmt.Fprintf(os.Stderr, "Alert rate limit reached (%d/hour), skipping non-critical alert dispatch\n", cfg.Alerts.MaxPerHour)
			return formatDispatchErrors(errs)
		}
		defer releaseRateLimit(reservation)
	}

	dispatched := false

	if len(emailFindings) > 0 {
		subject := buildSubject(cfg.Hostname, emailFindings)
		body := FormatAlert(cfg.Hostname, emailFindings)
		if err := SendEmail(cfg, subject, body); err != nil {
			addDispatchError(&errs, fmt.Errorf("email: %w", err))
		} else {
			dispatched = true
		}
	}

	if len(webhookFindings) > 0 {
		subject := buildSubject(cfg.Hostname, webhookFindings)
		body := FormatAlert(cfg.Hostname, webhookFindings)
		if err := SendWebhook(cfg, subject, body); err != nil {
			addDispatchError(&errs, fmt.Errorf("webhook: %w", err))
		} else {
			dispatched = true
		}
	}

	// Commit the rate-limit slot only after at least one channel
	// accepted the message. Without this, a failed send burned the
	// budget; the next non-critical alert was then throttled with no
	// operator-facing trace.
	if dispatched {
		commitRateLimit(cfg.StatePath, reservation)
	}

	return formatDispatchErrors(errs)
}

// SendHeartbeat pings a dead man's switch URL.
func SendHeartbeat(cfg *config.Config) {
	if !cfg.Alerts.Heartbeat.Enabled || cfg.Alerts.Heartbeat.URL == "" {
		return
	}
	client := httpClient(10 * time.Second)
	resp, err := client.Get(cfg.Alerts.Heartbeat.URL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Heartbeat failed: %v\n", err)
		return
	}
	defer closeWebhookResponseBody(resp)
}
