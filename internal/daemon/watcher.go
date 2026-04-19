package daemon

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/store"
)

// LogLineHandler parses a log line and returns findings (if any).
type LogLineHandler func(line string, cfg *config.Config) []alert.Finding

// LogWatcher tails a log file using inotify and processes new lines.
type LogWatcher struct {
	path    string
	cfg     *config.Config
	handler LogLineHandler
	alertCh chan<- alert.Finding
	file    *os.File
	offset  int64
}

// NewLogWatcher creates a watcher for a log file.
func NewLogWatcher(path string, cfg *config.Config, handler LogLineHandler, alertCh chan<- alert.Finding) (*LogWatcher, error) {
	// #nosec G304 -- path is operator-configured log path from csm.yaml.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Seek to end - only process new lines
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	return &LogWatcher{
		path:    path,
		cfg:     cfg,
		handler: handler,
		alertCh: alertCh,
		file:    f,
		offset:  offset,
	}, nil
}

// Run starts watching the log file. Uses polling (every 2 seconds) instead of
// inotify to avoid complexity with log rotation. Simple, reliable, low overhead.
func (w *LogWatcher) Run(stopCh <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Also reopen the file every 5 minutes to handle log rotation
	reopenTicker := time.NewTicker(5 * time.Minute)
	defer reopenTicker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-reopenTicker.C:
			w.reopen()
		case <-ticker.C:
			w.readNewLines()
		}
	}
}

// Stop closes the watcher.
func (w *LogWatcher) Stop() {
	if w.file != nil {
		_ = w.file.Close()
	}
}

func (w *LogWatcher) readNewLines() {
	info, err := w.file.Stat()
	if err != nil {
		w.reopen()
		return
	}

	// File was truncated or rotated (smaller than our offset)
	if info.Size() < w.offset {
		w.reopen()
		return
	}

	// No new data
	if info.Size() == w.offset {
		return
	}

	// Seek to where we left off
	_, err = w.file.Seek(w.offset, io.SeekStart)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(w.file)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		findings := w.handler(line, w.cfg)
		for _, f := range findings {
			if f.Timestamp.IsZero() {
				f.Timestamp = time.Now()
			}
			select {
			case w.alertCh <- f:
			default:
				// Channel full - drop (backpressure)
				fmt.Fprintf(os.Stderr, "[%s] Warning: alert channel full, dropping finding from %s\n", ts(), w.path)
			}
		}
	}

	// Update offset
	newOffset, err := w.file.Seek(0, io.SeekCurrent)
	if err == nil {
		w.offset = newOffset
	}
}

func (w *LogWatcher) reopen() {
	if w.file != nil {
		_ = w.file.Close()
	}

	f, err := os.Open(w.path)
	if err != nil {
		return
	}

	// If the file is new (after rotation), start from beginning
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return
	}

	w.file = f
	if info.Size() < w.offset {
		// File was rotated - read from start
		w.offset = 0
	} else {
		// Same file or larger - seek to where we were
		w.offset, _ = f.Seek(0, io.SeekEnd)
	}
}

// --- Log line handlers ---

func parseSessionLogLine(line string, cfg *config.Config) []alert.Finding {
	var findings []alert.Finding

	// cPanel login from non-infra IP - only alert on direct form login,
	// not API-created sessions (from portal create_user_session)
	if strings.Contains(line, "[cpaneld]") && strings.Contains(line, " NEW ") {
		// Track IP→account for purge correlation (before any filtering)
		if loginIP, loginAccount := parseCpanelSessionLogin(line); loginIP != "" && loginAccount != "" {
			purgeTracker.recordLogin(loginIP, loginAccount)
		}

		switch {
		case cfg.Suppressions.SuppressCpanelLogin:
			// Skip all cPanel login alerts
		case strings.Contains(line, "method=create_user_session") ||
			strings.Contains(line, "method=create_session") ||
			strings.Contains(line, "create_user_session"):
			// Portal-created session - no alert
		default:
			ip, account := parseCpanelSessionLogin(line)
			if ip != "" && account != "" && !isInfraIPDaemon(ip, cfg.InfraIPs) &&
				!isTrustedCountry(ip, cfg.Suppressions.TrustedCountries) {
				// WARNING severity - logins are useful for audit trail but
				// not paging-level. Multi-IP correlation and brute-force
				// stay at CRITICAL/HIGH via their own checks.
				method := "unknown"
				if strings.Contains(line, "method=handle_form_login") {
					method = "direct form login"
				} else if idx := strings.Index(line, "method="); idx >= 0 {
					rest := line[idx+7:]
					if comma := strings.IndexAny(rest, ",\n "); comma > 0 {
						method = rest[:comma]
					}
				}
				findings = append(findings, alert.Finding{
					Severity: alert.Warning,
					Check:    "cpanel_login_realtime",
					Message:  fmt.Sprintf("cPanel direct login from non-infra IP: %s (account: %s, method: %s)", ip, account, method),
					Details:  truncateDaemon(line, 300),
				})
			}
		}
	}

	// Password purge
	if strings.Contains(line, "PURGE") && strings.Contains(line, "password_change") {
		account := parsePurgeDaemon(line)
		if account != "" {
			purgeTracker.recordPurge(account)
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "cpanel_password_purge_realtime",
				Message:  fmt.Sprintf("cPanel password purge for: %s", account),
			})
		}
	}

	return findings
}

func parseSecureLogLine(line string, cfg *config.Config) []alert.Finding {
	var findings []alert.Finding

	if !strings.Contains(line, "Accepted") {
		return nil
	}

	// Extract IP
	parts := strings.Fields(line)
	for i, p := range parts {
		if p == "from" && i+1 < len(parts) {
			ip := parts[i+1]
			if isInfraIPDaemon(ip, cfg.InfraIPs) || ip == "127.0.0.1" {
				return nil
			}

			user := "unknown"
			for j, q := range parts {
				if q == "for" && j+1 < len(parts) {
					user = parts[j+1]
					break
				}
			}

			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "ssh_login_realtime",
				Message:  fmt.Sprintf("SSH login from non-infra IP: %s (user: %s)", ip, user),
				Details:  truncateDaemon(line, 200),
			})
			break
		}
	}

	return findings
}

func parseEximLogLine(line string, cfg *config.Config) []alert.Finding {
	var findings []alert.Finding

	// 1. Frozen bounces - spam indicator
	if strings.Contains(line, "frozen") {
		findings = append(findings, alert.Finding{
			Severity: alert.Warning,
			Check:    "exim_frozen_realtime",
			Message:  "Exim frozen message detected",
			Details:  truncateDaemon(line, 200),
		})
	}

	// 2. Outgoing mail hold - account suspended for spam
	// Format: "Sender office@example.com has an outgoing mail hold"
	// or: "Domain example.org has an outgoing mail hold"
	// Dedup: only alert once per domain per hour (exim retries held messages
	// every few minutes, generating the same log line each time)
	if strings.Contains(line, "outgoing mail hold") {
		sender := extractMailHoldSender(line)
		if sender == "" {
			sender = extractEximSender(line)
		}
		domain := extractDomainFromEmail(sender)
		if domain == "" {
			domain = sender // may already be a bare domain
		}

		// Auto-suspend regardless of dedup - idempotent, ensures hold stays on
		if sender != "" {
			autoSuspendOutgoingMail(sender)
		}
		if domain != "" {
			RecordCompromisedDomain(domain)
		}

		// Alert only once per domain per hour
		dedupKey := "email_hold:" + domain
		if db := store.Global(); db != nil {
			lastAlert := db.GetMetaString(dedupKey)
			if lastAlert != "" && !isDedupExpired(lastAlert, 1*time.Hour) {
				// Already alerted for this domain recently - skip finding
			} else {
				_ = db.SetMetaString(dedupKey, time.Now().Format(time.RFC3339))
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "email_compromised_account",
					Message:  fmt.Sprintf("Account %s has outgoing mail hold - outgoing mail auto-suspended", sender),
					Details:  truncateDaemon(line, 300),
				})
			}
		}
	}

	// 3. Max defers/failures exceeded - active spam outbreak
	if strings.Contains(line, "max defers and failures per hour") {
		domain := extractEximDomain(line)
		// Auto-suspend: confirmed spam outbreak
		autoSuspendOutgoingMail(domain)
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "email_spam_outbreak",
			Message:  fmt.Sprintf("Spam outbreak: %s exceeded max defers/failures - outgoing mail auto-suspended", domain),
			Details:  truncateDaemon(line, 300),
		})
		if domain != "" {
			RecordCompromisedDomain(domain)
		}
	}

	// 4. SMTP credentials leaked in subject - compromised account
	// Pattern: T="...host:port,user@domain,PASSWORD..." in the subject field
	if strings.Contains(line, " <= ") && strings.Contains(line, "T=\"") {
		subject := extractEximSubject(line)
		subjectLower := strings.ToLower(subject)
		// Detect credential patterns: host:port,user,password or
		// SMTP credentials in subject (common in credential stuffing attacks)
		if (strings.Contains(subject, ":587,") || strings.Contains(subject, ":465,") ||
			strings.Contains(subject, ":25,")) &&
			strings.Contains(subject, "@") {
			sender := extractEximSender(line)
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "email_credential_leak",
				Message:  fmt.Sprintf("SMTP credentials leaked in email subject from %s", sender),
				Details:  fmt.Sprintf("The email subject contains what appears to be SMTP credentials (host:port,user,password). This account is likely compromised by a bulk mail service.\nSubject: %s", truncateDaemon(subject, 100)),
			})
		}
		// Also detect common spam subject patterns
		if strings.Contains(subjectLower, "password") && strings.Contains(subjectLower, "smtp") {
			sender := extractEximSender(line)
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "email_credential_leak",
				Message:  fmt.Sprintf("Suspicious email subject with SMTP/password keywords from %s", sender),
				Details:  truncateDaemon(line, 300),
			})
		}
	}

	// 5. Authentication from known bulk mail services
	if strings.Contains(line, " <= ") && strings.Contains(line, "A=dovecot_") {
		knownSpamServices := []string{
			"truelist.io", "sendinblue.com", "mailspree.co",
			"bulkmailer.", "massmailsoftware.", "sendblaster.",
		}
		lineLower := strings.ToLower(line)
		for _, service := range knownSpamServices {
			if strings.Contains(lineLower, service) {
				sender := extractEximSender(line)
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "email_compromised_account",
					Message:  fmt.Sprintf("Compromised email account %s authenticated from bulk mail service %s", sender, service),
					Details:  truncateDaemon(line, 300),
				})
				break
			}
		}
	}

	// 6. Dovecot auth failure - brute force indicator
	// Format: "dovecot_login authenticator failed for H=(hostname) [IP]:port: 535 ... (set_id=user@domain)"
	if strings.Contains(line, "authenticator failed") && strings.Contains(line, "dovecot") {
		ip := extractBracketedIP(line)
		account := extractSetID(line)
		msg := "Email authentication failure"
		if account != "" {
			msg += " for " + account
		}
		if ip != "" {
			msg += " from " + ip
		}
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "email_auth_failure_realtime",
			Message:  msg,
			Details:  truncateDaemon(line, 300),
		})
	}

	// 7. DKIM signing failures
	if dkimDomain := parseDKIMFailureDomain(line); dkimDomain != "" {
		dedupKey := "dkim_fail:" + dkimDomain
		if db := store.Global(); db != nil {
			lastAlert := db.GetMetaString(dedupKey)
			if lastAlert == "" || isDedupExpired(lastAlert, 24*time.Hour) {
				_ = db.SetMetaString(dedupKey, time.Now().Format(time.RFC3339))
				findings = append(findings, alert.Finding{
					Severity:  alert.Warning,
					Check:     "email_dkim_failure",
					Message:   fmt.Sprintf("DKIM signing failed for %s - check key file and DNS TXT record", dkimDomain),
					Details:   truncateDaemon(line, 300),
					Timestamp: time.Now(),
				})
			}
		}
	}

	// 8. SPF/DMARC outbound rejections
	if spfDomain, spfReason := parseSPFDMARCRejection(line); spfDomain != "" {
		dedupKey := "spf_reject:" + spfDomain
		if db := store.Global(); db != nil {
			lastAlert := db.GetMetaString(dedupKey)
			if lastAlert == "" || isDedupExpired(lastAlert, 24*time.Hour) {
				_ = db.SetMetaString(dedupKey, time.Now().Format(time.RFC3339))
				findings = append(findings, alert.Finding{
					Severity:  alert.High,
					Check:     "email_spf_rejection",
					Message:   fmt.Sprintf("Outbound mail from %s rejected due to SPF/DMARC failure", spfDomain),
					Details:   fmt.Sprintf("Reason: %s\n%s", spfReason, truncateDaemon(line, 200)),
					Timestamp: time.Now(),
				})
			}
		}
	}

	// 9. Outbound rate limiting for authenticated users
	if strings.Contains(line, " <= ") && strings.Contains(line, "A=dovecot_") {
		authUser := extractAuthUser(line)
		if authUser != "" {
			rateFindings := checkEmailRate(authUser, cfg)
			findings = append(findings, rateFindings...)
		}
	}

	return findings
}

// extractEximSender extracts the sender address from an exim log line.
// Format: "... <= sender@domain.com H=..."
func extractEximSender(line string) string {
	idx := strings.Index(line, " <= ")
	if idx < 0 {
		return ""
	}
	rest := line[idx+4:]
	fields := strings.Fields(rest)
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// extractEximDomain extracts a domain from an exim log line mentioning
// "Domain X has exceeded".
func extractEximDomain(line string) string {
	idx := strings.Index(line, "Domain ")
	if idx < 0 {
		return ""
	}
	rest := line[idx+7:]
	if sp := strings.IndexByte(rest, ' '); sp > 0 {
		return rest[:sp]
	}
	return rest
}

// extractEximSubject extracts the subject from T="..." in an exim log line.
func extractEximSubject(line string) string {
	idx := strings.Index(line, "T=\"")
	if idx < 0 {
		return ""
	}
	rest := line[idx+3:]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// --- Helpers (avoid import cycle with checks package) ---

func parseCpanelSessionLogin(line string) (ip, account string) {
	idx := strings.Index(line, "[cpaneld]")
	if idx < 0 {
		return "", ""
	}
	rest := strings.TrimSpace(line[idx+len("[cpaneld]"):])
	fields := strings.Fields(rest)
	if len(fields) < 3 {
		return "", ""
	}
	ip = fields[0]
	for i, f := range fields {
		if f == "NEW" && i+1 < len(fields) {
			parts := strings.SplitN(fields[i+1], ":", 2)
			if len(parts) >= 1 {
				account = parts[0]
			}
			break
		}
	}
	return ip, account
}

func parsePurgeDaemon(line string) string {
	idx := strings.Index(line, "PURGE")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[idx+len("PURGE"):])
	fields := strings.Fields(rest)
	if len(fields) < 1 {
		return ""
	}
	parts := strings.SplitN(fields[0], ":", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
}

func isInfraIPDaemon(ip string, infraNets []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range infraNets {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as plain IP
			if ip == cidr {
				return true
			}
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// mergeInfraIPs combines top-level infra IPs with firewall-specific ones,
// deduplicating entries. This allows the firewall to include additional CIDRs
// (e.g. server's own range) that need port access but shouldn't suppress alerts.
func mergeInfraIPs(topLevel, fwSpecific []string) []string {
	seen := make(map[string]bool, len(topLevel)+len(fwSpecific))
	var merged []string
	for _, ip := range topLevel {
		if !seen[ip] {
			seen[ip] = true
			merged = append(merged, ip)
		}
	}
	for _, ip := range fwSpecific {
		if !seen[ip] {
			seen[ip] = true
			merged = append(merged, ip)
		}
	}
	return merged
}

// autoSuspendOutgoingMail calls whmapi1 to hold outgoing mail for the cPanel
// account that owns the given domain or email address. This is safe to call
// on confirmed spam (cPanel already flagged it via mail hold or max defers).
func autoSuspendOutgoingMail(domainOrEmail string) {
	if domainOrEmail == "" {
		return
	}
	// Extract domain from email if needed
	domain := domainOrEmail
	if atIdx := strings.LastIndexByte(domain, '@'); atIdx >= 0 {
		domain = domain[atIdx+1:]
	}
	// Look up cPanel username for this domain
	user := lookupCPanelUser(domain)
	if user == "" {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: could not find cPanel user for domain %s\n",
			time.Now().Format("2006-01-02 15:04:05"), domain)
		return
	}
	// Hold outgoing mail
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- whmapi1 is the cPanel API binary; user is a cPanel
	// account name validated upstream (cpuser regex in the caller).
	out, err := exec.CommandContext(ctx, "whmapi1", "hold_outgoing_email", "user="+user).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: whmapi1 hold_outgoing_email failed for %s: %v\n%s\n",
			time.Now().Format("2006-01-02 15:04:05"), user, err, string(out))
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] AUTO-SUSPEND: outgoing mail held for cPanel user %s (domain: %s)\n",
		time.Now().Format("2006-01-02 15:04:05"), user, domain)
}

// userdomainsPath is the cPanel domain→user map file. var (not const)
// so tests can point it at a fixture under t.TempDir(). Production must
// not mutate at runtime.
var userdomainsPath = "/etc/userdomains"

// lookupCPanelUser finds the cPanel username that owns a domain.
// Reads userdomainsPath which maps "domain: user" per line.
func lookupCPanelUser(domain string) string {
	f, err := os.Open(userdomainsPath)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		d := strings.TrimSpace(parts[0])
		u := strings.TrimSpace(parts[1])
		if strings.EqualFold(d, domain) {
			return u
		}
	}
	return ""
}

// extractMailHoldSender extracts the account/domain from outgoing mail hold messages.
//
// Two formats:
//
//	"Sender user@domain has an outgoing mail hold" -> "user@domain"
//	"Domain example.com has an outgoing mail hold" -> "example.com"
func extractMailHoldSender(line string) string {
	// Try "Sender user@domain" first
	if idx := strings.Index(line, "Sender "); idx >= 0 {
		rest := line[idx+7:]
		if sp := strings.IndexByte(rest, ' '); sp > 0 {
			return rest[:sp]
		}
		return rest
	}
	// Try "Domain example.com" format
	if idx := strings.Index(line, "Domain "); idx >= 0 {
		rest := line[idx+7:]
		if sp := strings.IndexByte(rest, ' '); sp > 0 {
			return rest[:sp]
		}
		return rest
	}
	return ""
}

// extractBracketedIP extracts an IP from [IP]:port or [IP] format in exim logs.
func extractBracketedIP(line string) string {
	// Find the LAST [IP] in the line (the client IP, not the hostname)
	lastBracket := strings.LastIndex(line, "[")
	if lastBracket < 0 {
		return ""
	}
	rest := line[lastBracket+1:]
	end := strings.IndexByte(rest, ']')
	if end < 0 {
		return ""
	}
	ip := rest[:end]
	if len(ip) >= 7 && (ip[0] >= '0' && ip[0] <= '9' || ip[0] == ':') {
		return ip
	}
	return ""
}

// extractSetID extracts the account from "(set_id=user@domain)" or "(set_id=user)" in exim logs.
func extractSetID(line string) string {
	const prefix = "set_id="
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(prefix):]
	end := strings.IndexAny(rest, ")\n ")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func truncateDaemon(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// parseDKIMFailureDomain extracts domain from "DKIM: signing failed for {domain}"
func parseDKIMFailureDomain(line string) string {
	const prefix = "DKIM: signing failed for "
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(prefix):]
	end := strings.IndexAny(rest, ": \t\n")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// parseSPFDMARCRejection extracts SENDER domain and rejection reason from
// exim ** permanent failure lines. Sender comes from <envelope_sender>.
func parseSPFDMARCRejection(line string) (senderDomain, reason string) {
	starIdx := strings.Index(line, " ** ")
	if starIdx < 0 {
		return "", ""
	}
	// Extract envelope sender from <sender@domain> - search AFTER the **
	// marker to avoid matching earlier <> fields (e.g. H=<hostname>).
	rest := line[starIdx:]
	ltIdx := strings.Index(rest, "<")
	gtIdx := strings.Index(rest, ">")
	if ltIdx < 0 || gtIdx < 0 || gtIdx <= ltIdx+1 {
		return "", ""
	}
	sender := rest[ltIdx+1 : gtIdx]
	atIdx := strings.LastIndexByte(sender, '@')
	if atIdx < 0 || atIdx >= len(sender)-1 {
		return "", ""
	}
	domain := sender[atIdx+1:]

	// Extract rejection reason after last " : "
	colonIdx := strings.LastIndex(line, " : ")
	if colonIdx < 0 {
		return "", ""
	}
	reason = strings.TrimSpace(line[colonIdx+3:])
	if !isSPFDMARCRelated(reason) {
		return "", ""
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	return domain, reason
}

// isSPFDMARCRelated checks if a rejection reason is SPF/DMARC related.
// Generic 5.7.1 alone is NOT sufficient - requires explicit auth keywords.
func isSPFDMARCRelated(reason string) bool {
	if reason == "" {
		return false
	}
	lower := strings.ToLower(reason)
	for _, kw := range []string{"spf", "dmarc", "dkim"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	for _, code := range []string{"5.7.23", "5.7.25", "5.7.26"} {
		if strings.Contains(lower, code) {
			return true
		}
	}
	if strings.Contains(lower, "5.7.1") {
		if strings.Contains(lower, "authentication") || strings.Contains(lower, "ptr record") ||
			strings.Contains(lower, "sender policy") || strings.Contains(lower, "alignment") {
			return true
		}
	}
	return false
}

// isDedupExpired checks if a stored RFC3339 timestamp is older than the given duration.
func isDedupExpired(stored string, window time.Duration) bool {
	t, err := time.Parse(time.RFC3339, stored)
	if err != nil {
		return true
	}
	return time.Since(t) > window
}

// --- Outbound email rate limiting ---

// rateWindow tracks send timestamps for a single authenticated user.
type rateWindow struct {
	mu      sync.Mutex
	times   []time.Time
	alerted string // last threshold level alerted ("warn" or "crit") - prevents repeated alerts per window
}

// add appends a timestamp to the window.
func (rw *rateWindow) add(t time.Time) {
	rw.times = append(rw.times, t)
}

// countInWindow returns the number of timestamps within the window duration.
// Caller must hold rw.mu.
func (rw *rateWindow) countInWindow(now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	count := 0
	for _, t := range rw.times {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// prune removes timestamps older than the window duration and resets the
// alerted flag when the count drops below thresholds. Caller must hold rw.mu.
func (rw *rateWindow) prune(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	kept := rw.times[:0]
	for _, t := range rw.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	rw.times = kept
}

// emailRateWindows tracks per-user send rate windows.
var emailRateWindows sync.Map // map[string]*rateWindow

// extractAuthUser extracts the authenticated user from an exim <= line.
// Looks for A=dovecot_login:{user} or A=dovecot_plain:{user}.
// Returns empty string if not found or line is not an acceptance line.
func extractAuthUser(line string) string {
	if !strings.Contains(line, " <= ") {
		return ""
	}

	// Look for A=dovecot_login: or A=dovecot_plain:
	for _, prefix := range []string{"A=dovecot_login:", "A=dovecot_plain:"} {
		idx := strings.Index(line, prefix)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(prefix):]
		end := strings.IndexAny(rest, " \t\n")
		if end < 0 {
			return rest
		}
		return rest[:end]
	}
	return ""
}

// isHighVolumeSender checks if a user is in the high-volume senders allowlist.
func isHighVolumeSender(user string, allowlist []string) bool {
	for _, allowed := range allowlist {
		if strings.EqualFold(user, allowed) {
			return true
		}
	}
	return false
}

// extractDomainFromEmail returns the domain part of an email address.
func extractDomainFromEmail(email string) string {
	idx := strings.LastIndexByte(email, '@')
	if idx < 0 || idx >= len(email)-1 {
		return ""
	}
	return email[idx+1:]
}

// hasRecentCompromisedFinding checks if there's a recent email_compromised_account
// or email_spam_outbreak finding for the given domain (suppresses rate alerts).
func hasRecentCompromisedFinding(domain string) bool {
	emailRateSuppressed.mu.Lock()
	defer emailRateSuppressed.mu.Unlock()
	if ts, ok := emailRateSuppressed.domains[domain]; ok {
		if time.Since(ts) < time.Hour {
			return true
		}
		delete(emailRateSuppressed.domains, domain)
	}
	return false
}

// emailRateSuppressed tracks domains with recent compromised/spam findings.
var emailRateSuppressed = struct {
	mu      sync.Mutex
	domains map[string]time.Time
}{domains: make(map[string]time.Time)}

// RecordCompromisedDomain marks a domain as having a recent compromised finding.
// Called from parseEximLogLine when email_compromised_account or email_spam_outbreak fires.
func RecordCompromisedDomain(domain string) {
	emailRateSuppressed.mu.Lock()
	defer emailRateSuppressed.mu.Unlock()
	emailRateSuppressed.domains[domain] = time.Now()
}

// checkEmailRate processes an outbound email for rate limiting.
// Returns findings if thresholds are exceeded.
func checkEmailRate(user string, cfg *config.Config) []alert.Finding {
	// Guard: skip if thresholds are zero (misconfigured or disabled)
	if cfg.EmailProtection.RateWarnThreshold <= 0 || cfg.EmailProtection.RateCritThreshold <= 0 {
		return nil
	}
	if isHighVolumeSender(user, cfg.EmailProtection.HighVolumeSenders) {
		return nil
	}

	// Load or create rate window for this user
	val, _ := emailRateWindows.LoadOrStore(user, &rateWindow{})
	rw := val.(*rateWindow)

	now := time.Now()
	windowDur := time.Duration(cfg.EmailProtection.RateWindowMin) * time.Minute

	rw.mu.Lock()
	defer rw.mu.Unlock()

	// Check domain suppression BEFORE adding to window - prevents
	// phantom rate inflation for suppressed domains.
	domain := extractDomainFromEmail(user)
	if domain != "" && hasRecentCompromisedFinding(domain) {
		return nil
	}

	rw.add(now)
	count := rw.countInWindow(now, windowDur)

	// Reset alerted state when count drops below warn threshold -
	// allows re-alerting on the next burst after the window slides.
	if count < cfg.EmailProtection.RateWarnThreshold {
		rw.alerted = ""
	}

	var findings []alert.Finding

	if count >= cfg.EmailProtection.RateCritThreshold {
		if rw.alerted != "crit" {
			rw.alerted = "crit"
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "email_rate_critical",
				Message:  fmt.Sprintf("Email rate CRITICAL: %s sent %d messages in %d minutes (threshold: %d)", user, count, cfg.EmailProtection.RateWindowMin, cfg.EmailProtection.RateCritThreshold),
				Details:  fmt.Sprintf("User: %s\nMessages in window: %d\nWindow: %d minutes\nThreshold: %d", user, count, cfg.EmailProtection.RateWindowMin, cfg.EmailProtection.RateCritThreshold),
			})
		}
	} else if count >= cfg.EmailProtection.RateWarnThreshold {
		if rw.alerted != "warn" && rw.alerted != "crit" {
			rw.alerted = "warn"
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "email_rate_warning",
				Message:  fmt.Sprintf("Email rate WARNING: %s sent %d messages in %d minutes (threshold: %d)", user, count, cfg.EmailProtection.RateWindowMin, cfg.EmailProtection.RateWarnThreshold),
				Details:  fmt.Sprintf("User: %s\nMessages in window: %d\nWindow: %d minutes\nThreshold: %d", user, count, cfg.EmailProtection.RateWindowMin, cfg.EmailProtection.RateWarnThreshold),
			})
		}
	}

	return findings
}

// StartEmailRateEviction starts a background goroutine that prunes expired
// rate windows every 10 minutes. Same pattern as StartModSecEviction.
func StartEmailRateEviction(stopCh <-chan struct{}) {
	obs.Go("email-rate-eviction", func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case now := <-ticker.C:
				evictEmailRateWindows(now)
			}
		}
	})
}

// evictEmailRateWindows prunes all per-user rate windows and deletes empty entries.
func evictEmailRateWindows(now time.Time) {
	// Use a generous 60-minute eviction window to avoid premature deletion.
	// The actual rate window is checked during rate evaluation.
	evictWindow := 60 * time.Minute
	emailRateWindows.Range(func(key, val any) bool {
		rw := val.(*rateWindow)
		rw.mu.Lock()
		rw.prune(now, evictWindow)
		empty := len(rw.times) == 0
		if empty {
			rw.alerted = ""
		}
		rw.mu.Unlock()
		if empty {
			emailRateWindows.Delete(key)
		}
		return true
	})

	// Also prune the suppressed domains map
	emailRateSuppressed.mu.Lock()
	for domain, ts := range emailRateSuppressed.domains {
		if time.Since(ts) > time.Hour {
			delete(emailRateSuppressed.domains, domain)
		}
	}
	emailRateSuppressed.mu.Unlock()
}
