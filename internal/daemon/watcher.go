package daemon

import (
	"bufio"
	"context"
	"errors"
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

const (
	recentOutgoingMailHoldWindow = 2 * time.Hour
	logWatcherMaxLineBytes       = 256 * 1024
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

	reader := bufio.NewReaderSize(w.file, 64*1024)
	for {
		rawLine, truncated, readErr := readBoundedWatcherLine(reader, logWatcherMaxLineBytes)
		if truncated {
			fmt.Fprintf(os.Stderr, "[%s] Warning: skipped oversized log line from %s at %d bytes\n", ts(), w.path, logWatcherMaxLineBytes)
		}
		if len(rawLine) > 0 && !truncated {
			line := trimWatcherLineEnding(rawLine)
			if line == "" {
				if readErr != nil {
					break
				}
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
		if readErr != nil {
			break
		}
	}

	// Update offset
	newOffset, err := w.file.Seek(0, io.SeekCurrent)
	if err == nil {
		w.offset = newOffset
	}
}

func readBoundedWatcherLine(r *bufio.Reader, maxBytes int) (string, bool, error) {
	var b strings.Builder
	truncated := false
	for {
		chunk, err := r.ReadSlice('\n')
		if len(chunk) > 0 {
			switch {
			case truncated:
			case b.Len()+len(chunk) <= maxBytes:
				b.Write(chunk)
			default:
				if room := maxBytes - b.Len(); room > 0 {
					b.Write(chunk[:room])
				}
				truncated = true
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return b.String(), truncated, err
	}
}

func trimWatcherLineEnding(line string) string {
	line = strings.TrimSuffix(line, "\n")
	return strings.TrimSuffix(line, "\r")
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
					SourceIP: ip,
					TenantID: account,
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
				TenantID: account,
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

			tenant := user
			if tenant == "unknown" {
				tenant = ""
			}
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "ssh_login_realtime",
				Message:  fmt.Sprintf("SSH login from non-infra IP: %s (user: %s)", ip, user),
				Details:  truncateDaemon(line, 200),
				SourceIP: ip,
				TenantID: tenant,
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

	// 2. Outgoing mail hold - account is held by cPanel.
	// Format: "Sender office@example.com has an outgoing mail hold"
	// or: "Domain example.org has an outgoing mail hold"
	//
	// Exim emits this rejection from the enforce_mail_permissions router on
	// EVERY queued-message retry while the hold is active, so re-applying the
	// hold here creates a feedback loop: an operator who clears a
	// false-positive hold (e.g. caused by external transit defers like the
	// 2026-05-11 Microsoft edge outage) sees CSM re-set the hold within
	// seconds because old queued messages keep retrying. cPanel's
	// TailWatch::Eximstats is the authoritative source for setting
	// the hold. CSM records the hold so later retry-limit noise from
	// the held domain is not promoted to a fresh spam outbreak.
	if strings.Contains(line, "outgoing mail hold") {
		sender := extractMailHoldSender(line)
		if sender == "" {
			sender = extractEximSender(line)
		}
		domain := extractDomainFromEmail(sender)
		if domain == "" {
			domain = sender // may already be a bare domain
		}

		if domain != "" {
			recordRecentOutgoingMailHold(domain)
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
					Message:  fmt.Sprintf("Account %s is on cPanel outgoing mail hold", sender),
					Details:  truncateDaemon(line, 300),
					Mailbox:  mailboxOnly(sender),
					Domain:   domain,
				})
			}
		}
	}

	// 3. Max defers/failures exceeded - active spam outbreak
	if strings.Contains(line, "max defers and failures per hour") {
		domain := extractEximDomain(line)
		if recentOutgoingMailHold(domain) {
			return findings
		}
		// Record the hold-seen marker only after CSM confirms the hold was
		// applied or already active. If lookup or whmapi1 fails, later
		// max-defers lines must still retry and alert.
		held := maybeHoldOutgoingMail(cfg, domain)
		if held {
			recordRecentOutgoingMailHold(domain)
		}
		message := fmt.Sprintf("Spam outbreak: %s exceeded max defers/failures", domain)
		if held {
			message += " - outgoing mail auto-suspended"
		}
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "email_spam_outbreak",
			Message:  message,
			Details:  truncateDaemon(line, 300),
			Domain:   domain,
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
				Mailbox:  mailboxOnly(sender),
				Domain:   extractDomainFromEmail(sender),
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
				Mailbox:  mailboxOnly(sender),
				Domain:   extractDomainFromEmail(sender),
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
					Mailbox:  mailboxOnly(sender),
					Domain:   extractDomainFromEmail(sender),
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
		// cPanel-local mailboxes log set_id as a bare local part with no
		// "@domain"; treating it as a Mailbox would leave the structured
		// field empty (mailboxOnly drops bare names) and force the
		// correlator to fall back to SourceIP, splitting one targeted
		// account across many attacker IPs. Route the bare form to
		// TenantID so the incident groups by account.
		mailbox, domain, tenant := splitMailAccount(account)
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "email_auth_failure_realtime",
			Message:  msg,
			Details:  truncateDaemon(line, 300),
			SourceIP: ip,
			Mailbox:  mailbox,
			Domain:   domain,
			TenantID: tenant,
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
					Domain:    dkimDomain,
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
					Domain:    spfDomain,
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

	// 10. Cloud-relay credential abuse (multiple authenticated sends from
	// distinct cloud-provider IPs for the same mailbox).
	// Use the AUTH identity (A=dovecot_*:<user>), not the envelope-from:
	// the envelope-from can be forged by the attacker, while the AUTH
	// identity is the credential actually being abused and the one we
	// must lock out.
	for _, f := range parseCloudRelayFinding(line, cfg) {
		handleCloudRelayCredentialAbuse(cfg, extractAuthUser(line))
		findings = append(findings, f)
	}

	if eng := PHPRelayEvaluator(); eng != nil {
		findings = append(findings, eng.parsePHPRelayAccountVolume(line, time.Now())...)
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
	// Bound the map size hint so a malformed config cannot push the sum
	// near max int; the lists are operator-supplied infra/firewall CIDRs
	// and tens of entries is the realistic ceiling.
	const infraIPHintCap = 1 << 16
	hint := len(topLevel) + len(fwSpecific)
	if hint < 0 || hint > infraIPHintCap {
		hint = infraIPHintCap
	}
	seen := make(map[string]bool, hint)
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

// outgoingMailHoldUsersPath is the cPanel file listing users currently
// under OUTGOING_MAIL_HOLD. Read-only; cPanel/WHM owns mutation. var
// (not const) so tests can point it at a fixture.
var outgoingMailHoldUsersPath = "/etc/outgoing_mail_hold_users"

// whmapi1HoldExec invokes `whmapi1 hold_outgoing_email user=<user>`.
// Declared as var so tests can replace it without spawning whmapi1.
var whmapi1HoldExec = func(user string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- whmapi1 is the cPanel API binary; user is a cPanel
	// account name resolved from /etc/userdomains (cpanel-managed).
	return exec.CommandContext(ctx, "whmapi1", "hold_outgoing_email", "user="+user).CombinedOutput()
}

// userOnOutgoingMailHold reports whether the cPanel user already appears
// in /etc/outgoing_mail_hold_users. Used to short-circuit redundant
// whmapi1 calls when exim re-emits "exceeded max defers/failures" every
// retry hour while the hold is already active.
func userOnOutgoingMailHold(user string) bool {
	if user == "" {
		return false
	}
	f, err := os.Open(outgoingMailHoldUsersPath)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == user {
			return true
		}
	}
	return false
}

// maybeHoldOutgoingMail applies an outgoing-mail hold only when auto-response
// is enabled and not in dry-run. Holding a customer's outbound mail is a
// customer-impacting action, so it honours the same master switch and dry-run
// safety default as IP blocking and quarantine; an operator evaluating CSM in
// monitor mode must never have mail held out from under them. It returns true
// only when a hold was actually applied (or already active), so callers can
// keep their hold-dedup bookkeeping accurate.
func maybeHoldOutgoingMail(cfg *config.Config, domainOrEmail string) bool {
	if cfg == nil || !cfg.AutoResponse.Enabled || cfg.AutoResponseDryRunEnabled() {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: would hold outgoing mail for %s (auto_response disabled or dry-run)\n",
			time.Now().Format("2006-01-02 15:04:05"), domainOrEmail)
		return false
	}
	return autoSuspendOutgoingMail(domainOrEmail)
}

// autoSuspendOutgoingMail calls whmapi1 to hold outgoing mail for the cPanel
// account that owns the given domain or email address. It returns true when
// the hold is applied or already active. Declared as var so tests can swap in
// a recorder without spawning whmapi1.
var autoSuspendOutgoingMail = autoSuspendOutgoingMailReal

func autoSuspendOutgoingMailReal(domainOrEmail string) bool {
	if domainOrEmail == "" {
		return false
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
		return false
	}
	// Skip if cPanel already lists this user as held. Re-issuing the
	// hold has no operational effect, but on a sustained exim retry
	// loop (queued bounces keep the defer/fail ratio above threshold
	// hour after hour) the redundant whmapi1 calls produce a stream
	// of "AUTO-SUSPEND" log lines that look like a fresh incident.
	if userOnOutgoingMailHold(user) {
		return true
	}
	out, err := whmapi1HoldExec(user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: whmapi1 hold_outgoing_email failed for %s: %v\n%s\n",
			time.Now().Format("2006-01-02 15:04:05"), user, err, string(out))
		return false
	}
	fmt.Fprintf(os.Stderr, "[%s] AUTO-SUSPEND: outgoing mail held for cPanel user %s (domain: %s)\n",
		time.Now().Format("2006-01-02 15:04:05"), user, domain)
	return true
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

func recordRecentOutgoingMailHold(domain string) {
	if domain == "" {
		return
	}
	db := store.Global()
	if db == nil {
		return
	}
	_ = db.SetMetaString("email_hold_seen:"+domain, time.Now().Format(time.RFC3339))
}

func recentOutgoingMailHold(domain string) bool {
	if domain == "" {
		return false
	}
	db := store.Global()
	if db == nil {
		return false
	}
	stored := db.GetMetaString("email_hold_seen:" + domain)
	return stored != "" && !isDedupExpired(stored, recentOutgoingMailHoldWindow)
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

// mailboxOnly returns the input only when it looks like a full mailbox
// (contains '@'); otherwise returns "". Used by realtime emit sites that
// receive either "user@domain" or a bare domain — the bare domain belongs
// in the Domain field, not Mailbox, so the correlator does not collapse
// distinct mailboxes onto a domain key.
func mailboxOnly(s string) string {
	if strings.IndexByte(s, '@') < 0 {
		return ""
	}
	return s
}

// splitMailAccount classifies an authenticated mail account string into
// the three correlation fields. A full mailbox ("user@domain") routes to
// Mailbox + Domain. A bare local part (cPanel-style, no '@') routes to
// TenantID so the incident correlator groups by account, not by attacker
// SourceIP. An empty input returns three empty strings.
func splitMailAccount(account string) (mailbox, domain, tenant string) {
	if account == "" {
		return "", "", ""
	}
	if strings.IndexByte(account, '@') < 0 {
		return "", "", account
	}
	return account, extractDomainFromEmail(account), ""
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

	mailbox, domain, tenant := splitMailAccount(user)
	if count >= cfg.EmailProtection.RateCritThreshold {
		if rw.alerted != "crit" {
			rw.alerted = "crit"
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "email_rate_critical",
				Message:  fmt.Sprintf("Email rate CRITICAL: %s sent %d messages in %d minutes (threshold: %d)", user, count, cfg.EmailProtection.RateWindowMin, cfg.EmailProtection.RateCritThreshold),
				Details:  fmt.Sprintf("User: %s\nMessages in window: %d\nWindow: %d minutes\nThreshold: %d", user, count, cfg.EmailProtection.RateWindowMin, cfg.EmailProtection.RateCritThreshold),
				Mailbox:  mailbox,
				Domain:   domain,
				TenantID: tenant,
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
				Mailbox:  mailbox,
				Domain:   domain,
				TenantID: tenant,
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
