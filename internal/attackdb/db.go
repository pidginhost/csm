package attackdb

import (
	"bufio"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
	"github.com/pidginhost/csm/internal/store"
)

// AttackType categorises observed attacks for grouping and scoring.
type AttackType string

const (
	AttackBruteForce  AttackType = "brute_force"
	AttackWAFBlock    AttackType = "waf_block"
	AttackWebshell    AttackType = "webshell"
	AttackPhishing    AttackType = "phishing"
	AttackC2          AttackType = "c2"
	AttackRecon       AttackType = "recon"
	AttackSPAM        AttackType = "spam"
	AttackCPanelLogin AttackType = "cpanel_login"
	AttackFileUpload  AttackType = "file_upload"

	// AttackAuthSuccess marks an event that followed a SUCCESSFUL
	// authentication. Recorded for correlation; carries no score.
	AttackAuthSuccess AttackType = "auth_success"
	AttackReputation  AttackType = "reputation"
	AttackOther       AttackType = "other"
)

// attackTypeLabels is how the Web UI names each attack type.
var attackTypeLabels = map[AttackType]string{
	AttackBruteForce:  "Brute Force",
	AttackWAFBlock:    "WAF Block",
	AttackWebshell:    "Web Shell",
	AttackPhishing:    "Phishing",
	AttackC2:          "C2 Communication",
	AttackRecon:       "Reconnaissance",
	AttackSPAM:        "Spam",
	AttackCPanelLogin: "cPanel Login",
	AttackFileUpload:  "File Upload",
	AttackAuthSuccess: "Authenticated Activity",
	AttackReputation:  "Known Malicious IP",
	AttackOther:       "Other",
}

// AttackTypeLabels returns the display label of every attack type, keyed
// by the type's string value.
func AttackTypeLabels() map[string]string {
	out := make(map[string]string, len(attackTypeLabels))
	for typ, label := range attackTypeLabels {
		out[string(typ)] = label
	}
	return out
}

// checkToAttack maps alert.Finding.Check values to attack types.
var checkToAttack = map[string]AttackType{
	// Brute force
	"wp_login_bruteforce":         AttackBruteForce,
	"xmlrpc_abuse":                AttackBruteForce,
	"ftp_bruteforce":              AttackBruteForce,
	"ssh_login_unknown_ip":        AttackBruteForce,
	"webmail_bruteforce":          AttackBruteForce,
	"api_auth_failure":            AttackBruteForce,
	"api_auth_failure_realtime":   AttackBruteForce,
	"ftp_auth_failure_realtime":   AttackBruteForce,
	"email_auth_failure_realtime": AttackBruteForce,
	"credential_stuffing":         AttackBruteForce,
	"pam_bruteforce":              AttackBruteForce,
	"smtp_bruteforce":             AttackBruteForce,
	"smtp_probe_abuse":            AttackBruteForce,
	"smtp_subnet_spray":           AttackBruteForce,
	"mail_bruteforce":             AttackBruteForce,
	"mail_subnet_spray":           AttackBruteForce,
	"mail_account_compromised":    AttackBruteForce,
	"admin_panel_bruteforce":      AttackBruteForce,

	// Webshells and malware
	"webshell":                 AttackWebshell,
	"new_webshell_file":        AttackWebshell,
	"obfuscated_php":           AttackWebshell,
	"suspicious_php_content":   AttackWebshell,
	"new_php_in_languages":     AttackWebshell,
	"new_php_in_upgrade":       AttackWebshell,
	"backdoor_binary":          AttackWebshell,
	"new_executable_in_config": AttackWebshell,

	// Phishing
	"phishing_page":           AttackPhishing,
	"phishing_php":            AttackPhishing,
	"phishing_iframe":         AttackPhishing,
	"phishing_redirector":     AttackPhishing,
	"phishing_credential_log": AttackPhishing,
	"phishing_kit_archive":    AttackPhishing,
	"phishing_directory":      AttackPhishing,

	// C2 and suspicious processes
	"fake_kernel_thread":       AttackC2,
	"suspicious_process":       AttackC2,
	"php_suspicious_execution": AttackC2,
	"user_outbound_connection": AttackC2,
	"exfiltration_paste_site":  AttackC2,

	// Recon
	"wp_user_enumeration": AttackRecon,
	// HTTP-layer abuse from a single source IP: URL enumeration, request
	// floods, and scanner UA spoofing. Recorded so repeat offenders build
	// local reputation; recon-classed (volume-scored, no brute-force bonus).
	// "http_distributed_flood" is intentionally excluded: it is an aggregate
	// per-vhost finding with no single source IP, so RecordFinding has nothing
	// to attribute it to.
	"http_scanner_profile":        AttackRecon,
	"http_request_flood":          AttackRecon,
	"http_claimed_bot_unverified": AttackRecon,
	"http_ua_spoof":               AttackRecon,

	// SPAM
	"mail_per_account":     AttackSPAM,
	"exim_frozen_realtime": AttackSPAM,

	// WAF: no emitted check maps here today. The two names this table once
	// listed were never emitted by any release, so WAF blocks have never
	// built local reputation through this database; mapping the real
	// ModSecurity block names is a scoring decision recorded in the roadmap.

	// cPanel/webmail login
	// Successful, post-authentication events. They are RECORDED, because they
	// are evidence when correlated with other findings on the same account,
	// but they carry no attack weight: scoring them made an account owner an
	// attacker for using cPanel, FTP or File Manager normally. One successful
	// File Manager upload alone added 20 points that never decayed, and the
	// resulting score fed the reputation path that kept re-blocking the owner.
	//
	// cpanel_multi_ip_login stays a real attack type: several addresses inside
	// a window is correlation evidence rather than one successful login.
	"cpanel_login":                AttackAuthSuccess,
	"cpanel_login_realtime":       AttackAuthSuccess,
	"webmail_login_realtime":      AttackAuthSuccess,
	"ftp_login":                   AttackAuthSuccess,
	"pam_login":                   AttackAuthSuccess,
	"cpanel_file_upload_realtime": AttackAuthSuccess,
	"cpanel_multi_ip_login":       AttackCPanelLogin,

	// Reputation - known malicious IPs from threat database
	"ip_reputation": AttackReputation,
	// NOTE: "local_threat_score" is intentionally excluded - it is a derived
	// finding, not a raw attack. Recording it would create a feedback loop
	// that inflates EventCount by +1 every 10-minute cycle.
}

// MappedChecks lists every check name the attack database records, sorted.
// The slice is the caller's own copy.
func MappedChecks() []string {
	out := make([]string, 0, len(checkToAttack))
	for name := range checkToAttack {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// AttackTypeFor reports the attack type a check name records under, and
// whether the name is mapped at all.
func AttackTypeFor(check string) (AttackType, bool) {
	kind, ok := checkToAttack[config.CanonicalCheckName(check)]
	return kind, ok
}

// Event is a single observed attack incident.
type Event struct {
	Timestamp  time.Time  `json:"ts"`
	IP         string     `json:"ip"`
	AttackType AttackType `json:"type"`
	CheckName  string     `json:"check"`
	Severity   int        `json:"sev"`
	Account    string     `json:"account,omitempty"`
	Message    string     `json:"msg,omitempty"`
}

// IPRecord is the per-IP aggregated intelligence record.
type IPRecord struct {
	IP                    string             `json:"ip"`
	FirstSeen             time.Time          `json:"first_seen"`
	LastSeen              time.Time          `json:"last_seen"`
	EventCount            int                `json:"event_count"`
	AttackCounts          map[AttackType]int `json:"attack_counts"`
	Accounts              map[string]int     `json:"accounts"`
	AuthSuccessAccounts   map[string]int     `json:"auth_success_accounts,omitempty"`
	ThreatScore           int                `json:"threat_score"`
	AutoBlocked           bool               `json:"auto_blocked"`
	BruteForceWindowStart time.Time          `json:"brute_force_window_start,omitzero"`
	BruteForceWindowCount int                `json:"brute_force_window_count,omitempty"`
	BruteForceSustainedAt time.Time          `json:"brute_force_sustained_at,omitzero"`
}

// DB is the in-memory attack database backed by JSON files.
type DB struct {
	flushMu          sync.Mutex
	mu               sync.RWMutex
	records          map[string]*IPRecord
	deletedIPs       map[string]struct{}
	dirtyIPs         map[string]struct{}
	pendingEvents    []Event
	eventHealthOnce  sync.Once
	eventQueue       *eventQueue
	openEvents       func(string) (io.WriteCloser, error)
	recordHealthOnce sync.Once
	recordQueue      *recordQueue
	saveRecord       func(*store.DB, store.IPRecord) error
	deleteRecord     func(*store.DB, string) error
	writeRecords     func(string, []byte) error
	dbPath           string
	dirty            bool
	stopCh           chan struct{}
	wg               sync.WaitGroup
}

// markDirtyLocked records that ip's record changed and must be persisted on the
// next flush. The caller must hold db.mu. dirty stays as the flush gate so
// Flush keeps its existing "anything to write?" check.
func (db *DB) markDirtyLocked(ip string) {
	if db.dirtyIPs == nil {
		db.dirtyIPs = make(map[string]struct{})
	}
	db.dirtyIPs[ip] = struct{}{}
	db.dirty = true
	db.queueRecordLocked(ip)
}

func (db *DB) markDeletedLocked(ip string) {
	if db.deletedIPs == nil {
		db.deletedIPs = make(map[string]struct{})
	}
	db.deletedIPs[ip] = struct{}{}
	delete(db.dirtyIPs, ip)
	db.dirty = true
	db.queueRecordLocked(ip)
}

var (
	globalDB   *DB
	globalMu   sync.Mutex
	dbInitOnce sync.Once
)

// Init initializes the global attack database.
func Init(statePath string) *DB {
	dbInitOnce.Do(func() {
		dbPath := statePath + "/attack_db"
		_ = os.MkdirAll(dbPath, 0700)

		db := &DB{
			records:    make(map[string]*IPRecord),
			deletedIPs: make(map[string]struct{}),
			dbPath:     dbPath,
			stopCh:     make(chan struct{}),
		}
		db.load()
		db.pruneExpired()

		// Background saver - flush dirty records every 30 seconds
		db.wg.Add(1)
		go db.backgroundSaver()

		globalDB = db
	})
	return globalDB
}

// SeedFromPermanentBlocklist imports IPs from the threat DB permanent blocklist
// into the attack database. These are IPs that already attacked and were auto-blocked.
// Only imports IPs not already in the attack DB.
func (db *DB) SeedFromPermanentBlocklist(statePath string) int {
	path := statePath + "/threat_db/permanent.txt"
	// #nosec G304 -- fixed filename under operator-configured statePath.
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()

	imported := 0
	now := time.Now()
	scanner := bufio.NewScanner(f)
	db.mu.Lock()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue
		}
		if _, exists := db.records[ip]; exists {
			continue // already tracked
		}

		// Extract reason from comment: "1.2.3.4 # reason [date]"
		reason := "auto-blocked (historical)"
		if idx := strings.Index(line, "# "); idx > 0 {
			reason = strings.TrimSpace(line[idx+2:])
		}

		db.records[ip] = &IPRecord{
			IP:           ip,
			FirstSeen:    now,
			LastSeen:     now,
			EventCount:   1,
			AttackCounts: map[AttackType]int{AttackOther: 1},
			Accounts:     make(map[string]int),
			AutoBlocked:  true,
		}
		db.records[ip].ThreatScore = ComputeScore(db.records[ip])

		db.queueEventLocked(Event{
			Timestamp:  now,
			IP:         ip,
			AttackType: AttackOther,
			CheckName:  "permanent_blocklist_import",
			Severity:   2,
			Message:    truncate(reason, 200),
		})
		delete(db.deletedIPs, ip)
		db.markDirtyLocked(ip)
		imported++
	}
	db.mu.Unlock()
	return imported
}

// Global returns the global attack database instance.
func Global() *DB {
	globalMu.Lock()
	defer globalMu.Unlock()
	return globalDB
}

// SetGlobal overrides the global attack database. Mirrors
// store.SetGlobal: production wires globalDB exactly once via Init;
// tests use this to install a pre-seeded DB without touching the
// sync.Once-guarded Init path.
func SetGlobal(db *DB) {
	globalMu.Lock()
	globalDB = db
	globalMu.Unlock()
}

// NewForTest builds a bare in-memory DB pre-populated with the given
// records. No backgroundSaver is started (no goroutines to clean up),
// no disk path is configured. Reserved for unit tests; production
// wiring stays on Init. Records are deep-copied so a later mutation
// to the caller's map (including its nested AttackCounts / Accounts
// maps) cannot bleed into the DB.
func NewForTest(records map[string]*IPRecord) *DB {
	db := &DB{
		records:    make(map[string]*IPRecord, len(records)),
		deletedIPs: make(map[string]struct{}),
		stopCh:     make(chan struct{}),
	}
	for k, v := range records {
		db.records[k] = cloneIPRecord(v)
	}
	return db
}

// RecordFinding records an attack event from a finding.
// Fire-and-forget: never blocks, never panics.
func (db *DB) RecordFinding(f alert.Finding) {
	attackType, ok := AttackTypeFor(f.Check)
	if !ok {
		return // not an attack-related check
	}

	ip := extractFindingIP(f)
	if ip == "" {
		return
	}

	account := extractFindingAccount(f)
	// Attribute the original finding, then redact before truncation can remove
	// the service tag or other context needed to recognize a credential.
	f = alert.SanitizeFinding(f)

	event := Event{
		Timestamp:  f.Timestamp,
		IP:         ip,
		AttackType: attackType,
		CheckName:  f.Check,
		Severity:   int(f.Severity),
		Account:    account,
		Message:    truncate(f.Message, 200),
	}

	now := f.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	db.mu.Lock()
	rec, exists := db.records[ip]
	if !exists {
		rec = &IPRecord{
			IP:           ip,
			FirstSeen:    now,
			AttackCounts: make(map[AttackType]int),
			Accounts:     make(map[string]int),
		}
		db.records[ip] = rec
	}
	rec.LastSeen = now
	rec.EventCount++
	rec.AttackCounts[attackType]++
	if tracksSustainedBruteScore(f.Check) {
		updateBruteForceWindow(rec, now)
	}
	if account != "" {
		rec.Accounts[account]++
		if attackType == AttackAuthSuccess {
			if rec.AuthSuccessAccounts == nil {
				rec.AuthSuccessAccounts = make(map[string]int)
			}
			rec.AuthSuccessAccounts[account]++
		}
	}
	rec.ThreatScore = computeScoreAt(rec, now)
	db.queueEventLocked(event)
	delete(db.deletedIPs, ip)
	db.markDirtyLocked(ip)
	db.mu.Unlock()
}

// MarkBlocked sets the auto-blocked flag on an IP record.
func (db *DB) MarkBlocked(ip string) {
	db.mu.Lock()
	if rec, ok := db.records[ip]; ok {
		rec.AutoBlocked = true
		rec.ThreatScore = ComputeScore(rec)
		delete(db.deletedIPs, ip)
		db.markDirtyLocked(ip)
	}
	db.mu.Unlock()
}

// LookupIP returns the record for an IP, or nil if not tracked.
func (db *DB) LookupIP(ip string) *IPRecord {
	db.mu.RLock()
	defer db.mu.RUnlock()
	rec, ok := db.records[ip]
	if !ok {
		return nil
	}
	return cloneIPRecord(rec)
}

// TopAttackers returns the top N IPs by threat score.
func (db *DB) TopAttackers(n int) []*IPRecord {
	db.mu.RLock()
	defer db.mu.RUnlock()

	all := make([]*IPRecord, 0, len(db.records))
	for _, rec := range db.records {
		all = append(all, cloneIPRecord(rec))
	}

	// Sort by threat score descending, then event count
	sortRecords(all)

	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// Flush saves all pending data to disk. Called on daemon shutdown.
func (db *DB) Flush() error {
	// Keep snapshots and disk writes in the same order. A command can flush
	// alongside the background saver; an older write must not undo its delete.
	db.flushMu.Lock()
	defer db.flushMu.Unlock()

	db.mu.Lock()
	events := db.pendingEvents
	eventBatch := db.eventHealth().detach()
	db.pendingEvents = nil
	dirty := db.dirty
	db.dirty = false
	db.mu.Unlock()

	if len(events) > 0 {
		db.appendEvents(events, eventBatch)
	}
	if dirty {
		db.saveRecords()
	}
	return nil
}

// Stop stops the background saver and flushes.
func (db *DB) Stop() {
	close(db.stopCh)
	db.wg.Wait()
	_ = db.Flush()
}

func (db *DB) backgroundSaver() {
	defer db.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-db.stopCh:
			return
		case <-ticker.C:
			_ = db.Flush()
		}
	}
}

// extractIP pulls an IP address from a finding message.
func extractIP(message string) string {
	for _, sep := range []string{" from ", ": ", "accessing server: "} {
		if idx := strings.Index(message, sep); idx >= 0 {
			rest := message[idx+len(sep):]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				token := fields[0]
				// Strip AbuseIPDB score suffix like "(AbuseIPDB"
				if paren := strings.Index(token, "("); paren > 0 {
					token = token[:paren]
				}
				if ip, ok := netutil.ParseIPToken(token); ok {
					return ip
				}
			}
		}
	}
	return ""
}

func extractFindingIP(f alert.Finding) string {
	if ip := normalizeRecordIP(f.SourceIP); ip != "" {
		return ip
	}
	return extractIP(f.Message)
}

func normalizeRecordIP(raw string) string {
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

func extractFindingAccount(f alert.Finding) string {
	mailbox := strings.TrimSpace(f.Mailbox)
	domain := strings.TrimSpace(f.Domain)
	if mailbox != "" {
		if strings.Contains(mailbox, "@") || domain == "" {
			return mailbox
		}
		return mailbox + "@" + strings.ToLower(domain)
	}
	if tenant := strings.TrimSpace(f.TenantID); tenant != "" {
		return tenant
	}
	return extractAccount(f.Message, f.Details)
}

// extractAccount tries to pull a cPanel account name from message or details.
func extractAccount(message, details string) string {
	// Check details first: "Account: username"
	for _, text := range []string{details, message} {
		if idx := strings.Index(text, "Account: "); idx >= 0 {
			rest := text[idx+9:]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	// Try /home/username/ pattern
	if idx := strings.Index(message, "/home/"); idx >= 0 {
		rest := message[idx+6:]
		if slash := strings.Index(rest, "/"); slash > 0 {
			return rest[:slash]
		}
	}
	return ""
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func updateBruteForceWindow(rec *IPRecord, ts time.Time) {
	if rec.BruteForceWindowStart.IsZero() ||
		ts.Before(rec.BruteForceWindowStart) ||
		ts.Sub(rec.BruteForceWindowStart) > sustainedBruteForceWindow {
		rec.BruteForceWindowStart = ts
		rec.BruteForceWindowCount = 1
		return
	}
	rec.BruteForceWindowCount++
	if rec.BruteForceWindowCount >= sustainedBruteForceThreshold &&
		(rec.BruteForceSustainedAt.IsZero() || !ts.Before(rec.BruteForceSustainedAt)) {
		rec.BruteForceSustainedAt = ts
	}
}

func tracksSustainedBruteScore(check string) bool {
	return check == "email_auth_failure_realtime"
}

// RemoveIP removes an IP from the attack database entirely.
func (db *DB) RemoveIP(ip string) {
	db.mu.Lock()
	delete(db.records, ip)
	db.markDeletedLocked(ip)
	db.mu.Unlock()
}

// ForgetIP atomically removes all scoring records for a parsed IP, including
// legacy imports stored under equivalent spellings. Event history is retained.
// The returned records are detached, so later findings cannot change them.
func (db *DB) ForgetIP(ip net.IP) []*IPRecord {
	db.mu.Lock()
	defer db.mu.Unlock()
	var removed []*IPRecord
	for key, rec := range db.records {
		if ip.Equal(net.ParseIP(key)) {
			removed = append(removed, rec)
			delete(db.records, key)
			db.markDeletedLocked(key)
		}
	}
	return removed
}

// PruneExpired removes records older than 90 days.
func (db *DB) PruneExpired() {
	db.pruneExpired()
}

func (db *DB) pruneExpired() {
	cutoff := time.Now().Add(-90 * 24 * time.Hour)
	db.mu.Lock()
	for ip, rec := range db.records {
		if rec.LastSeen.Before(cutoff) {
			delete(db.records, ip)
			db.markDeletedLocked(ip)
		}
	}
	db.mu.Unlock()
}

// TotalIPs returns the number of tracked IPs.
func (db *DB) TotalIPs() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.records)
}

// AllRecords returns a deep-copy snapshot of all records.
func (db *DB) AllRecords() []*IPRecord {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result := make([]*IPRecord, 0, len(db.records))
	for _, rec := range db.records {
		result = append(result, cloneIPRecord(rec))
	}
	return result
}

// FormatTopLine returns a summary string for stderr logging.
func (db *DB) FormatTopLine() string {
	db.mu.RLock()
	defer db.mu.RUnlock()
	total := len(db.records)
	blocked := 0
	for _, r := range db.records {
		if r.AutoBlocked {
			blocked++
		}
	}
	return fmt.Sprintf("%d IPs tracked, %d auto-blocked", total, blocked)
}

// Snapshots must detach all count maps from concurrent recording.
func cloneIPRecord(rec *IPRecord) *IPRecord {
	cp := *rec
	cp.AttackCounts = maps.Clone(rec.AttackCounts)
	cp.Accounts = maps.Clone(rec.Accounts)
	if cp.AttackCounts == nil {
		cp.AttackCounts = make(map[AttackType]int)
	}
	if cp.Accounts == nil {
		cp.Accounts = make(map[string]int)
	}
	cp.AuthSuccessAccounts = maps.Clone(rec.AuthSuccessAccounts)
	return &cp
}
