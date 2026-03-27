package attackdb

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
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
	AttackOther       AttackType = "other"
)

// checkToAttack maps alert.Finding.Check values to attack types.
var checkToAttack = map[string]AttackType{
	// Brute force
	"wp_login_bruteforce":       AttackBruteForce,
	"xmlrpc_abuse":              AttackBruteForce,
	"ftp_bruteforce":            AttackBruteForce,
	"ssh_login_unknown_ip":      AttackBruteForce,
	"ssh_login_realtime":        AttackBruteForce,
	"webmail_bruteforce":        AttackBruteForce,
	"api_auth_failure":          AttackBruteForce,
	"api_auth_failure_realtime": AttackBruteForce,
	"ftp_auth_failure_realtime": AttackBruteForce,
	"pam_bruteforce":            AttackBruteForce,

	// Webshells and malware
	"webshell":                 AttackWebshell,
	"new_webshell_file":        AttackWebshell,
	"obfuscated_php":           AttackWebshell,
	"php_dropper":              AttackWebshell,
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

	// SPAM
	"mail_per_account":     AttackSPAM,
	"exim_frozen_realtime": AttackSPAM,

	// WAF
	"modsec_block": AttackWAFBlock,
	"waf_block":    AttackWAFBlock,

	// cPanel/webmail login
	"cpanel_login":           AttackCPanelLogin,
	"cpanel_login_realtime":  AttackCPanelLogin,
	"cpanel_multi_ip_login":  AttackCPanelLogin,
	"webmail_login_realtime": AttackCPanelLogin,
	"ftp_login":              AttackCPanelLogin,
	"ftp_login_realtime":     AttackCPanelLogin,
	"pam_login":              AttackCPanelLogin,

	// File upload
	"cpanel_file_upload_realtime": AttackFileUpload,

	// Reputation (not an attack by itself, but the IP is known bad)
	"ip_reputation": AttackOther,
	// NOTE: "local_threat_score" is intentionally excluded — it is a derived
	// finding, not a raw attack. Recording it would create a feedback loop
	// that inflates EventCount by +1 every 10-minute cycle.
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
	IP           string             `json:"ip"`
	FirstSeen    time.Time          `json:"first_seen"`
	LastSeen     time.Time          `json:"last_seen"`
	EventCount   int                `json:"event_count"`
	AttackCounts map[AttackType]int `json:"attack_counts"`
	Accounts     map[string]int     `json:"accounts"`
	ThreatScore  int                `json:"threat_score"`
	AutoBlocked  bool               `json:"auto_blocked"`
}

// DB is the in-memory attack database backed by JSON files.
type DB struct {
	mu            sync.RWMutex
	records       map[string]*IPRecord
	pendingEvents []Event
	dbPath        string
	dirty         bool
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

var (
	globalDB   *DB
	dbInitOnce sync.Once
)

// Init initializes the global attack database.
func Init(statePath string) *DB {
	dbInitOnce.Do(func() {
		dbPath := statePath + "/attack_db"
		_ = os.MkdirAll(dbPath, 0700)

		db := &DB{
			records: make(map[string]*IPRecord),
			dbPath:  dbPath,
			stopCh:  make(chan struct{}),
		}
		db.load()
		db.pruneExpired()

		// Background saver — flush dirty records every 30 seconds
		db.wg.Add(1)
		go db.backgroundSaver()

		globalDB = db
	})
	return globalDB
}

// Global returns the global attack database instance.
func Global() *DB {
	return globalDB
}

// RecordFinding records an attack event from a finding.
// Fire-and-forget: never blocks, never panics.
func (db *DB) RecordFinding(f alert.Finding) {
	attackType, ok := checkToAttack[f.Check]
	if !ok {
		return // not an attack-related check
	}

	ip := extractIP(f.Message)
	if ip == "" {
		return
	}

	account := extractAccount(f.Message, f.Details)

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
	if account != "" {
		rec.Accounts[account]++
	}
	rec.ThreatScore = ComputeScore(rec)
	db.pendingEvents = append(db.pendingEvents, event)
	db.dirty = true
	db.mu.Unlock()
}

// MarkBlocked sets the auto-blocked flag on an IP record.
func (db *DB) MarkBlocked(ip string) {
	db.mu.Lock()
	if rec, ok := db.records[ip]; ok {
		rec.AutoBlocked = true
		rec.ThreatScore = ComputeScore(rec)
		db.dirty = true
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
	// Return a copy to avoid races
	cp := *rec
	cp.AttackCounts = make(map[AttackType]int, len(rec.AttackCounts))
	for k, v := range rec.AttackCounts {
		cp.AttackCounts[k] = v
	}
	cp.Accounts = make(map[string]int, len(rec.Accounts))
	for k, v := range rec.Accounts {
		cp.Accounts[k] = v
	}
	return &cp
}

// TopAttackers returns the top N IPs by threat score.
func (db *DB) TopAttackers(n int) []*IPRecord {
	db.mu.RLock()
	defer db.mu.RUnlock()

	all := make([]*IPRecord, 0, len(db.records))
	for _, rec := range db.records {
		cp := *rec
		cp.AttackCounts = make(map[AttackType]int, len(rec.AttackCounts))
		for k, v := range rec.AttackCounts {
			cp.AttackCounts[k] = v
		}
		cp.Accounts = make(map[string]int, len(rec.Accounts))
		for k, v := range rec.Accounts {
			cp.Accounts[k] = v
		}
		all = append(all, &cp)
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
	db.mu.Lock()
	events := db.pendingEvents
	db.pendingEvents = nil
	dirty := db.dirty
	db.dirty = false
	db.mu.Unlock()

	if len(events) > 0 {
		db.appendEvents(events)
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
				ip := strings.TrimRight(fields[0], ",:;)([]")
				// Strip AbuseIPDB score suffix like "(AbuseIPDB"
				if paren := strings.Index(ip, "("); paren > 0 {
					ip = ip[:paren]
				}
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
	}
	return ""
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
			db.dirty = true
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
		cp := *rec
		cp.AttackCounts = make(map[AttackType]int, len(rec.AttackCounts))
		for k, v := range rec.AttackCounts {
			cp.AttackCounts[k] = v
		}
		cp.Accounts = make(map[string]int, len(rec.Accounts))
		for k, v := range rec.Accounts {
			cp.Accounts[k] = v
		}
		result = append(result, &cp)
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
