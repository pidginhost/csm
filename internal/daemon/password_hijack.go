package daemon

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

// PasswordHijackDetector tracks WHM password changes from non-infra IPs
// and correlates them with subsequent cPanel logins to detect the attack
// pattern: attacker changes password via WHM → immediately logs in.
//
// Legitimate flow (excluded):
//
//	Portal (infra IP) changes password via xml-api → user logs in
//
// Attack flow (detected):
//
//	Attacker (non-infra IP) changes password via whostmgr → logs in within 60s
type PasswordHijackDetector struct {
	mu            sync.Mutex
	recentChanges map[string]*passwordChange // account -> change info
	cfg           *config.Config
	alertCh       chan<- alert.Finding
}

type passwordChange struct {
	account   string
	ip        string
	timestamp time.Time
}

const hijackWindow = 120 * time.Second // time window to correlate password change + login

// NewPasswordHijackDetector creates a new detector.
func NewPasswordHijackDetector(cfg *config.Config, alertCh chan<- alert.Finding) *PasswordHijackDetector {
	return &PasswordHijackDetector{
		recentChanges: make(map[string]*passwordChange),
		cfg:           cfg,
		alertCh:       alertCh,
	}
}

// HandlePasswordChange records a WHM password change from a non-infra IP.
func (d *PasswordHijackDetector) HandlePasswordChange(account, ip string) {
	if isInfraIPDaemon(ip, d.cfg.InfraIPs) || ip == "127.0.0.1" || ip == "internal" {
		return // legitimate — portal or admin action
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.recentChanges[account] = &passwordChange{
		account:   account,
		ip:        ip,
		timestamp: time.Now(),
	}

	// Alert on the password change itself — non-infra WHM password change is always suspicious
	d.alertCh <- alert.Finding{
		Severity:  alert.Critical,
		Check:     "whm_password_change_noninfra",
		Message:   fmt.Sprintf("WHM password change from non-infra IP: %s (account: %s)", ip, account),
		Details:   "Password was changed via WHM from an IP outside your infrastructure. This is a strong indicator of account takeover.",
		Timestamp: time.Now(),
	}
}

// HandleLogin checks if a cPanel login matches a recent non-infra password change.
func (d *PasswordHijackDetector) HandleLogin(account, loginIP string) {
	if isInfraIPDaemon(loginIP, d.cfg.InfraIPs) {
		return
	}

	d.mu.Lock()
	change, exists := d.recentChanges[account]
	if exists {
		delete(d.recentChanges, account)
	}
	d.mu.Unlock()

	if !exists {
		return
	}

	// Check if within the hijack window
	if time.Since(change.timestamp) > hijackWindow {
		return
	}

	// CONFIRMED ATTACK: password changed from non-infra IP, login within 120s
	d.alertCh <- alert.Finding{
		Severity:  alert.Critical,
		Check:     "password_hijack_confirmed",
		Message:   fmt.Sprintf("CONFIRMED ACCOUNT HIJACK: %s — password changed from %s, login from %s within %ds", account, change.ip, loginIP, int(time.Since(change.timestamp).Seconds())),
		Details:   fmt.Sprintf("Attack pattern: WHM password change from non-infra IP followed by immediate cPanel login.\nPassword change IP: %s\nLogin IP: %s\nTime between: %ds\n\nBoth IPs should be permanently blocked.", change.ip, loginIP, int(time.Since(change.timestamp).Seconds())),
		Timestamp: time.Now(),
	}
}

// Cleanup removes expired entries.
func (d *PasswordHijackDetector) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for account, change := range d.recentChanges {
		if time.Since(change.timestamp) > hijackWindow*2 {
			delete(d.recentChanges, account)
		}
	}
}

// ParseSessionLineForHijack extracts password change and login events
// from session log lines and feeds them to the detector.
func ParseSessionLineForHijack(line string, detector *PasswordHijackDetector) {
	// WHM password change: [timestamp] info [whostmgr] IP PURGE account:token password_change
	if strings.Contains(line, "[whostmgr]") && strings.Contains(line, "PURGE") && strings.Contains(line, "password_change") {
		ip, account := parseWHMPurge(line)
		if ip != "" && account != "" {
			detector.HandlePasswordChange(account, ip)
		}
	}

	// cPanel login: [timestamp] info [cpaneld] IP NEW account:token ...
	if strings.Contains(line, "[cpaneld]") && strings.Contains(line, " NEW ") {
		// Skip API sessions
		if strings.Contains(line, "method=create_user_session") {
			return
		}
		ip, account := parseCpanelSessionLogin(line)
		if ip != "" && account != "" {
			detector.HandleLogin(account, ip)
		}
	}
}

func parseWHMPurge(line string) (ip, account string) {
	// Format: [timestamp] info [whostmgr] 86.62.29.50 PURGE account:token password_change
	idx := strings.Index(line, "[whostmgr]")
	if idx < 0 {
		return "", ""
	}
	rest := strings.TrimSpace(line[idx+len("[whostmgr]"):])
	fields := strings.Fields(rest)
	if len(fields) < 3 {
		return "", ""
	}
	ip = fields[0]

	// Find account from PURGE account:token
	for i, f := range fields {
		if f == "PURGE" && i+1 < len(fields) {
			parts := strings.SplitN(fields[i+1], ":", 2)
			if len(parts) >= 1 {
				account = parts[0]
			}
			break
		}
	}

	return ip, account
}
