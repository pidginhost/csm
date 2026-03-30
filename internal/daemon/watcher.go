package daemon

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
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
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Seek to end — only process new lines
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
				// Channel full — drop (backpressure)
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
		// File was rotated — read from start
		w.offset = 0
	} else {
		// Same file or larger — seek to where we were
		w.offset, _ = f.Seek(0, io.SeekEnd)
	}
}

// --- Log line handlers ---

func parseSessionLogLine(line string, cfg *config.Config) []alert.Finding {
	var findings []alert.Finding

	// cPanel login from non-infra IP — only alert on direct form login,
	// not API-created sessions (from portal create_user_session)
	if strings.Contains(line, "[cpaneld]") && strings.Contains(line, " NEW ") {
		switch {
		case cfg.Suppressions.SuppressCpanelLogin:
			// Skip all cPanel login alerts
		case strings.Contains(line, "method=create_user_session") ||
			strings.Contains(line, "method=create_session") ||
			strings.Contains(line, "create_user_session"):
			// Portal-created session — no alert
		default:
			ip, account := parseCpanelSessionLogin(line)
			if ip != "" && account != "" && !isInfraIPDaemon(ip, cfg.InfraIPs) &&
				!isTrustedCountry(ip, cfg.Suppressions.TrustedCountries) {
				// WARNING severity — logins are useful for audit trail but
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

func parseEximLogLine(line string, _ *config.Config) []alert.Finding {
	// Count outbound per domain — this is handled by the periodic check.
	// Real-time exim monitoring would need a more complex rate tracking system.
	// For now, only flag obvious spam indicators in real-time.
	if strings.Contains(line, "frozen") && strings.Contains(line, "bounce") {
		return []alert.Finding{{
			Severity: alert.Warning,
			Check:    "exim_frozen_realtime",
			Message:  "Exim frozen bounce detected",
			Details:  truncateDaemon(line, 200),
		}}
	}
	return nil
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

func truncateDaemon(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
