package alert

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

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
	Severity    Severity  `json:"severity"`
	Check       string    `json:"check"`
	Message     string    `json:"message"`
	Details     string    `json:"details,omitempty"`
	FilePath    string    `json:"file_path,omitempty"`
	ProcessInfo string    `json:"process_info,omitempty"` // "pid=N cmd=name uid=N" from fanotify
	PID         int       `json:"pid,omitempty"`          // structured PID for auto-response
	Timestamp   time.Time `json:"timestamp"`
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
	if f.Details == "" {
		return fmt.Sprintf("%s:%s", f.Check, f.Message)
	}
	h := sha256.Sum256([]byte(f.Details))
	return fmt.Sprintf("%s:%s:%x", f.Check, f.Message, h[:4])
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

var rateLimitMu sync.Mutex

// checkRateLimit returns true if we can send more alerts this hour.
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

// Dispatch sends alerts via all configured channels.
func Dispatch(cfg *config.Config, findings []Finding) error {
	// Deduplicate
	findings = Deduplicate(findings)

	// Filter out blocked IP alerts if configured
	findings = FilterBlockedAlerts(cfg, findings)

	if len(findings) == 0 {
		return nil
	}

	emailFindings := []Finding(nil)
	if cfg.Alerts.Email.Enabled {
		emailFindings = filterChecks(findings, cfg.Alerts.Email.DisabledChecks)
	}

	webhookFindings := []Finding(nil)
	if cfg.Alerts.Webhook.Enabled {
		webhookFindings = findings
	}

	if len(emailFindings) == 0 && len(webhookFindings) == 0 {
		return nil
	}

	// Rate limit check — CRITICAL realtime findings (malware, webshells,
	// backdoors) always get through. Only non-critical alerts are rate-limited.
	hasCritical := false
	for _, f := range findings {
		if f.Severity == Critical {
			hasCritical = true
			break
		}
	}
	if !hasCritical && !checkRateLimit(cfg.StatePath, cfg.Alerts.MaxPerHour) {
		fmt.Fprintf(os.Stderr, "Alert rate limit reached (%d/hour), skipping non-critical alert dispatch\n", cfg.Alerts.MaxPerHour)
		return nil
	}
	// Still count critical dispatches toward the rate limit budget
	if hasCritical {
		checkRateLimit(cfg.StatePath, cfg.Alerts.MaxPerHour)
	}

	var errs []error

	if len(emailFindings) > 0 {
		subject := buildSubject(cfg.Hostname, emailFindings)
		body := FormatAlert(cfg.Hostname, emailFindings)
		if err := SendEmail(cfg, subject, body); err != nil {
			errs = append(errs, fmt.Errorf("email: %w", err))
		}
	}

	if len(webhookFindings) > 0 {
		subject := buildSubject(cfg.Hostname, webhookFindings)
		body := FormatAlert(cfg.Hostname, webhookFindings)
		if err := SendWebhook(cfg, subject, body); err != nil {
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		}
	}

	if len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		return fmt.Errorf("alert dispatch errors: %s", strings.Join(msgs, "; "))
	}

	return nil
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
	defer func() { _ = resp.Body.Close() }()
}
