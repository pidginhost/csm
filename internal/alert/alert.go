package alert

import (
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
	s := fmt.Sprintf("[%s] %s — %s", f.Severity, f.Check, f.Message)
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
	return fmt.Sprintf("%s:%s", f.Check, f.Message)
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

	fmt.Fprintf(&b, "SECURITY ALERT — %s\n", hostname)
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
	b.WriteString("CSM — Continuous Security Monitor\n")

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

	// Redact password= values in URLs and POST data
	// Matches: password=X, pass=X, passwd=X (up to next & or space or quote)
	for _, prefix := range []string{
		"password=", "pass=", "passwd=", "new_password=",
		"old_password=", "confirmpassword=",
	} {
		for {
			lower := strings.ToLower(s)
			idx := strings.Index(lower, prefix)
			if idx < 0 {
				break
			}
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
			} else {
				break
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

	// Rate limit check
	if !checkRateLimit(cfg.StatePath, cfg.Alerts.MaxPerHour) {
		fmt.Fprintf(os.Stderr, "Alert rate limit reached (%d/hour), skipping alert dispatch\n", cfg.Alerts.MaxPerHour)
		return nil
	}

	body := FormatAlert(cfg.Hostname, findings)

	subject := fmt.Sprintf("[CSM] %s — %d security finding(s)", cfg.Hostname, len(findings))
	for _, f := range findings {
		if f.Severity == Critical {
			subject = fmt.Sprintf("[CSM] CRITICAL — %s — %d finding(s)", cfg.Hostname, len(findings))
			break
		}
	}

	var errs []error

	if cfg.Alerts.Email.Enabled {
		if err := SendEmail(cfg, subject, body); err != nil {
			errs = append(errs, fmt.Errorf("email: %w", err))
		}
	}

	if cfg.Alerts.Webhook.Enabled {
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
