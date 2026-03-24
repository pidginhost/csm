package alert

import (
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

type Severity int

const (
	Warning  Severity = iota
	High
	Critical
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

type Finding struct {
	Severity  Severity
	Check     string
	Message   string
	Details   string
	Timestamp time.Time
}

func (f Finding) String() string {
	ts := f.Timestamp.Format("2006-01-02 15:04:05")
	s := fmt.Sprintf("[%s] %s — %s", f.Severity, f.Check, f.Message)
	if f.Details != "" {
		s += "\n  " + strings.ReplaceAll(f.Details, "\n", "\n  ")
	}
	s += fmt.Sprintf("\n  Time: %s", ts)
	return s
}

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

	b.WriteString(fmt.Sprintf("SECURITY ALERT — %s\n", hostname))
	b.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05 MST")))
	b.WriteString(fmt.Sprintf("Findings: %d critical, %d high, %d warning\n", critCount, highCount, warnCount))
	b.WriteString(strings.Repeat("─", 60) + "\n\n")

	// Group by severity
	for _, sev := range []Severity{Critical, High, Warning} {
		for _, f := range findings {
			if f.Severity == sev {
				b.WriteString(f.String())
				b.WriteString("\n\n")
			}
		}
	}

	b.WriteString(strings.Repeat("─", 60) + "\n")
	b.WriteString("CSM — cPanel Security Monitor\n")

	return b.String()
}

func Dispatch(cfg *config.Config, findings []Finding) error {
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
