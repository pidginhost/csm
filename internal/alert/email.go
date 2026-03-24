package alert

import (
	"fmt"
	"net/smtp"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

func SendEmail(cfg *config.Config, subject, body string) error {
	to := cfg.Alerts.Email.To
	from := cfg.Alerts.Email.From
	smtpAddr := cfg.Alerts.Email.SMTP

	if len(to) == 0 {
		return fmt.Errorf("no email recipients configured")
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		from,
		strings.Join(to, ", "),
		subject,
		body,
	)

	host := strings.Split(smtpAddr, ":")[0]

	err := smtp.SendMail(smtpAddr, nil, from, to, []byte(msg))
	if err != nil {
		// Retry without auth for local servers
		c, dialErr := smtp.Dial(smtpAddr)
		if dialErr != nil {
			return fmt.Errorf("smtp dial %s: %w (original: %v)", smtpAddr, dialErr, err)
		}
		defer func() { _ = c.Close() }()

		if err := c.Hello(host); err != nil {
			return fmt.Errorf("smtp hello: %w", err)
		}
		if err := c.Mail(from); err != nil {
			return fmt.Errorf("smtp mail from: %w", err)
		}
		for _, addr := range to {
			if err := c.Rcpt(addr); err != nil {
				return fmt.Errorf("smtp rcpt %s: %w", addr, err)
			}
		}
		w, err := c.Data()
		if err != nil {
			return fmt.Errorf("smtp data: %w", err)
		}
		if _, err := w.Write([]byte(msg)); err != nil {
			return fmt.Errorf("smtp write: %w", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("smtp close: %w", err)
		}
		return c.Quit()
	}

	return nil
}
