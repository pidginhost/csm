package alert

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

var emailSendTimeout = 10 * time.Second
var smtpDial = func(timeout time.Duration, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).Dial("tcp", addr)
}

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

	host := smtpHost(smtpAddr)
	deadline := time.Now().Add(emailSendTimeout)

	if err := sendSMTPWithDeadline(smtpAddr, host, from, to, []byte(msg), deadline, true); err != nil {
		if fallbackErr := sendSMTPWithDeadline(smtpAddr, host, from, to, []byte(msg), deadline, false); fallbackErr != nil {
			return fmt.Errorf("%w (original: %v)", fallbackErr, err)
		}
	}

	return nil
}

func smtpHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Split(addr, ":")[0]
}

func sendSMTPWithDeadline(addr, host, from string, to []string, msg []byte, deadline time.Time, tryStartTLS bool) error {
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return fmt.Errorf("smtp send timed out after %s", emailSendTimeout)
	}
	conn, dialErr := smtpDial(timeout, addr)
	if dialErr != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, dialErr)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp deadline: %w", err)
	}
	c, clientErr := smtp.NewClient(conn, host)
	if clientErr != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp connect %s: %w", addr, clientErr)
	}
	defer func() { _ = c.Close() }()

	if err := c.Hello(host); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}
	if tryStartTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", addr, err)
		}
	}
	w, dataErr := c.Data()
	if dataErr != nil {
		return fmt.Errorf("smtp data: %w", dataErr)
	}
	if _, writeErr := w.Write(msg); writeErr != nil {
		return fmt.Errorf("smtp write: %w", writeErr)
	}
	if closeErr := w.Close(); closeErr != nil {
		return fmt.Errorf("smtp close: %w", closeErr)
	}
	if quitErr := c.Quit(); quitErr != nil {
		return fmt.Errorf("smtp quit: %w", quitErr)
	}
	return nil
}
