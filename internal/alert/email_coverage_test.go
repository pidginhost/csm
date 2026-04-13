package alert

import (
	"net"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// ---------------------------------------------------------------------------
// SendEmail — message format validation
// ---------------------------------------------------------------------------

func TestSendEmailMessageContainsHeaders(t *testing.T) {
	// Capture what SendEmail would send by standing up a fake SMTP server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var captured string
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		write := func(s string) { _, _ = conn.Write([]byte(s)) }
		read := func() string {
			buf := make([]byte, 8192)
			n, _ := conn.Read(buf)
			return string(buf[:n])
		}

		write("220 test SMTP\r\n")
		for i := 0; i < 20; i++ {
			line := read()
			if line == "" {
				return
			}
			lower := strings.ToLower(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(lower, "ehlo"), strings.HasPrefix(lower, "helo"):
				write("250-test\r\n250 OK\r\n")
			case strings.HasPrefix(lower, "mail from"), strings.HasPrefix(lower, "rcpt to"):
				write("250 OK\r\n")
			case strings.HasPrefix(lower, "data"):
				write("354 go\r\n")
				for j := 0; j < 10; j++ {
					part := read()
					captured += part
					if strings.Contains(part, "\r\n.\r\n") {
						break
					}
				}
				write("250 OK\r\n")
			case strings.HasPrefix(lower, "quit"):
				write("221 bye\r\n")
				return
			default:
				write("250 OK\r\n")
			}
		}
	}()

	cfg := &config.Config{}
	cfg.Alerts.Email.To = []string{"admin@example.com"}
	cfg.Alerts.Email.From = "csm@server.example.com"
	cfg.Alerts.Email.SMTP = ln.Addr().String()

	if err := SendEmail(cfg, "Test Alert Subject", "Alert body text"); err != nil {
		t.Fatalf("SendEmail: %v", err)
	}
	<-done

	if !strings.Contains(captured, "From: csm@server.example.com") {
		t.Errorf("message should contain From header, got: %s", captured)
	}
	if !strings.Contains(captured, "To: admin@example.com") {
		t.Errorf("message should contain To header, got: %s", captured)
	}
	if !strings.Contains(captured, "Subject: Test Alert Subject") {
		t.Errorf("message should contain Subject header, got: %s", captured)
	}
	if !strings.Contains(captured, "Content-Type: text/plain; charset=UTF-8") {
		t.Errorf("message should contain Content-Type header, got: %s", captured)
	}
	if !strings.Contains(captured, "Alert body text") {
		t.Errorf("message should contain body, got: %s", captured)
	}
}

func TestSendEmailMultipleRecipients(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var captured string
	rcptCount := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		write := func(s string) { _, _ = conn.Write([]byte(s)) }
		read := func() string {
			buf := make([]byte, 8192)
			n, _ := conn.Read(buf)
			return string(buf[:n])
		}

		write("220 test SMTP\r\n")
		for i := 0; i < 20; i++ {
			line := read()
			if line == "" {
				return
			}
			lower := strings.ToLower(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(lower, "ehlo"), strings.HasPrefix(lower, "helo"):
				write("250-test\r\n250 OK\r\n")
			case strings.HasPrefix(lower, "mail from"):
				write("250 OK\r\n")
			case strings.HasPrefix(lower, "rcpt to"):
				rcptCount++
				write("250 OK\r\n")
			case strings.HasPrefix(lower, "data"):
				write("354 go\r\n")
				for j := 0; j < 10; j++ {
					part := read()
					captured += part
					if strings.Contains(part, "\r\n.\r\n") {
						break
					}
				}
				write("250 OK\r\n")
			case strings.HasPrefix(lower, "quit"):
				write("221 bye\r\n")
				return
			default:
				write("250 OK\r\n")
			}
		}
	}()

	cfg := &config.Config{}
	cfg.Alerts.Email.To = []string{"admin@example.com", "ops@example.com", "security@example.com"}
	cfg.Alerts.Email.From = "csm@server.example.com"
	cfg.Alerts.Email.SMTP = ln.Addr().String()

	if err := SendEmail(cfg, "Multi Recipient Test", "body"); err != nil {
		t.Fatalf("SendEmail: %v", err)
	}
	<-done

	if !strings.Contains(captured, "admin@example.com, ops@example.com, security@example.com") {
		t.Errorf("To header should list all recipients, got: %s", captured)
	}
}

func TestSendEmailEmptyRecipients(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "127.0.0.1:25"
	err := SendEmail(cfg, "sub", "body")
	if err == nil {
		t.Fatal("empty To should error")
	}
	if !strings.Contains(err.Error(), "no email recipients") {
		t.Errorf("error = %v, want 'no email recipients' message", err)
	}
}

func TestSendEmailHostExtraction(t *testing.T) {
	// Verifies that host is extracted correctly from smtpAddr for HELO.
	// We use a non-listening port so it will fail, but the error path
	// tests the host extraction logic.
	cfg := &config.Config{}
	cfg.Alerts.Email.To = []string{"a@b.test"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "mail.example.com:587"

	err := SendEmail(cfg, "sub", "body")
	// Both smtp.SendMail and the fallback Dial should fail since nothing listens.
	if err == nil {
		t.Fatal("unreachable host should error")
	}
	// The error should reference the smtp address
	if !strings.Contains(err.Error(), "mail.example.com:587") {
		t.Errorf("error should reference smtp addr, got: %v", err)
	}
}

func TestSendEmailFallbackPath(t *testing.T) {
	// This test verifies that when smtp.SendMail fails (e.g. auth required),
	// the fallback path using smtp.Dial is attempted.
	// We use a server that rejects AUTH but allows unauthenticated relay.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// First connection: smtp.SendMail — report auth failure to force fallback
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		write := func(s string) { _, _ = conn.Write([]byte(s)) }
		read := func() string {
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			return string(buf[:n])
		}

		write("220 test\r\n")
		for i := 0; i < 20; i++ {
			line := read()
			if line == "" {
				break
			}
			lower := strings.ToLower(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(lower, "ehlo"):
				// Advertise AUTH PLAIN to trigger an auth attempt that we can fail
				write("250-test\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
			case strings.HasPrefix(lower, "helo"):
				write("250 OK\r\n")
			case strings.HasPrefix(lower, "mail from"):
				// Reject to simulate server requiring auth
				write("530 Authentication required\r\n")
			case strings.HasPrefix(lower, "quit"):
				write("221 bye\r\n")
				_ = conn.Close()
				goto secondConn
			default:
				write("250 OK\r\n")
			}
		}
		_ = conn.Close()

	secondConn:
		// Second connection: fallback Dial path
		conn2, acceptErr2 := ln.Accept()
		if acceptErr2 != nil {
			return
		}
		defer func() { _ = conn2.Close() }()

		write2 := func(s string) { _, _ = conn2.Write([]byte(s)) }
		read2 := func() string {
			buf := make([]byte, 4096)
			n, _ := conn2.Read(buf)
			return string(buf[:n])
		}

		write2("220 test fallback\r\n")
		for i := 0; i < 20; i++ {
			line := read2()
			if line == "" {
				return
			}
			lower := strings.ToLower(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(lower, "ehlo"), strings.HasPrefix(lower, "helo"):
				write2("250-test\r\n250 OK\r\n")
			case strings.HasPrefix(lower, "mail from"), strings.HasPrefix(lower, "rcpt to"):
				write2("250 OK\r\n")
			case strings.HasPrefix(lower, "data"):
				write2("354 go\r\n")
				for j := 0; j < 10; j++ {
					part := read2()
					if strings.Contains(part, "\r\n.\r\n") {
						break
					}
				}
				write2("250 OK\r\n")
			case strings.HasPrefix(lower, "quit"):
				write2("221 bye\r\n")
				return
			default:
				write2("250 OK\r\n")
			}
		}
	}()

	cfg := &config.Config{}
	cfg.Alerts.Email.To = []string{"admin@example.com"}
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.Alerts.Email.SMTP = ln.Addr().String()

	err = SendEmail(cfg, "Fallback Test", "body")
	if err != nil {
		t.Fatalf("fallback path should succeed: %v", err)
	}
	<-done
}
