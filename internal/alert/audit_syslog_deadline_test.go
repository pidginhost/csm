package alert

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Emit runs inside the single alert-dispatch goroutine. A receiver that stops
// reading (stalled rsyslog, blackholed SIEM) fills the socket buffer and a
// write without a deadline then blocks forever, which stops every alert,
// history write and incident correlation on the host. The write must give up.
func TestSyslogSinkWriteGivesUpOnStalledReceiver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr == nil {
			accepted <- c // never read from
		}
	}()

	sink, err := NewSyslogSink(SyslogConfig{Network: "tcp", Address: ln.Addr().String(), Hostname: "host"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()

	event := AuditEvent{
		Timestamp: time.Now(),
		Severity:  "critical",
		Check:     "webshell",
		Message:   strings.Repeat("A", 64<<10),
	}
	done := make(chan error, 1)
	go func() {
		// 4096 x 64 KiB is far beyond any loopback socket buffer, so a write
		// must block (and therefore time out) long before the loop ends.
		for i := 0; i < 4096; i++ {
			if err := sink.Emit(event); err != nil {
				done <- err
				return
			}
		}
		done <- errors.New("no write error after 256 MiB against a receiver that never reads")
	}()

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Emit error = %v, want a write deadline error", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Emit blocked on a receiver that never reads; the alert pipeline would wedge")
	}
	select {
	case c := <-accepted:
		_ = c.Close()
	default:
	}
}
