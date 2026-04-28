package alert

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// receiveOneUDP listens on a fresh UDP socket, returns the address
// and a channel that yields the first datagram received. Used to
// black-box test the UDP transport.
func receiveOneUDP(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	out := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16*1024)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			out <- nil
			return
		}
		out <- buf[:n]
	}()
	return conn.LocalAddr().String(), out
}

// receiveOneTCP accepts a single connection and returns the first
// line read from it.
func receiveOneTCP(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	out := make(chan []byte, 1)
	go func() {
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		c, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := bufio.NewReader(c).ReadBytes('\n')
		if err != nil && len(line) == 0 {
			out <- nil
			return
		}
		out <- line
	}()
	return ln.Addr().String(), out
}

func TestSyslogSinkUDPRoundTripRFC5424(t *testing.T) {
	addr, gotCh := receiveOneUDP(t)

	sink, err := NewSyslogSink(SyslogConfig{
		Network:  "udp",
		Address:  addr,
		Facility: "local0",
		Hostname: "host.test",
	})
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	ev := NewAuditEvent("host.test", Finding{
		Severity:  Critical,
		Check:     "webshell_realtime",
		Message:   "boom",
		Timestamp: time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC),
		FilePath:  "/var/www/x.php",
	})
	if err := sink.Emit(ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case raw := <-gotCh:
		if raw == nil {
			t.Fatal("UDP read failed (timed out)")
		}
		s := string(raw)
		// PRI = local0 (16) * 8 + crit (2) = 130
		if !strings.HasPrefix(s, "<130>1 ") {
			t.Errorf("missing or wrong PRI/version prefix: %q", s)
		}
		if !strings.Contains(s, "csm ") {
			t.Errorf("missing APP-NAME 'csm': %q", s)
		}
		if !strings.Contains(s, "webshell_realtime") {
			t.Errorf("missing MSGID (Check name): %q", s)
		}
		// MSG body should be the JSON event.
		if !strings.Contains(s, `"check":"webshell_realtime"`) {
			t.Errorf("missing JSON body: %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP receive timeout")
	}
}

func TestSyslogSinkTCPLFFraming(t *testing.T) {
	addr, gotCh := receiveOneTCP(t)

	sink, err := NewSyslogSink(SyslogConfig{
		Network:  "tcp",
		Address:  addr,
		Facility: "local1",
		Hostname: "tcp.test",
	})
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	if err := sink.Emit(sampleEvent(0)); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case raw := <-gotCh:
		if raw == nil {
			t.Fatal("TCP read failed")
		}
		if !strings.HasSuffix(string(raw), "\n") {
			t.Errorf("TCP line missing LF terminator: %q", raw)
		}
		// PRI = local1 (17) * 8 + crit (2) = 138
		if !strings.HasPrefix(string(raw), "<138>1 ") {
			t.Errorf("wrong PRI prefix: %q", raw)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP receive timeout")
	}
}

func TestSyslogSinkUnknownNetworkRejected(t *testing.T) {
	_, err := NewSyslogSink(SyslogConfig{
		Network:  "smoke-signals",
		Address:  "doesnt:matter",
		Facility: "local0",
	})
	if err == nil {
		t.Fatal("expected error for unknown network")
	}
}

func TestSyslogSinkUnknownFacilityRejected(t *testing.T) {
	addr, _ := receiveOneUDP(t)
	_, err := NewSyslogSink(SyslogConfig{
		Network:  "udp",
		Address:  addr,
		Facility: "bogusfac",
	})
	if err == nil {
		t.Fatal("expected error for unknown facility")
	}
}

func TestSyslogSinkBodyIsValidJSON(t *testing.T) {
	addr, gotCh := receiveOneUDP(t)
	sink, err := NewSyslogSink(SyslogConfig{
		Network:  "udp",
		Address:  addr,
		Hostname: "host.test",
	})
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	if err := sink.Emit(sampleEvent(0)); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	raw := <-gotCh
	if raw == nil {
		t.Fatal("no UDP packet")
	}
	// Pull JSON body: everything after the first " - " separator.
	idx := strings.LastIndex(string(raw), " - ")
	if idx < 0 {
		t.Fatalf("missing structured-data sep in %q", raw)
	}
	body := string(raw[idx+3:])
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &got); err != nil {
		t.Fatalf("body is not valid JSON: %v\nbody=%q", err, body)
	}
	if got["check"] != "webshell_realtime" {
		t.Errorf("body check field = %v", got["check"])
	}
}

func TestSyslogSinkUDSDatagram(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "syslog.sock")
	addr, err := net.ResolveUnixAddr("unixgram", sockPath)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("listen unixgram: %v", err)
	}
	defer func() { _ = conn.Close() }()

	sink, err := NewSyslogSink(SyslogConfig{
		Network:  "unixgram",
		Address:  sockPath,
		Hostname: "uds.test",
	})
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	if emitErr := sink.Emit(sampleEvent(0)); emitErr != nil {
		t.Fatalf("Emit: %v", emitErr)
	}

	buf := make([]byte, 16*1024)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("read uds: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "csm ") {
		t.Errorf("uds body missing csm app-name: %q", buf[:n])
	}
}
