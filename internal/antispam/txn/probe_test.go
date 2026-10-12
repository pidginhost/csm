package txn

import (
	"bufio"
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestListeners(t *testing.T) {
	for name, tc := range map[string]struct {
		settings map[string]string
		want     []string
	}{
		"cpanel defaults": {
			map[string]string{"daemon_smtp_ports": "25 : 465 : 587", "local_interfaces": "<; 0.0.0.0 ; ::0", "tls_on_connect_ports": "465"},
			[]string{"127.0.0.1:25", "127.0.0.1:587", "[::1]:25", "[::1]:587"},
		},
		"unset interfaces": {
			map[string]string{"daemon_smtp_ports": "25", "local_interfaces": ""},
			[]string{"127.0.0.1:25", "[::1]:25"},
		},
		"specific addresses": {
			map[string]string{"daemon_smtp_ports": "25", "local_interfaces": "<; 192.0.2.10 ; 2001:db8::25"},
			[]string{"192.0.2.10:25", "[2001:db8::25]:25"},
		},
		"interface ports": {
			map[string]string{"daemon_smtp_ports": "25", "local_interfaces": "<; 192.0.2.10.2525 ; [2001:db8::1]:26 ; 2001:db8::2.27 ; 192.0.2.11.465", "tls_on_connect_ports": "465"},
			[]string{"192.0.2.10:2525", "[2001:db8::1]:26", "[2001:db8::2]:27"},
		},
		"colon list with doubled colons": {
			map[string]string{"daemon_smtp_ports": "smtp : 25", "local_interfaces": "127.0.0.1 : ::::1"},
			[]string{"127.0.0.1:25", "[::1]:25"},
		},
		"only tls ports": {
			map[string]string{"daemon_smtp_ports": "465", "tls_on_connect_ports": "465"},
			nil,
		},
	} {
		if got := listeners(tc.settings); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

// fakeSMTP serves one session with greeting and records what the client sent.
func fakeSMTP(t *testing.T, greeting string) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte(greeting))
		line, _ := bufio.NewReader(conn).ReadString('\n')
		got <- line
		_, _ = conn.Write([]byte("221 bye\r\n"))
	}()
	return ln.Addr().String(), got
}

func TestSMTPGreetingWaitsForWholeBannerAndQuits(t *testing.T) {
	addr, sent := fakeSMTP(t, "220-host ESMTP Exim\r\n220-second line\r\n220 last line\r\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := smtpGreeting(ctx, addr); err != nil {
		t.Fatal(err)
	}
	if line := <-sent; line != "QUIT\r\n" {
		t.Errorf("client sent %q, want QUIT", line)
	}
}

func TestSMTPGreetingRejectsOtherReplies(t *testing.T) {
	addr, _ := fakeSMTP(t, "554 secret-banner-text\r\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := smtpGreeting(ctx, addr)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("err = %v", err)
	}
}

func TestRetryStopsAtWindow(t *testing.T) {
	start := time.Now()
	calls := 0
	err := retry(context.Background(), 500*time.Millisecond, func(context.Context) error { calls++; return net.ErrClosed })
	if err == nil || calls < 2 || time.Since(start) > 2*time.Second {
		t.Errorf("err %v after %d calls in %v", err, calls, time.Since(start))
	}
}
