package txn

import (
	"bufio"
	"context"
	"errors"
	"io"
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
		"empty interfaces": {
			map[string]string{"daemon_smtp_ports": "25", "local_interfaces": ""},
			nil,
		},
		"bracketed addresses without ports": {
			map[string]string{"daemon_smtp_ports": "25", "local_interfaces": "<; [192.0.2.10] ; [2001:db8::1]"},
			[]string{"192.0.2.10:25", "[2001:db8::1]:25"},
		},
		"zero interface ports inherit daemon ports": {
			map[string]string{"daemon_smtp_ports": "25 : 587", "local_interfaces": "<; 192.0.2.10.0 ; [2001:db8::1]:0"},
			[]string{"192.0.2.10:25", "192.0.2.10:587", "[2001:db8::1]:25", "[2001:db8::1]:587"},
		},
		"scoped address with dot port": {
			map[string]string{"daemon_smtp_ports": "25", "local_interfaces": "<; 2001:db8::1%eth0.2525"},
			[]string{"[2001:db8::1%eth0]:2525"},
		},
		"scoped address with multiple dots": {
			map[string]string{"daemon_smtp_ports": "25", "local_interfaces": "<; 2001:db8::1%eth.0.2525"},
			[]string{"[2001:db8::1%eth.0.2525]:25"},
		},
		"named daemon port": {
			map[string]string{"daemon_smtp_ports": "smtp", "local_interfaces": "192.0.2.10"},
			[]string{"192.0.2.10:25"},
		},
		"numeric daemon port bases": {
			map[string]string{"daemon_smtp_ports": "0x19 : 025 : 65535", "local_interfaces": "192.0.2.10"},
			[]string{"192.0.2.10:25", "192.0.2.10:21", "192.0.2.10:65535"},
		},
		"named tls ports": {
			map[string]string{"daemon_smtp_ports": "25 : 465 : 587", "local_interfaces": "<; 192.0.2.10 ; 192.0.2.11.465", "tls_on_connect_ports": "submissions"},
			[]string{"192.0.2.10:25", "192.0.2.10:587"},
		},
		"control separators": {
			map[string]string{"daemon_smtp_ports": "<\t25\t\t587", "local_interfaces": "<\n192.0.2.10\n\n2001:db8::1", "tls_on_connect_ports": "<\x7f465\x7f\x7f587"},
			[]string{"192.0.2.10:25", "[2001:db8::1]:25"},
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
			map[string]string{"daemon_smtp_ports": "465", "local_interfaces": "0.0.0.0", "tls_on_connect_ports": "465"},
			nil,
		},
	} {
		if got := listeners(tc.settings); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

func TestReadReplySyntax(t *testing.T) {
	for name, tc := range map[string]struct {
		reply string
		ok    bool
	}{
		"text":                    {"220 ready\r\n", true},
		"empty text":              {"220 \r\n", true},
		"bare code":               {"220\r\n", true},
		"multiline bare terminal": {"220-first\r\n220-second\r\n220\r\n", true},
		"missing separator":       {"220private-banner\r\n", false},
		"extra code digit":        {"2200 private-banner\r\n", false},
		"tab separator":           {"220\tprivate-banner\r\n", false},
		"bare newline":            {"220 private-banner\n", false},
		"incomplete line":         {"220 private-banner", false},
		"wrong multiline code":    {"220-first\r\n221 last\r\n", false},
		"missing terminal line":   {"220-first\r\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			err := readReply(bufio.NewReader(strings.NewReader(tc.reply)), "220")
			if (err == nil) != tc.ok {
				t.Fatalf("readReply returned %v, want success %v", err, tc.ok)
			}
			if err != nil && strings.Contains(err.Error(), "private-banner") {
				t.Fatalf("reply text leaked in error: %v", err)
			}
		})
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

func TestSMTPGreetingCancellationAfterConnect(t *testing.T) {
	for _, stage := range []string{"greeting", "quit reply"} {
		t.Run(stage, func(t *testing.T) {
			ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			if err = ln.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- smtpGreeting(ctx, ln.Addr().String()) }()
			conn, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if stage == "quit reply" {
				if _, err := io.WriteString(conn, "220 ready\r\n"); err != nil {
					t.Fatal(err)
				}
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil || line != "QUIT\r\n" {
					t.Fatalf("client sent %q, error %v", line, err)
				}
			}
			cancel()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("canceled probe reported success")
				}
			case <-time.After(time.Second):
				t.Fatal("probe remained blocked after cancellation")
			}
		})
	}
}

func TestSMTPGreetingBoundsReplies(t *testing.T) {
	addr, sent := fakeSMTP(t, "220-"+strings.Repeat("x", maxGreeting)+"\r\n220 ready\r\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := smtpGreeting(ctx, addr); err == nil {
		t.Fatal("oversized greeting accepted")
	}
	if line := <-sent; line != "" {
		t.Fatalf("sent %q after an incomplete greeting", line)
	}
}

func TestRetryDoesNotProbeExpiredContext(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		window, want := time.Duration(0), context.DeadlineExceeded
		if canceled {
			cancel()
			window, want = time.Second, context.Canceled
		}
		calls := 0
		err := retry(ctx, window, func(context.Context) error {
			calls++
			return nil
		})
		cancel()
		if calls != 0 || !errors.Is(err, want) {
			t.Errorf("canceled %v: got %d calls, error %v; want no calls and %v", canceled, calls, err, want)
		}
	}
}

func TestRetryRejectsSuccessAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := retry(ctx, time.Second, func(context.Context) error {
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}

func TestRetrySucceedsAfterFailure(t *testing.T) {
	calls := 0
	err := retry(context.Background(), 3*time.Second, func(context.Context) error {
		calls++
		if calls == 1 {
			return net.ErrClosed
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("got %d calls, error %v; want two calls and success", calls, err)
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
