package hostfacts

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// serveRspamd answers one request on a unix socket with body and sends the
// raw request, headers and message, on the returned channel.
func serveRspamd(t *testing.T, body string) (string, <-chan string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	requests := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		r := bufio.NewReader(c)
		var head strings.Builder
		length := 0
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			head.WriteString(line)
			if line == "\r\n" {
				break
			}
			if k, v, ok := strings.Cut(strings.TrimRight(line, "\r\n"), ":"); ok && textproto.CanonicalMIMEHeaderKey(k) == "Content-Length" {
				length, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
		msg := make([]byte, length)
		if _, err := io.ReadFull(r, msg); err != nil {
			return
		}
		requests <- head.String() + string(msg)
		_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}()
	return sock, requests
}

func TestCanaryReadsTheGeneration(t *testing.T) {
	sock, requests := serveRspamd(t, `{"symbols":{"CSM_IP_CANARY":{"name":"CSM_IP_CANARY","score":0,"options":["gabcdef012345"]}}}`)
	gen, err := Canary(context.Background(), sock)
	if err != nil || gen != "abcdef012345" {
		t.Fatalf("Canary = %q, %v", gen, err)
	}
	req := <-requests
	for _, want := range []string{"POST /checkv2 HTTP/1.1\r\n", "\r\nIP: 192.0.2.255\r\n", "\r\nSettings: {symbols_enabled = [\"CSM_IP\"]}\r\n", "\r\nFlags: no_log,no_stat\r\n"} {
		if !strings.Contains(req, want) {
			t.Errorf("request lacks %q:\n%s", want, req)
		}
	}
}

func TestCanaryWithoutTheSymbol(t *testing.T) {
	sock, _ := serveRspamd(t, `{"symbols":{}}`)
	if gen, err := Canary(context.Background(), sock); err != nil || gen != "" {
		t.Fatalf("no canary = %q, %v", gen, err)
	}
	sock, _ = serveRspamd(t, `not json`)
	if _, err := Canary(context.Background(), sock); err == nil || strings.Contains(err.Error(), "not json") {
		t.Fatalf("bad reply = %v", err)
	}
}
