package hostfacts

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestCanaryDoesNotDrainRejectedReply(t *testing.T) {
	for name, reply := range map[string]string{
		"status": "HTTP/1.1 503 Unavailable\r\nContent-Length: 1048576\r\n\r\n",
		"body": "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n" +
			strings.Repeat("a", maxCanaryBody+1),
	} {
		t.Run(name, func(t *testing.T) {
			sock := serveReply(t, reply, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := Canary(ctx, sock); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("rejected reply accepted")
				}
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("Canary drained the rejected reply instead of closing the connection")
			}
		})
	}
}

func TestCanaryDoesNotTreatWireLimitAsEOF(t *testing.T) {
	body := `{"symbols":{"CSM_IP_CANARY":{"options":["gabcdef012345"]}}}`
	reply := "HTTP/1.1 200 OK\r\nX-Padding: " + strings.Repeat("a", maxCanaryBody+100) +
		"\r\n\r\n" + body + strings.Repeat(" ", maxCanaryBody)
	gen, err := Canary(context.Background(), serveReply(t, reply, false))
	if err == nil || gen != "" {
		t.Fatalf("truncated oversized reply accepted: generation=%q err=%v", gen, err)
	}
}

func TestCanaryRejectsMalformedGeneration(t *testing.T) {
	for _, option := range []string{"g", "gshort", "gabcdef0123450", "gABCDEF012345", "gabcdef01234z", "g\nreply-marker"} {
		t.Run(strconv.Quote(option), func(t *testing.T) {
			body := fmt.Sprintf(`{"symbols":{"CSM_IP_CANARY":{"options":[%s]}}}`, strconv.Quote(option))
			gen, err := Canary(context.Background(), serveReply(t,
				fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body), false))
			if gen != "" || err == nil || strings.Contains(err.Error(), "reply-marker") {
				t.Fatalf("malformed generation not safely rejected: generation=%q err=%v", gen, err)
			}
		})
	}
}

func TestReadCanaryReplyAcceptsValidFraming(t *testing.T) {
	const body = `{"symbols":{"CSM_IP_CANARY":{"options":["gabcdef012345"]}}}`
	for name, reply := range map[string]string{
		"chunked": fmt.Sprintf("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body),
		"body boundary": fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", maxCanaryBody) +
			body + strings.Repeat(" ", maxCanaryBody-len(body)),
		"EOF": "HTTP/1.1 200 OK\r\n\r\n" + body,
	} {
		t.Run(name, func(t *testing.T) {
			gen, err := readCanaryReply(io.NopCloser(strings.NewReader(reply)))
			if err != nil || gen != "abcdef012345" {
				t.Fatalf("valid reply refused: generation=%q err=%v", gen, err)
			}
		})
	}
}

func TestCanaryRejectsInvalidReplies(t *testing.T) {
	const marker = "reply-marker"
	for name, reply := range map[string]string{
		"status line": marker + "\r\n\r\n",
		"header":      "HTTP/1.1 200 OK\r\n" + marker + "\r\n\r\n",
		"length":      "HTTP/1.1 200 OK\r\nContent-Length: " + marker + "\r\n\r\n",
		"headers too large": "HTTP/1.1 200 OK\r\nX-Padding: " +
			strings.Repeat("a", maxCanaryReply) + "\r\n\r\n{}",
		"truncated": "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}",
		"JSON":      "HTTP/1.1 200 OK\r\n\r\n" + marker,
		"options type": "HTTP/1.1 200 OK\r\n\r\n" +
			`{"symbols":{"CSM_IP_CANARY":{"options":"` + marker + `"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			gen, err := readCanaryReply(io.NopCloser(strings.NewReader(reply)))
			if err == nil || gen != "" || strings.Contains(err.Error(), marker) {
				t.Fatalf("invalid reply not safely rejected: generation=%q err=%v", gen, err)
			}
		})
	}
}

func TestCanaryCancelsPendingReply(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			entered := make(chan struct{})
			sock := serve(t, t.TempDir(), func(_ http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read request body: %v", err)
					return
				}
				close(entered)
				<-r.Context().Done()
			})
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := Canary(ctx, sock); done <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("probe did not reach the server")
			}
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled probe succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("canceled probe waited for its timeout")
			}
		})
	}
}
