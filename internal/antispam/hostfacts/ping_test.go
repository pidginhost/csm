package hostfacts

import (
	"bufio"
	"context"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// serve answers HTTP on a Unix socket at dir/s, the way rspamd's normal
// worker does with bind_socket.
func serve(t *testing.T, dir string, h http.HandlerFunc) string {
	t.Helper()
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func pong(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ping" {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write([]byte("pong\r\n"))
}

func wantPeer() int {
	if runtime.GOOS != "linux" {
		return -1
	}
	return os.Getuid()
}

func TestPingAcceptsPong(t *testing.T) {
	sock := serve(t, t.TempDir(), pong)
	uid, err := Ping(context.Background(), sock)
	if err != nil || uid != wantPeer() {
		t.Fatalf("uid = %d, err = %v; want %d, nil", uid, err, wantPeer())
	}
}

func TestPingRejectsWrongReplies(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"status":  func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "pong", http.StatusInternalServerError) },
		"notpong": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("pang\r\n")) },
		"oversize": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("pong" + strings.Repeat(" ", maxPingBody)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			sock := serve(t, t.TempDir(), h)
			uid, err := Ping(context.Background(), sock)
			if err == nil {
				t.Fatal("wrong reply accepted")
			}
			if uid != wantPeer() {
				t.Errorf("uid = %d after a wrong reply, want %d", uid, wantPeer())
			}
			if strings.Contains(err.Error(), "pang") {
				t.Errorf("error repeats the reply: %v", err)
			}
		})
	}
}

func TestPingGivesUpOnSilentListener(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	held := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			held <- c
		}
	}()
	defer func() {
		select {
		case c := <-held:
			_ = c.Close()
		default:
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Ping(ctx, sock); err == nil {
		t.Fatal("silent listener accepted")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Ping took %s, want it bounded by the caller's deadline", elapsed)
	}
}

func TestPingWithoutListener(t *testing.T) {
	uid, err := Ping(context.Background(), filepath.Join(t.TempDir(), "s"))
	if err == nil || uid != -1 {
		t.Fatalf("uid = %d, err = %v; want -1 and an error", uid, err)
	}
}

func TestSocketFactsThroughSymlinkedRun(t *testing.T) {
	d := t.TempDir()
	mkdir(t, filepath.Join(d, "run", "rspamd"))
	mkdir(t, filepath.Join(d, "var"))
	symlink(t, "../run", filepath.Join(d, "var", "run"))
	serve(t, filepath.Join(d, "run", "rspamd"), pong)

	f := socketFacts(context.Background(), filepath.Join(d, "var", "run", "rspamd", "s"))
	if f.Err != nil || f.Missing || f.PingErr != nil {
		t.Fatalf("facts %+v", f)
	}
	if f.Socket.Mode.Type() != fs.ModeSocket || f.Socket.Path != filepath.Join(d, "run", "rspamd", "s") {
		t.Errorf("socket %+v", f.Socket)
	}
	var walked []string
	for _, p := range f.Parents {
		walked = append(walked, p.Path)
	}
	want := []string{d, filepath.Join(d, "var"), filepath.Join(d, "run"), filepath.Join(d, "run", "rspamd")}
	if got := after(t, walked, d); !slices.Equal(got, want) {
		t.Errorf("parents %v, want %v", got, want)
	}
	if f.PeerUID != wantPeer() || f.RspamdUID != -1 || f.EximUID != -1 || f.EximGID != -1 {
		t.Errorf("uids peer=%d rspamd=%d exim=%d/%d", f.PeerUID, f.RspamdUID, f.EximUID, f.EximGID)
	}
}

// rspamd removes /run/rspamd while stopped: that is a missing socket, a
// temporary state, not a stat failure.
func TestSocketFactsMissingDirectory(t *testing.T) {
	d := t.TempDir()
	f := socketFacts(context.Background(), filepath.Join(d, "rspamd", "s"))
	if !f.Missing || f.Err != nil || f.PeerUID != -1 || len(f.Parents) == 0 {
		t.Fatalf("facts %+v", f)
	}
}

func TestSocketFactsRejectsInvalidPath(t *testing.T) {
	if f := socketFacts(context.Background(), "run/rspamd.sock"); f.Err == nil {
		t.Fatalf("relative socket accepted: %+v", f)
	}
}

func serveReply(t *testing.T, reply string, hold bool) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	release, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		_, _ = io.WriteString(c, reply)
		if hold {
			<-release
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		close(release)
		<-done
	})
	return sock
}

func TestPingDoesNotRepeatMalformedReplies(t *testing.T) {
	const marker = "reply-marker"
	for name, reply := range map[string]string{
		"status line": marker + "\r\n\r\n",
		"status code": "HTTP/1.1 " + marker + "\r\n\r\n",
		"header":      "HTTP/1.1 200 OK\r\n" + marker + "\r\n\r\n",
		"length":      "HTTP/1.1 200 OK\r\nContent-Length: " + marker + "\r\n\r\n",
		"encoding":    "HTTP/1.1 200 OK\r\nTransfer-Encoding: " + marker + "\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			uid, err := Ping(context.Background(), serveReply(t, reply, false))
			if err == nil || strings.Contains(err.Error(), marker) {
				t.Fatalf("malformed reply not safely rejected: uid=%d err=%v", uid, err)
			}
			if uid != wantPeer() {
				t.Errorf("uid = %d, want %d", uid, wantPeer())
			}
		})
	}
}

func TestPingRejectsOversizedHeaders(t *testing.T) {
	reply := "HTTP/1.1 200 OK\r\nX-Padding: " + strings.Repeat("a", 64<<10) + "\r\nContent-Length: 4\r\n\r\npong"
	uid, err := Ping(context.Background(), serveReply(t, reply, false))
	if err == nil || uid != wantPeer() {
		t.Fatalf("oversized headers: uid=%d err=%v", uid, err)
	}
}

func TestPingDoesNotDrainOversizedBody(t *testing.T) {
	reply := "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n" + strings.Repeat("a", maxPingBody+1)
	sock := serveReply(t, reply, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Ping(ctx, sock); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("oversized body accepted")
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("Ping drained the rejected reply instead of closing the connection")
	}
}

func TestReadPingReplyAcceptsValidFraming(t *testing.T) {
	for name, reply := range map[string]string{
		"chunked":       "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npong\r\n0\r\n\r\n",
		"body boundary": "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\npong" + strings.Repeat(" ", maxPingBody-4),
		"CRLF":          "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\npong\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := readPingReply(io.NopCloser(strings.NewReader(reply))); err != nil {
				t.Fatalf("valid reply refused: %v", err)
			}
		})
	}
}

func TestReadPingReplyDoesNotTreatWireLimitAsEOF(t *testing.T) {
	reply := "HTTP/1.1 200 OK\r\nX-Padding: " + strings.Repeat("a", maxPingBody+100) +
		"\r\n\r\npong" + strings.Repeat(" ", maxPingBody)
	if err := readPingReply(io.NopCloser(strings.NewReader(reply))); err == nil {
		t.Fatal("truncated oversized reply accepted as a complete pong")
	}
}

func TestPingCancelsPendingReply(t *testing.T) {
	entered := make(chan struct{})
	sock := serve(t, t.TempDir(), func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Ping(ctx, sock); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not reach the server")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled probe succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled probe waited for its timeout")
	}
}
