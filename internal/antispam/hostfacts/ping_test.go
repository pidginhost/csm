package hostfacts

import (
	"context"
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
