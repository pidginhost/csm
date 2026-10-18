package hostfacts

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControllerGetReadsReply(t *testing.T) {
	sock := serve(t, t.TempDir(), func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/symbols" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{"group":"fuzzy","rules":[]}]`))
	})
	body, err := ControllerGet(context.Background(), sock, "/symbols", 1<<20, os.Getuid())
	if err != nil || string(body) != `[{"group":"fuzzy","rules":[]}]` {
		t.Fatalf("body=%q err=%v", body, err)
	}
	if _, err := ControllerGet(context.Background(), sock, "/missing", 1<<20, os.Getuid()); err == nil {
		t.Fatal("HTTP 404 accepted")
	}
	for _, path := range []string{"symbols", "/symbols\r\nX-Forwarded-For: 1", "/a b"} {
		if _, err := ControllerGet(context.Background(), sock, path, 1<<20, os.Getuid()); err == nil {
			t.Fatalf("path %q accepted", path)
		}
	}
}

func TestControllerGetRejectsOversize(t *testing.T) {
	sock := serve(t, t.TempDir(), func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
	})
	_, err := ControllerGet(context.Background(), sock, "/symbols", 1024, os.Getuid())
	if err == nil {
		t.Fatal("oversized reply accepted")
	}
	if strings.Contains(err.Error(), "xxxx") {
		t.Fatal("error repeats the reply")
	}
}

// A forwarded header makes rspamd apply passwords on its private socket
// and could forge a peer address; CSM never sends one.
func TestControllerGetNoForwardedHeaders(t *testing.T) {
	var got http.Header
	sock := serve(t, t.TempDir(), func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte("[]"))
	})
	if _, err := ControllerGet(context.Background(), sock, "/symbols", 1<<20, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	for name := range got {
		switch strings.ToLower(name) {
		case "x-forwarded-for", "x-real-ip", "forwarded", "password":
			t.Fatalf("sent %s", name)
		}
	}
}

// After an rspamd restart a squatter could answer at the socket path; CSM
// talks only to the socket's expected owner.
func TestControllerGetRejectsWrongPeer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "controller.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	received := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err = conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			received <- err
			return
		}
		var b [1]byte
		n, err := conn.Read(b[:])
		if n != 0 {
			err = errors.New("the rejected peer received request bytes")
		}
		received <- err
	}()
	if _, err := ControllerGet(context.Background(), sock, "/symbols", 1<<20, os.Getuid()+1); err == nil {
		t.Fatal("a socket served by another user answered")
	}
	select {
	case err := <-received:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("rejected connection did not close without sending a byte: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the peer check did not connect to the listener")
	}
}
