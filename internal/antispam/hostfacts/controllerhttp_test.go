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

func TestControllerDoSendsHeadersAndBody(t *testing.T) {
	var method, path, flag, body string
	sock := serve(t, t.TempDir(), func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		method, path, flag, body = r.Method, r.URL.RequestURI(), r.Header.Get("Flag"), string(data)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"refused"}`))
	})
	status, reply, err := ControllerDo(context.Background(), sock, os.Getuid(), http.MethodPost, "/fuzzyadd?x=1", map[string]string{"Flag": "1"}, []byte("message"), 1024)
	if err != nil || status != http.StatusInternalServerError || string(reply) != `{"error":"refused"}` {
		t.Fatalf("status=%d reply=%q err=%v", status, reply, err)
	}
	if method != http.MethodPost || path != "/fuzzyadd?x=1" || flag != "1" || body != "message" {
		t.Fatalf("sent %s %s flag=%q body=%q", method, path, flag, body)
	}
	for _, hdr := range []map[string]string{{"Flag": "1\r\nX: y"}, {"Bad Name": "1"}, {"": "1"}} {
		if _, _, err := ControllerDo(context.Background(), sock, os.Getuid(), http.MethodPost, "/fuzzyadd", hdr, nil, 1024); !errors.Is(err, ErrControllerNotSent) {
			t.Fatalf("header %q: err=%v", hdr, err)
		}
	}
}

// Once a request is written, a missing reply leaves its outcome unknown;
// before that, nothing reached rspamd.
func TestControllerDoSeparatesNotSentFromNoReply(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.sock")
	if _, _, err := ControllerDo(context.Background(), missing, os.Getuid(), http.MethodPost, "/fuzzyadd", nil, nil, 1024); !errors.Is(err, ErrControllerNotSent) || errors.Is(err, ErrControllerNoReply) {
		t.Fatalf("connect failure: %v", err)
	}
	sock := serve(t, t.TempDir(), func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		time.Sleep(300 * time.Millisecond)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := ControllerDo(ctx, sock, os.Getuid(), http.MethodPost, "/fuzzyadd", nil, []byte("m"), 1024); !errors.Is(err, ErrControllerNoReply) || errors.Is(err, ErrControllerNotSent) {
		t.Fatalf("timeout after send: %v", err)
	}
	if _, _, err := ControllerDo(context.Background(), sock, os.Getuid()+1, http.MethodPost, "/fuzzyadd", nil, nil, 1024); !errors.Is(err, ErrControllerPeer) || !errors.Is(err, ErrControllerNotSent) {
		t.Fatalf("wrong peer: %v", err)
	}
}

func TestControllerDoOversizeClosesBeforeDraining(t *testing.T) {
	release := make(chan struct{})
	sock := serve(t, t.TempDir(), func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Length", "4096")
		_, _ = w.Write([]byte(strings.Repeat("x", 1025)))
		w.(http.Flusher).Flush()
		<-release
	})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := ControllerDo(ctx, sock, os.Getuid(), http.MethodPost, "/fuzzyadd", nil, []byte("anchor"), 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrControllerNoReply) || errors.Is(err, ErrControllerNotSent) {
			t.Fatalf("oversized reply: %v", err)
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("oversized reply blocked while draining the body")
	}
}

type controllerWriteResult struct {
	n   int
	err error
}

func (w controllerWriteResult) Write([]byte) (int, error) { return w.n, w.err }

func TestControllerWriteClassifiesSentBytes(t *testing.T) {
	request := []byte("request")
	for _, tc := range []struct {
		name  string
		write controllerWriteResult
		want  error
	}{
		{"nothing sent", controllerWriteResult{0, io.ErrClosedPipe}, ErrControllerNotSent},
		{"partly sent", controllerWriteResult{1, io.ErrClosedPipe}, ErrControllerNoReply},
		{"all sent with error", controllerWriteResult{len(request), io.ErrClosedPipe}, ErrControllerNoReply},
		{"sent", controllerWriteResult{len(request), nil}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := writeControllerRequest(tc.write, request)
			if !errors.Is(err, tc.want) || (tc.want == ErrControllerNoReply && errors.Is(err, ErrControllerNotSent)) {
				t.Fatalf("err=%v want=%v", err, tc.want)
			}
		})
	}
}

func TestControllerRequestRejectsIdentityHeaders(t *testing.T) {
	for _, name := range []string{"X-Forwarded-For", "x-real-ip", "Forwarded", "pAsSwOrD", "Authorization", "Proxy-Authorization"} {
		if _, err := controllerRequest(http.MethodPost, "/fuzzyadd", map[string]string{name: ""}, nil); err == nil {
			t.Errorf("accepted identity header %s", name)
		}
	}
}
