package learn

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

// serveController answers HTTP on a fresh Unix socket and counts requests.
func serveController(t *testing.T, h http.HandlerFunc) (string, *atomic.Int32) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "controller.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h(w, r)
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock, &n
}

func testClient(sock string) Client {
	return Client{Controller: sock, RspamdUID: os.Getuid()}
}

func TestInspectDigestsUsesSyntheticMessage(t *testing.T) {
	a, b := digest('a'), digest('b')
	sock, _ := serveController(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != InspectPath || r.URL.Query().Get("digests") != string(a)+","+string(b) || string(body) != SyntheticMessage {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(reply(t, hit(a, a, 1, 2), miss(b)))
	})
	insp, err := testClient(sock).InspectDigests(context.Background(), []Digest{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if v, present, err := insp.ExactValue(a); err != nil || !present || v != 2 {
		t.Fatalf("value %d present %v err %v", v, present, err)
	}
	for _, ds := range [][]Digest{nil, {"abc"}, make([]Digest, MaxExplicitDigests+1)} {
		if _, err := testClient(sock).InspectDigests(context.Background(), ds); err == nil {
			t.Fatalf("accepted %d digests", len(ds))
		}
	}
}

func TestInspectSendsBody(t *testing.T) {
	a := digest('a')
	sock, _ := serveController(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.RawQuery != "" || string(body) != "report" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(reply(t, miss(a)))
	})
	insp, err := testClient(sock).Inspect(context.Background(), []byte("report"))
	if err != nil || insp.Distinct != 1 || insp.Results[0].Queried != a {
		t.Fatalf("%+v %v", insp, err)
	}
	if _, err := testClient(sock).Inspect(context.Background(), make([]byte, MaxBody+1)); err == nil {
		t.Fatal("oversized body sent")
	}
}

func TestAddSendsFlagAndWeight(t *testing.T) {
	var got http.Header
	var body string
	sock, _ := serveController(t, func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/fuzzyadd" {
			http.NotFound(w, r)
			return
		}
		got, body = r.Header.Clone(), string(data)
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	if err := testClient(sock).Add(context.Background(), []byte("anchor"), 18); err != nil {
		t.Fatal(err)
	}
	if got.Get("Flag") != "1" || got.Get("Weight") != "18" || body != "anchor" {
		t.Fatalf("flag %q weight %q body %q", got.Get("Flag"), got.Get("Weight"), body)
	}
	for name := range got {
		switch strings.ToLower(name) {
		case "x-forwarded-for", "x-real-ip", "forwarded", "password":
			t.Fatalf("sent %s", name)
		}
	}
	for _, w := range []int32{0, -2} {
		if err := testClient(sock).Add(context.Background(), []byte("anchor"), w); err == nil {
			t.Fatalf("weight %d sent", w)
		}
	}
}

func TestAddTimeoutIsUncertain(t *testing.T) {
	sock, _ := serveController(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		time.Sleep(300 * time.Millisecond)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := testClient(sock).Add(ctx, []byte("anchor"), 2); !errors.Is(err, ErrUncertain) {
		t.Fatalf("err=%v", err)
	}
}

func TestAddErrorReplyIsRejected(t *testing.T) {
	for _, h := range []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"Module disabled"}`))
		},
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"error":"no"}`)) },
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"success":false}`)) },
	} {
		sock, _ := serveController(t, h)
		err := testClient(sock).Add(context.Background(), []byte("anchor"), 2)
		if !errors.Is(err, ErrRejected) || errors.Is(err, ErrUncertain) {
			t.Fatalf("err=%v", err)
		}
		if strings.Contains(err.Error(), "Module") {
			t.Fatal("error repeats the reply")
		}
	}
}

func TestDeleteHashFullDigestOnly(t *testing.T) {
	var hash, flag string
	sock, n := serveController(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/fuzzydelhash" {
			http.NotFound(w, r)
			return
		}
		hash, flag = r.Header.Get("Hash"), r.Header.Get("Flag")
		_, _ = w.Write([]byte(`{"success":true,"hashes":[]}`))
	})
	if err := testClient(sock).DeleteHash(context.Background(), Digest(strings.Repeat("a", 10))); err == nil || n.Load() != 0 {
		t.Fatalf("prefix sent: err=%v requests=%d", err, n.Load())
	}
	if err := testClient(sock).DeleteHash(context.Background(), digest('a')); err != nil {
		t.Fatal(err)
	}
	if hash != string(digest('a')) || flag != "1" {
		t.Fatalf("hash %q flag %q", hash, flag)
	}
}

func TestClientRejectsWrongPeer(t *testing.T) {
	sock, n := serveController(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	c := Client{Controller: sock, RspamdUID: os.Getuid() + 1}
	if err := c.Add(context.Background(), []byte("anchor"), 2); !errors.Is(err, ErrPeer) {
		t.Fatalf("err=%v", err)
	}
	if _, err := c.Inspect(context.Background(), []byte("m")); !errors.Is(err, ErrPeer) {
		t.Fatalf("err=%v", err)
	}
	if n.Load() != 0 {
		t.Fatal("the wrong peer received a request")
	}
}

func TestSyncRunsControlCommand(t *testing.T) {
	var got []string
	var limit time.Duration
	c := Client{Run: func(_ context.Context, l time.Duration, name string, args ...string) antispam.CommandResult {
		got, limit = append([]string{name}, args...), l
		return antispam.CommandResult{}
	}}
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "rspamadm control fuzzy_sync" || limit != SyncTimeout {
		t.Fatalf("ran %q with limit %v", got, limit)
	}
	c.Run = func(context.Context, time.Duration, string, ...string) antispam.CommandResult {
		return antispam.CommandResult{Err: errors.New("exit status 1")}
	}
	if err := c.Sync(context.Background()); err == nil {
		t.Fatal("failed sync accepted")
	}
}

func TestMutationHTTPReplies(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		want           error
	}{
		{"continue then success", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n{\"success\":true}", nil},
		{"early hints then success", "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n{\"success\":true}", nil},
		{"continue without final", "HTTP/1.1 100 Continue\r\n\r\n", ErrUncertain},
		{"unsupported upgrade", "HTTP/1.1 101 Switching Protocols\r\n\r\n", ErrUncertain},
		{"truncated body", "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"success\":true}", ErrUncertain},
		{"truncated chunk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{\"success\":true}\r\n", ErrUncertain},
		{"invalid headers", "HTTP/1.1 200 OK\r\ninvalid reply data\r\n\r\n", ErrUncertain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, calls := serveController(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer func() { _ = conn.Close() }()
				_, _ = io.WriteString(conn, tc.response)
			})
			err := testClient(sock).Add(context.Background(), []byte("anchor"), 2)
			if !errors.Is(err, tc.want) || calls.Load() != 1 {
				t.Fatalf("err=%v, want=%v, requests=%d", err, tc.want, calls.Load())
			}
		})
	}
}

func TestMutationRejectsAmbiguousSuccess(t *testing.T) {
	for _, body := range []string{
		`{"success":false,"success":true}`,
		`{"success":true,"success":null}`,
		`{"Success":true}`,
		`{"success":true,"error":"refused"}`,
		`{"success":`,
		`{}`,
		`{"success":"true"}`,
		`{"success":true,"hashes":"invalid"}`,
		`{"success":true,"hashes":[null]}`,
		`{"success":true,"hashes":["abc"]}`,
		`{"success":true,"extra":1}`,
		`{"error":null}`,
		`{"error":{}}`,
	} {
		t.Run(body, func(t *testing.T) {
			sock, calls := serveController(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			})
			err := testClient(sock).Add(context.Background(), []byte("anchor"), 2)
			if !errors.Is(err, ErrUncertain) || errors.Is(err, ErrRejected) || calls.Load() != 1 {
				t.Fatalf("err=%v requests=%d", err, calls.Load())
			}
		})
	}
}

func TestMutationAcceptsNativeHashes(t *testing.T) {
	sock, calls := serveController(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"success":true,"hashes":["`+string(digest('a'))+`","`+string(digest('b'))+`"]}`)
	})
	if err := testClient(sock).Add(context.Background(), []byte("anchor"), 2); err != nil || calls.Load() != 1 {
		t.Fatalf("native success reply: %v, requests=%d", err, calls.Load())
	}
}
