package hostfacts

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestControllerGetReadsReply(t *testing.T) {
	sock := serve(t, t.TempDir(), func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/symbols" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{"group":"fuzzy","rules":[]}]`))
	})
	body, err := ControllerGet(context.Background(), sock, "/symbols", 1<<20)
	if err != nil || string(body) != `[{"group":"fuzzy","rules":[]}]` {
		t.Fatalf("body=%q err=%v", body, err)
	}
	if _, err := ControllerGet(context.Background(), sock, "/missing", 1<<20); err == nil {
		t.Fatal("HTTP 404 accepted")
	}
	for _, path := range []string{"symbols", "/symbols\r\nX-Forwarded-For: 1", "/a b"} {
		if _, err := ControllerGet(context.Background(), sock, path, 1<<20); err == nil {
			t.Fatalf("path %q accepted", path)
		}
	}
}

func TestControllerGetRejectsOversize(t *testing.T) {
	sock := serve(t, t.TempDir(), func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
	})
	_, err := ControllerGet(context.Background(), sock, "/symbols", 1024)
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
	if _, err := ControllerGet(context.Background(), sock, "/symbols", 1<<20); err != nil {
		t.Fatal(err)
	}
	for name := range got {
		switch strings.ToLower(name) {
		case "x-forwarded-for", "x-real-ip", "forwarded", "password":
			t.Fatalf("sent %s", name)
		}
	}
}
