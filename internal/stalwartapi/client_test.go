package stalwartapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	testUser     = "admin"
	testPassword = "pw-must-not-leak-9"
	testAccount  = "d333333"
)

// fakeStalwart answers the session document and one JMAP method per POST.
// reply builds the method response args for a request; a nil reply answers
// with an empty object.
type fakeStalwart struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	calls []fakeCall
	reply func(method string, args map[string]any) (string, any)
}

type fakeCall struct {
	Method string
	Args   map[string]any
	Using  []string
	User   string
	Pass   string
}

func newFake(t *testing.T) *fakeStalwart {
	t.Helper()
	f := &fakeStalwart{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jmap", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != testUser || p != testPassword {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiUrl":          "https://mail.example.org/jmap/",
			"primaryAccounts": map[string]string{"urn:ietf:params:jmap:core": "other", "urn:stalwart:jmap": testAccount},
		})
	})
	mux.HandleFunc("/jmap/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Using       []string            `json:"using"`
			MethodCalls [][]json.RawMessage `json:"methodCalls"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.MethodCalls) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var name, id string
		var args map[string]any
		_ = json.Unmarshal(req.MethodCalls[0][0], &name)
		_ = json.Unmarshal(req.MethodCalls[0][1], &args)
		_ = json.Unmarshal(req.MethodCalls[0][2], &id)
		u, p, _ := r.BasicAuth()
		f.mu.Lock()
		f.calls = append(f.calls, fakeCall{Method: name, Args: args, Using: req.Using, User: u, Pass: p})
		f.mu.Unlock()
		respName, respArgs := name, any(map[string]any{})
		if f.reply != nil {
			respName, respArgs = f.reply(name, args)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"methodResponses": []any{[]any{respName, respArgs, id}},
			"sessionState":    "s1",
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeStalwart) client() *Client { return New(f.srv.URL, testUser, testPassword) }

func (f *fakeStalwart) last() fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		f.t.Fatal("no JMAP call was made")
	}
	return f.calls[len(f.calls)-1]
}

func TestClientUsesSessionAccountNotAPIURL(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"list": []any{}}
	}
	if _, err := f.client().TracingLevels(context.Background()); err != nil {
		t.Fatalf("TracingLevels: %v", err)
	}
	c := f.last()
	if c.Method != "x:EventTracingLevel/get" {
		t.Fatalf("method = %q", c.Method)
	}
	if c.Args["accountId"] != testAccount {
		t.Fatalf("accountId = %v, want %s", c.Args["accountId"], testAccount)
	}
	if c.User != testUser || c.Pass != testPassword {
		t.Fatal("request did not carry the admin login as Basic auth")
	}
	want := []string{"urn:ietf:params:jmap:core", "urn:stalwart:jmap"}
	if strings.Join(c.Using, " ") != strings.Join(want, " ") {
		t.Fatalf("using = %v, want %v", c.Using, want)
	}
}

func TestClientUnauthorized(t *testing.T) {
	f := newFake(t)
	_, err := New(f.srv.URL, testUser, "wrong").TracingLevels(context.Background())
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestClientErrorsNeverContainPassword(t *testing.T) {
	ctx := context.Background()

	unauthorized := newFake(t)
	_, err401 := New(unauthorized.srv.URL, testUser, testPassword+"x").TracingLevels(ctx)

	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(r.Header.Get("Authorization") + " " + testPassword + " " + string(body)))
	}))
	defer echo.Close()
	_, err500 := New(echo.URL, testUser, testPassword).TracingLevels(ctx)

	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	_, errClosed := New(closedURL, testUser, testPassword).TracingLevels(ctx)

	for name, err := range map[string]error{"401": err401, "500": err500, "closed": errClosed} {
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if strings.Contains(err.Error(), testPassword) {
			t.Fatalf("%s: error contains the password: %v", name, err)
		}
	}
}

func TestClientMethodError(t *testing.T) {
	f := newFake(t)
	f.reply = func(string, map[string]any) (string, any) {
		return "error", map[string]any{"type": "forbidden", "description": "no"}
	}
	_, err := f.client().TracingLevels(context.Background())
	var me *MethodError
	if !errors.As(err, &me) || me.Type != "forbidden" || me.Method != "x:EventTracingLevel/get" {
		t.Fatalf("err = %#v, want MethodError forbidden", err)
	}
}

func TestClientCapsResponseSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jmap" {
			_, _ = w.Write([]byte(`{"primaryAccounts":{"urn:stalwart:jmap":"a","pad":"`))
			_, _ = w.Write([]byte(strings.Repeat("x", 5<<20)))
			_, _ = w.Write([]byte(`"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := New(srv.URL, testUser, testPassword).TracingLevels(context.Background()); err == nil {
		t.Fatal("a 5 MiB response was accepted")
	}
}
