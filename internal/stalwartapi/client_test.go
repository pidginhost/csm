package stalwartapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

func TestClientRejectsUnacknowledgedWrites(t *testing.T) {
	for _, reply := range []map[string]any{{}, {"created": map[string]any{"c": nil}}} {
		f := newFake(t)
		f.reply = func(method string, _ map[string]any) (string, any) { return method, reply }
		if err := f.client().SetTracingLevel(context.Background(), "", "auth.failed", "info"); err == nil {
			t.Fatal("unacknowledged write reported success")
		}
	}
	f := newFake(t)
	if err := f.client().SetHTTPSettings(context.Background(), HTTPSettings{}); err == nil {
		t.Fatal("unacknowledged update reported success")
	}
}

func TestClientRedactsServerErrors(t *testing.T) {
	for _, kind := range []string{"method", "set", "name", "decode"} {
		t.Run(kind, func(t *testing.T) {
			f := newFake(t)
			f.reply = func(method string, _ map[string]any) (string, any) {
				switch kind {
				case "method":
					return "error", map[string]any{"type": testPassword, "description": testPassword}
				case "set":
					return method, map[string]any{"notUpdated": map[string]any{"singleton": map[string]any{"type": testPassword, "description": testPassword}}}
				case "name":
					return testPassword, map[string]any{}
				default:
					return method, map[string]any{"list": []any{map[string]any{"forwardedHops": testPassword}}}
				}
			}
			var err error
			if kind == "set" {
				err = f.client().SetHTTPSettings(context.Background(), HTTPSettings{})
			} else {
				_, err = f.client().HTTPSettings(context.Background())
			}
			if err == nil {
				t.Fatal("expected failure")
			}
			if strings.Contains(err.Error(), testPassword) {
				t.Fatal("password exposed by error")
			}
		})
	}
}

func TestClientRejectsUnsafeAddressesBeforeSending(t *testing.T) {
	for _, address := range []string{"http://192.0.2.1:8080", "http://admin:" + testPassword + "@127.0.0.1:8080", "http://127.0.0.1:8080/?q=x", "http://127.0.0.1:8080/#x"} {
		c := New(address, testUser, testPassword)
		c.hc.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsafe address reached transport")
			return nil, nil
		})
		if _, err := c.TracingLevels(context.Background()); err == nil || strings.Contains(err.Error(), testPassword) {
			t.Fatal("unsafe address accepted or leaked login")
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientRejectsRedirectDowngrade(t *testing.T) {
	c := New("https://mail.example.org:443", testUser, testPassword)
	calls := 0
	c.hc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"http://mail.example.org:443/jmap/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	if _, err := c.TracingLevels(context.Background()); err == nil {
		t.Fatal("downgrade accepted")
	}
	if calls != 1 {
		t.Fatal("login sent after downgrade redirect")
	}
}

func TestClientRejectsNullSettings(t *testing.T) {
	for _, list := range []any{nil, []any{nil}} {
		f := newFake(t)
		f.reply = func(method string, _ map[string]any) (string, any) { return method, map[string]any{"list": list} }
		if _, err := f.client().HTTPSettings(context.Background()); err == nil {
			t.Fatal("null settings accepted")
		}
	}
}

func TestClientRedactsReloadWarnings(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"created": map[string]any{"r": map[string]any{"warnings": map[string]any{testPassword: testPassword}}}}
	}
	warnings, err := f.client().ReloadSettings(context.Background())
	if err != nil || len(warnings) != 1 {
		t.Fatal("expected a reload warning")
	}
	if strings.Contains(warnings[0], testPassword) {
		t.Fatal("warning exposed password")
	}
}

func TestClientPreservesAPIPathPrefix(t *testing.T) {
	c := New("https://mail.example.org/admin/", testUser, testPassword)
	calls := 0
	c.hc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		want := "/admin/.well-known/jmap"
		body := `{"primaryAccounts":{"urn:stalwart:jmap":"admin"}}`
		if calls == 2 {
			want = "/admin/jmap/"
			body = `{"methodResponses":[["x:EventTracingLevel/get",{"list":[]},"a"]]}`
		}
		if r.URL.Path != want {
			t.Fatalf("request path = %q, want %q", r.URL.Path, want)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	if _, err := c.TracingLevels(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want session and settings", calls)
	}
}

// A successful preflight cannot authorize a replacement connection after a
// restart. Each dial must pass the peer check before any HTTP bytes leave.
func TestClientChecksEachLocalConnection(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "{}")
	}))
	defer srv.Close()
	var checks atomic.Int32
	refused := errors.New("untrusted replacement peer")
	c := NewWithPeerCheck(srv.URL, testUser, testPassword, func(context.Context, net.Conn) error {
		if checks.Add(1) == 1 {
			return nil
		}
		return refused
	})
	if _, err := c.do(context.Background(), http.MethodGet, "/", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.do(context.Background(), http.MethodGet, "/", nil); !errors.Is(err, refused) {
		t.Fatalf("replacement connection: %v", err)
	}
	if checks.Load() != 2 || requests.Load() != 1 {
		t.Fatalf("checks=%d requests=%d; refused peer must receive no HTTP request", checks.Load(), requests.Load())
	}
}

func TestClientPeerErrorRedactsLogin(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer srv.Close()
	c := NewWithPeerCheck(srv.URL, testUser, testPassword, func(context.Context, net.Conn) error {
		return errors.New("peer error: " + testPassword)
	})
	_, err := c.do(context.Background(), http.MethodGet, "/", nil)
	if err == nil || strings.Contains(err.Error(), testPassword) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatal("peer error was not safely reported")
	}
	if requests.Load() != 0 {
		t.Fatal("unverified peer received an HTTP request")
	}
}
