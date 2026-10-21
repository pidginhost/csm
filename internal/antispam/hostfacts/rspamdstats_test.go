package hostfacts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

const (
	testStatBody     = `{"scanned":1200,"learned":30,"ham_count":20,"spam_count":10,"connections":5,"actions":{"reject":41,"add header":9},"statfiles":[]}`
	testCountersBody = `[{"symbol":"R_SPF_FAIL","weight":1,"frequency":0.1,"hits":7,"time":0.001},{"symbol":"BAYES_SPAM","hits":12}]`
)

var testStats = antispam.RspamdStats{Scanned: 1200, Learned: 30, HamCount: 20, SpamCount: 10, Version: "3.9.1",
	Actions: map[string]int64{"reject": 41, "add header": 9}, TopRules: []antispam.RuleHits{{Symbol: "BAYES_SPAM", Hits: 12}, {Symbol: "R_SPF_FAIL", Hits: 7}}}

// statsServer answers /stat and /counters and records each request.
type statsServer struct {
	mu       sync.Mutex
	requests []*http.Request
	stat     string
	counters string
}

func (s *statsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Clone(context.Background()))
	s.mu.Unlock()
	switch r.URL.Path {
	case "/stat":
		_, _ = w.Write([]byte(s.stat))
	case "/counters":
		_, _ = w.Write([]byte(s.counters))
	default:
		http.NotFound(w, r)
	}
}

func (s *statsServer) seen() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func tcpStatsServer(t *testing.T, h http.Handler) antispam.StatsEndpoint {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return antispam.StatsEndpoint{Address: srv.Listener.Addr().String(), Version: "3.9.1"}
}

// The controller trusts the loopback peer; a password, auth or forwarded
// header would change what rspamd checks, so none is sent.
func assertPlainRequests(t *testing.T, requests []*http.Request) {
	t.Helper()
	var paths []string
	for _, r := range requests {
		paths = append(paths, r.URL.RequestURI())
		if r.Method != http.MethodGet || r.Host != "localhost" {
			t.Errorf("sent %s with Host %q", r.Method, r.Host)
		}
		for name := range r.Header {
			switch strings.ToLower(name) {
			case "password", "authorization", "proxy-authorization", "cookie", "x-forwarded-for", "x-real-ip", "forwarded":
				t.Errorf("sent %s", name)
			}
		}
	}
	if !reflect.DeepEqual(paths, []string{"/stat", "/counters"}) {
		t.Errorf("requested %q", paths)
	}
}

func TestReadRspamdStatsTCP(t *testing.T) {
	s := &statsServer{stat: testStatBody, counters: testCountersBody}
	got, err := ReadRspamdStats(context.Background(), tcpStatsServer(t, s))
	if err != nil {
		t.Fatal(err)
	}
	// /stat has no version, so the endpoint's stands in.
	if !reflect.DeepEqual(got, testStats) {
		t.Fatalf("got %+v, want %+v", got, testStats)
	}
	assertPlainRequests(t, s.seen())
}

func TestReadRspamdStatsUnix(t *testing.T) {
	s := &statsServer{stat: strings.Replace(testStatBody, `{`, `{"version":"3.10.0",`, 1), counters: testCountersBody}
	sock := serve(t, t.TempDir(), s.ServeHTTP)
	got, err := ReadRspamdStats(context.Background(), antispam.StatsEndpoint{Unix: true, Address: sock, RspamdUID: wantPeer(), Version: "3.9.1"})
	if err != nil {
		t.Fatal(err)
	}
	want := testStats
	want.Version = "3.10.0"
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	assertPlainRequests(t, s.seen())
	// A socket served by another user gets no request.
	s = &statsServer{stat: testStatBody, counters: testCountersBody}
	sock = serve(t, t.TempDir(), s.ServeHTTP)
	if _, err := ReadRspamdStats(context.Background(), antispam.StatsEndpoint{Unix: true, Address: sock, RspamdUID: wantPeer() + 1}); err == nil || len(s.seen()) != 0 {
		t.Fatalf("wrong peer: err %v, %d requests", err, len(s.seen()))
	}
}

func TestReadRspamdStatsBodyLimit(t *testing.T) {
	padded := func(open, pad, end string, size int) string {
		return open + strings.Repeat(pad, size-len(open)-len(end)) + end
	}
	for _, tc := range []struct {
		name, stat, counters string
		ok                   bool
	}{
		{"stat at limit", padded(`{"version":"`, "x", `"}`, 1<<20), `[]`, true},
		{"stat over limit", padded(`{"version":"`, "x", `"}`, 1<<20+1), `[]`, false},
		{"counters at limit", `{}`, padded(`[`, " ", `]`, 4<<20), true},
		{"counters over limit", `{}`, padded(`[{"symbol":"`, "x", `","hits":1}]`, 4<<20+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &statsServer{stat: tc.stat, counters: tc.counters}
			_, err := ReadRspamdStats(context.Background(), tcpStatsServer(t, s))
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok %t", err, tc.ok)
			}
			if err != nil && strings.Contains(err.Error(), "xxxx") {
				t.Fatalf("error repeats the reply: %v", err)
			}
		})
	}
}

func TestReadRspamdStatsRejectsReplies(t *testing.T) {
	unauthorized := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
	})
	var redirected bool
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			redirected = true
			_, _ = w.Write([]byte(testStatBody))
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	for name, h := range map[string]http.Handler{
		"unauthorized":     unauthorized,
		"redirect":         redirect,
		"bad stat":         &statsServer{stat: `{"scanned":"many"}`, counters: testCountersBody},
		"bad counters":     &statsServer{stat: testStatBody, counters: `{"symbol":"many"}`},
		"missing counters": &statsServer{stat: testStatBody},
	} {
		t.Run(name, func(t *testing.T) {
			ep := tcpStatsServer(t, h)
			got, err := ReadRspamdStats(context.Background(), ep)
			if err == nil {
				t.Fatalf("accepted as %+v", got)
			}
			for _, leak := range []string{"Unauthorized", "many", ep.Address} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("error repeats %q: %v", leak, err)
				}
			}
		})
	}
	if redirected {
		t.Fatal("followed a redirect")
	}
	if _, err := ReadRspamdStats(context.Background(), antispam.StatsEndpoint{Version: "3.9.1"}); err == nil {
		t.Fatal("read stats without an endpoint")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &statsServer{stat: testStatBody, counters: testCountersBody}
	if _, err := ReadRspamdStats(ctx, tcpStatsServer(t, s)); err == nil {
		t.Fatal("read stats with a canceled context")
	}
}
