package geoip

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A transport error or a non-200 from the RDAP service used to be cached as
// a successful empty answer for 24 hours, so an operator investigating an
// address during a brief outage saw blank registry data for a day. Failures
// are retried after a short negative interval.
func TestLookupWithRDAPRetriesAfterFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"name":"EXAMPLE-NET","country":"RO","handle":"X","entities":[]}`))
	}))
	defer srv.Close()

	origURL, origNeg := rdapBaseURL, rdapNegativeTTL
	rdapBaseURL, rdapNegativeTTL = srv.URL+"/ip/", 0
	t.Cleanup(func() { rdapBaseURL, rdapNegativeTTL = origURL, origNeg })

	db := &DB{rdapTTL: make(map[string]rdapCacheEntry)}
	if first := db.LookupWithRDAP("203.0.113.9"); first.RDAPName != "" {
		t.Fatalf("failed lookup returned data: %+v", first)
	}
	second := db.LookupWithRDAP("203.0.113.9")
	if second.RDAPName != "EXAMPLE-NET" || second.RDAPCountry != "RO" {
		t.Fatalf("failure was cached as a final answer: %+v (calls=%d)", second, calls.Load())
	}
}

// A successful answer stays cached: a third lookup must not hit the service.
func TestLookupWithRDAPCachesSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"name":"EXAMPLE-NET","country":"RO"}`))
	}))
	defer srv.Close()
	orig := rdapBaseURL
	rdapBaseURL = srv.URL + "/ip/"
	t.Cleanup(func() { rdapBaseURL = orig })

	db := &DB{rdapTTL: make(map[string]rdapCacheEntry)}
	db.LookupWithRDAP("203.0.113.10")
	db.LookupWithRDAP("203.0.113.10")
	if calls.Load() != 1 {
		t.Fatalf("successful answer refetched: %d calls", calls.Load())
	}
}
