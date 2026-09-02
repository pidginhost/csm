package geoip

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type rdapTransportFunc func(*http.Request) (*http.Response, error)

func (f rdapTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func rdapResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}
}

// A transport error or a non-200 from the RDAP service used to be cached as
// a successful empty answer for 24 hours, so an operator investigating an
// address during a brief outage saw blank registry data for a day. Failures
// are retried after a short negative interval.
func TestLookupWithRDAPRetriesAfterFailure(t *testing.T) {
	var calls atomic.Int32
	swapGeoipTransport(t, rdapTransportFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return rdapResponse(req, http.StatusTooManyRequests, ""), nil
		}
		return rdapResponse(req, http.StatusOK, "{\"name\":\"EXAMPLE-NET\",\"country\":\"RO\",\"handle\":\"X\",\"entities\":[]}"), nil
	}))

	origNeg := rdapNegativeTTL
	rdapNegativeTTL = 0
	t.Cleanup(func() { rdapNegativeTTL = origNeg })

	db := &DB{rdapTTL: make(map[string]rdapCacheEntry)}
	if first := db.LookupWithRDAP("203.0.113.9"); first.RDAPName != "" {
		t.Fatalf("failed lookup returned data: %+v", first)
	}
	second := db.LookupWithRDAP("203.0.113.9")
	if second.RDAPName != "EXAMPLE-NET" || second.RDAPCountry != "RO" {
		t.Fatalf("failure was cached as a final answer: %+v (calls=%d)", second, calls.Load())
	}
}

func TestFetchRDAPRejectsResponsePastLimit(t *testing.T) {
	body := "{\"name\":\"EXAMPLE-NET\",\"country\":\"RO\"}" +
		strings.Repeat(" ", int(rdapMaxResponseBytes))
	swapGeoipTransport(t, &rdapRoundTripper{status: http.StatusOK, body: []byte(body)})

	info, err := fetchRDAP("203.0.113.11")
	if !errors.Is(err, errRDAPLookupIncomplete) {
		t.Fatalf("oversized response error = %v, want errRDAPLookupIncomplete", err)
	}
	if info.RDAPName != "" {
		t.Fatalf("oversized partial response was accepted: %+v", info)
	}
}

// A successful answer stays cached: a third lookup must not hit the service.
func TestLookupWithRDAPCachesSuccess(t *testing.T) {
	var calls atomic.Int32
	swapGeoipTransport(t, rdapTransportFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return rdapResponse(req, http.StatusOK, "{\"name\":\"EXAMPLE-NET\",\"country\":\"RO\"}"), nil
	}))

	db := &DB{rdapTTL: make(map[string]rdapCacheEntry)}
	db.LookupWithRDAP("203.0.113.10")
	db.LookupWithRDAP("203.0.113.10")
	if calls.Load() != 1 {
		t.Fatalf("successful answer refetched: %d calls", calls.Load())
	}
}
