package checks

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"time"
)

const localHTTPTestURL = "http://csm.test"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newHandlerHTTPClient(handler http.Handler) *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: newHandlerHTTPTransport(handler),
	}
}

func newHandlerHTTPTransport(handler http.Handler) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		resp := rec.Result()
		resp.Request = r
		return resp, nil
	})
}

func withDefaultHTTPTransport(t interface {
	Helper()
	Cleanup(func())
}, handler http.Handler) {
	t.Helper()
	old := http.DefaultTransport
	http.DefaultTransport = newHandlerHTTPTransport(handler)
	t.Cleanup(func() { http.DefaultTransport = old })
}

func newFailingHTTPClient(message string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New(message)
		}),
	}
}
