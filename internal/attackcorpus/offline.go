package attackcorpus

import (
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
)

var errOffline = errors.New("attack corpus runs offline")

type offlineTransport struct{ attempts *atomic.Int64 }

func (o offlineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	o.attempts.Add(1)
	if req.Body != nil {
		_ = req.Body.Close()
	}
	return nil, errOffline
}

// Offline fails and counts every request through http.DefaultTransport, which
// every client without a transport of its own uses, until the test ends.
func Offline(t testing.TB) *atomic.Int64 {
	attempts := new(atomic.Int64)
	prev := http.DefaultTransport
	http.DefaultTransport = offlineTransport{attempts}
	t.Cleanup(func() { http.DefaultTransport = prev })
	return attempts
}
