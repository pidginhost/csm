package checks

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// A log file any local user can write may name an address, but it never
// displaces a sighting from a log the service itself wrote: one forged line
// would make the address's reputation finding alert-only.
func TestWritableSightingNeverDisplacesTrustedOne(t *testing.T) {
	cfg := &config.Config{}
	for _, trusted := range []string{"HTTP request", "cPanel/WHM access", "SMTP auth failure"} {
		for _, writable := range []string{"SSH login", reputationViaMailLogin} {
			for _, order := range [][2]string{{trusted, writable}, {writable, trusted}} {
				ips := map[string]string{}
				addIfNotInfra(ips, "203.0.113.90", order[0], cfg)
				addIfNotInfra(ips, "203.0.113.90", order[1], cfg)
				if got := ips["203.0.113.90"]; got != trusted {
					t.Errorf("%q then %q: surface %q, want %q", order[0], order[1], got, trusted)
				}
			}
		}
	}
}

// An address only a writable log names gets no AbuseIPDB lookup: forged
// nominations would otherwise spend the lookups trusted sightings need.
func TestWritableOnlySightingGetsNoLookup(t *testing.T) {
	cfg, _ := reputationQueueFixture(t, 1)
	withMockOS(t, mockOSWithAuthLog(t, "Sep 10 10:00:00 host sshd[1]: Accepted publickey for alice from 198.51.100.1 port 22 ssh2\n"))
	var queries atomic.Int32
	withReputationQueueTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		queries.Add(1)
		return reputationQueueResponse(r, 200, io.NopCloser(strings.NewReader(`{"data":{"abuseConfidenceScore":80}}`))), nil
	}))
	CheckIPReputation(context.Background(), cfg, nil)
	if n := queries.Load(); n != 0 {
		t.Fatalf("%d AbuseIPDB lookups for an address only a writable log named", n)
	}
}
