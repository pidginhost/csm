package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// A trailing quoted field can be a client header: nginx's main format and the
// trusted_proxies format log X-Forwarded-For there. A proxy vhost name in it
// never marks a request as panel traffic, in any log.
func TestForgedProxyVhostFieldCountsAsWebTraffic(t *testing.T) {
	const line = `203.0.113.7 - - [02/Oct/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10 "-" "Mozilla" "proxy-subdomains-vhost.localhost"`
	for _, central := range []bool{true, false} {
		stats := newDomlogStatsAt(time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC))
		rec, ok := parseAccessLogRecord(line)
		if !ok {
			t.Fatal("unparsable fixture")
		}
		rec.Central = central
		stats.scan(rec, &config.Config{}, nopBotClassifier{})
		if stats.wpLogin["203.0.113.7"] != 1 || stats.httpReqs["203.0.113.7"] != 1 {
			t.Errorf("central=%v: a client-chosen vhost field hid the request: %d logins, %d requests",
				central, stats.wpLogin["203.0.113.7"], stats.httpReqs["203.0.113.7"])
		}
	}
}
