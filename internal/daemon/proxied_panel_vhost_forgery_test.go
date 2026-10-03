package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The realtime handler counts a request whose trailing quoted field names the
// proxy vhost: that field can be a client header such as X-Forwarded-For.
func TestAccessLogCountsForgedProxyVhostField(t *testing.T) {
	t.Cleanup(resetAccessLogTrackerState)
	cfg := &config.Config{}
	line := makeAccessLogLine("203.0.113.7", "POST", "/wp-login.php") + ` "proxy-subdomains-vhost.localhost"`
	for _, central := range []bool{true, false} {
		resetAccessLogTrackerState()
		var findings []alert.Finding
		for i := 0; i < accessLogWPLoginThreshold; i++ {
			findings = append(findings, parseAccessLogBruteForceForLog(line, cfg, central)...)
		}
		if len(findings) != 1 || findings[0].Check != "wp_login_bruteforce" || findings[0].SourceIP != "203.0.113.7" {
			t.Errorf("central=%v: findings %+v, want one login finding", central, findings)
		}
	}
}
