package reporting

import (
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The gate admitted any Critical finding of a reportable class whose IP
// parsed: a Cloudflare edge or a private address seen in a brute-force
// finding was signed and shipped to the shared abuse set as an attacker.
// The daemon supplies the same firebreak it uses for central actions.
func TestGateConsiderHonoursProtectedFirebreak(t *testing.T) {
	g := Gate{
		Enabled:   map[Class]bool{ClassBruteforce: true},
		Protected: func(ip net.IP) bool { return ip.Equal(net.ParseIP("173.245.48.10")) },
	}
	f := alert.Finding{Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: "173.245.48.10", Timestamp: time.Now()}
	if _, ok := g.Consider(f); ok {
		t.Fatal("protected address was admitted to the abuse report")
	}
	f.SourceIP = "203.0.113.9"
	if _, ok := g.Consider(f); !ok {
		t.Fatal("unprotected attacker was not reported")
	}
}
