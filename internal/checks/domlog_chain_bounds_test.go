package checks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Short address tokens fit many more hops than the resolver's bound into
// the log's kept end. Only the hops read before the client count, so the
// client the proxy appended still resolves however many sit left of it.
func TestDomlogParserBoundsShortForwardedChains(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"192.0.2.0/24"}
	for _, hops := range []int{31, 32, 33, 64} {
		t.Run(fmt.Sprint(hops), func(t *testing.T) {
			const end = "203.0.113.9,192.0.2.11"
			xff := strings.Repeat("::,", hops-2) + end
			line := domlogTestLine("192.0.2.10", 0, "POST", "/wp-login.php", 200, "Mozilla/5.0") + ` "` + xff + `"`
			rec, ok := parseAccessLogRecord(line)
			if !ok || !strings.HasSuffix(rec.XFF, end) {
				t.Fatalf("parsed=%v XFF=%q, want the proxy-appended end kept", ok, rec.XFF)
			}
			ip, chained, err := resolvedClient(rec, cfg)
			if err != nil || ip != "203.0.113.9" || !chained {
				t.Fatalf("client=%q chained=%v error=%v, want forwarded 203.0.113.9", ip, chained, err)
			}
		})
	}
}
