package checks

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func FuzzDomlogClientFieldsCannotHideRequests(f *testing.F) {
	f.Add("a b", "-", `agent "quoted"`, "127.0.0.1")
	f.Add("[01/Jan/2000:00:00:00 +0000]", `https://example.com/"`, "Mozilla", `"`)
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, user, referer, ua, extension string) {
		loggedUser := escapeAccessLogField(user)
		if loggedUser == "" {
			loggedUser = `""`
		}
		line := fmt.Sprintf(`192.0.2.85 - %s [02/Oct/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 401 10 "%s" "%s" "203.0.113.7" "%s"`, loggedUser, escapeAccessLogField(referer), escapeAccessLogField(ua), escapeAccessLogField(extension))
		rec, ok := parseAccessLogRecord(line)
		if !ok {
			t.Fatal("valid log line was rejected")
		}
		cfg := &config.Config{}
		cfg.WebServer.TrustedProxies = []string{"192.0.2.85"}
		for _, central := range []bool{true, false} {
			rec.Central = central
			stats := newDomlogStatsAt(time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC))
			stats.scan(rec, cfg, nopBotClassifier{})
			if stats.wpLogin["203.0.113.7"] != 1 || stats.httpReqs["203.0.113.7"] != 1 {
				t.Fatalf("central=%v: client fields changed request counting", central)
			}
		}
	})
}

func escapeAccessLogField(value string) string {
	var escaped strings.Builder
	for i := range len(value) {
		switch c := value[i]; {
		case c == '"' || c == '\\':
			escaped.WriteByte('\\')
			escaped.WriteByte(c)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&escaped, `\x%02x`, c)
		default:
			escaped.WriteByte(c)
		}
	}
	return escaped.String()
}
