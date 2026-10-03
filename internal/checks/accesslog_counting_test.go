package checks

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestDomlogCountsClientFieldsWithoutChangingFraming(t *testing.T) {
	for name, fields := range map[string]struct {
		user, referer, ua, extra string
	}{
		"username timestamp":   {user: "[01/Jan/2000:00:00:00 +0000]", referer: "-", ua: "Mozilla"},
		"username brackets":    {user: "a[1]", referer: "-", ua: "Mozilla"},
		"quoted referer":       {user: "-", referer: `https://example.com/\"`, ua: "Mozilla"},
		"quoted UA":            {user: "-", referer: "-", ua: `agent \"quoted\"`},
		"UA address text":      {user: "-", referer: "-", ua: `agent \" \"127.0.0.1\"`},
		"referer address text": {user: "-", referer: `https://example.com/\" \"127.0.0.1\"`, ua: "Mozilla"},
		"later address field":  {user: "-", referer: "-", ua: "Mozilla", extra: ` "127.0.0.1"`},
		"quoted extension":     {user: "-", referer: "-", ua: "Mozilla", extra: ` "client \"text\""`},
	} {
		t.Run(name, func(t *testing.T) {
			line := fmt.Sprintf(`192.0.2.85 - %s [02/Oct/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 401 10 "%s" "%s" "203.0.113.7"%s`, fields.user, fields.referer, fields.ua, fields.extra)
			cfg := &config.Config{}
			cfg.WebServer.TrustedProxies = []string{"192.0.2.85"}
			for _, central := range []bool{true, false} {
				rec, ok := parseAccessLogRecord(line)
				if !ok {
					t.Fatal("valid log line was rejected")
				}
				rec.Central = central
				stats := newDomlogStatsAt(time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC))
				stats.scan(rec, cfg, nopBotClassifier{})
				if stats.wpLogin["203.0.113.7"] != 1 || stats.httpReqs["203.0.113.7"] != 1 {
					t.Fatalf("central=%v: got logins=%v requests=%v, want one of each for 203.0.113.7", central, stats.wpLogin, stats.httpReqs)
				}
			}
		})
	}
}

func TestDomlogExtensionAttributionUsesOnlyTheForwardedField(t *testing.T) {
	for _, tc := range []struct {
		extra, want string
	}{
		{` "203.0.113.7" "127.0.0.1"`, "203.0.113.7"},
		{` "-" "127.0.0.1"`, "192.0.2.85"},
		{` "client text" "127.0.0.1"`, "192.0.2.85"},
		{` "example.com:443" "203.0.113.7" "127.0.0.1"`, "203.0.113.7"},
		{` "127.0.0.1, invalid"`, "192.0.2.85"},
	} {
		t.Run(tc.extra, func(t *testing.T) {
			line := `192.0.2.85 - - [02/Oct/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 401 10 "-" "Mozilla"` + tc.extra
			rec, ok := parseAccessLogRecord(line)
			if !ok {
				t.Fatal("valid log line was rejected")
			}
			cfg := &config.Config{}
			cfg.WebServer.TrustedProxies = []string{"192.0.2.85"}
			stats := newDomlogStatsAt(time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC))
			stats.scan(rec, cfg, nopBotClassifier{})
			if stats.wpLogin[tc.want] != 1 || stats.httpReqs[tc.want] != 1 {
				t.Fatalf("got logins=%v requests=%v, want one of each for %s", stats.wpLogin, stats.httpReqs, tc.want)
			}
		})
	}
}
