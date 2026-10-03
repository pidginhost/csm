package daemon

import (
	"fmt"
	"strings"
	"testing"
)

func FuzzAccessLogRemoteUserCannotChangeRequest(f *testing.F) {
	f.Add("a b")
	f.Add("[01/Jan/2000:00:00:00 +0000]")
	f.Add(`name] "POST /___proxy_subdomain_cpanel/ HTTP/1.1"`)
	f.Add("")
	f.Fuzz(func(t *testing.T, user string) {
		var escaped strings.Builder
		for i := range len(user) {
			switch c := user[i]; {
			case c == '"' || c == '\\':
				escaped.WriteByte('\\')
				escaped.WriteByte(c)
			case c < 0x20 || c >= 0x7f:
				fmt.Fprintf(&escaped, `\x%02x`, c)
			default:
				escaped.WriteByte(c)
			}
		}
		loggedUser := escaped.String()
		if loggedUser == "" {
			loggedUser = `""`
		}
		line := `203.0.113.7 - ` + loggedUser + ` [02/Oct/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 401 10 "-" "Mozilla"`
		ip, method, path, ok := accessLogIPMethodPath(line)
		if !ok || ip != "203.0.113.7" || method != "POST" || path != "/wp-login.php" {
			t.Fatalf("client username changed request: ip=%q method=%q path=%q ok=%v", ip, method, path, ok)
		}
	})
}
