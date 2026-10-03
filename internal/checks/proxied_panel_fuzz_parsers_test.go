package checks

import (
	"strings"
	"testing"
)

func FuzzProxiedPanelLogVhost(f *testing.F) {
	f.Add("-", "-", "Mozilla", "site.example")
	f.Add("a b", "proxy-subdomains-vhost.localhost", `agent "quoted"`, "site.example")
	f.Add("", `ref\"text`, "proxy-subdomains-vhost.localhost", "site.example")
	f.Add("x] [02/Oct/2026", "-", "Mozilla", "proxy-subdomains-vhost.localhost")
	f.Fuzz(func(t *testing.T, user, referrer, ua, vhost string) {
		escape := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`)
		loggedUser := escape.Replace(user)
		if loggedUser == "" {
			loggedUser = `""`
		}
		line := `192.0.2.85 - ` + loggedUser + ` [02/Oct/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "` + escape.Replace(referrer) + `" "` + escape.Replace(ua) + `" "` + escape.Replace(vhost) + `" "proxy-subdomains-vhost.localhost"`
		got := ProxiedPanelLogVhost(line)
		if vhost == "proxy-subdomains-vhost.localhost" {
			if got != vhost {
				t.Fatal("server vhost was lost")
			}
		} else if got != "" {
			t.Fatal("client field supplied the server vhost")
		}
	})
}
