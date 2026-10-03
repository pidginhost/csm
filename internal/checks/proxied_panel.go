package checks

import (
	"net/url"
	"path"
	"strings"
)

// proxySubdomainVhost is the ServerName cPanel gives the virtual host that
// passes the cpanel., webmail. and whm. proxy subdomains to the panel.
const proxySubdomainVhost = "proxy-subdomains-vhost.localhost"

// proxySubdomainPath prefixes the requests LiteSpeed passes to the panel.
const proxySubdomainPath = "/___proxy_subdomain_"

// IsProxiedPanelRequest reports a web-server log record of a request that a
// cPanel proxy subdomain passed to the panel: the proxy vhost in cPanel's
// trailing vhost field, which the server writes, or the proxy path LiteSpeed
// logs in its central log. A client chooses the logged path, so the path
// counts only in the central log (central), where proxied requests land, and
// only when it still starts with the prefix after the server's own decoding
// and dot-segment removal: a request a site actually served is never
// skipped. (A log format that starts with "%v:port" never yields a client
// address, so those lines are skipped already.) The panel's own log carries
// these requests, so one request never counts as two families of evidence.
func IsProxiedPanelRequest(uri, vhost string, central bool) bool {
	if vhost == proxySubdomainVhost {
		return true
	}
	if !central || !strings.HasPrefix(uri, proxySubdomainPath) {
		return false
	}
	raw, _, _ := strings.Cut(uri, "?")
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return false
	}
	return strings.HasPrefix(path.Clean(decoded), proxySubdomainPath)
}

// ProxiedPanelLogVhost reads optional Combined Log Format extensions only.
// Request, referrer and User-Agent values cannot supply a server vhost.
func ProxiedPanelLogVhost(line string) string {
	for field := 0; ; field++ {
		start := strings.IndexByte(line, '"')
		if start < 0 {
			return ""
		}
		line = line[start+1:]
		end := 0
		for end < len(line) && line[end] != '"' {
			if line[end] == '\\' {
				end++
			}
			end++
		}
		if end >= len(line) {
			return ""
		}
		if field >= 3 && line[:end] == proxySubdomainVhost {
			return proxySubdomainVhost
		}
		line = line[end+1:]
	}
}
