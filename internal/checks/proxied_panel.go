package checks

import (
	"net/url"
	"path"
	"strings"
)

// proxySubdomainPath prefixes the requests LiteSpeed passes to the panel.
const proxySubdomainPath = "/___proxy_subdomain_"

// IsProxiedPanelRequest reports a web-server log record of a request that a
// cPanel proxy subdomain passed to the panel: the proxy path LiteSpeed logs
// in its central log. A client chooses the logged path, so the path counts
// only in a recognized central log (central), where proxied requests land,
// and only when it still starts with the prefix after the server's own
// decoding and dot-segment removal: a request a site actually served is never
// skipped. No log field names the proxy vhost reliably: a trailing quoted
// field can be a client header, and Apache keeps proxied requests out of its
// traffic log. The panel's own log carries these requests, so one request
// never counts as two families of evidence.
func IsProxiedPanelRequest(uri string, central bool) bool {
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
