package config

import (
	"fmt"

	"github.com/pidginhost/csm/internal/clientaddr"
	"github.com/pidginhost/csm/internal/netutil"
)

// TrustedProxies returns the one trusted proxy list every HTTP producer and
// the challenge server resolve clients against: web_server.trusted_proxies
// and challenge.trusted_proxies together. Load rejects unreadable entries,
// so a config that skipped it and holds one trusts no proxy at all.
func TrustedProxies(cfg *Config) clientaddr.Trusted {
	if cfg == nil {
		return clientaddr.Trusted{}
	}
	entries := make([]string, 0, len(cfg.WebServer.TrustedProxies)+len(cfg.Challenge.TrustedProxies))
	entries = append(entries, cfg.WebServer.TrustedProxies...)
	entries = append(entries, cfg.Challenge.TrustedProxies...)
	trusted, err := clientaddr.Parse(entries)
	if err != nil {
		return clientaddr.Trusted{}
	}
	return trusted
}

// WebServerLocalTrustError reports a web_server.trusted_proxies entry that
// covers an address of this host. CSM never trusts such an entry, since any
// local account can connect from that address and write X-Forwarded-For, so
// the requests a proxy there forwards count against nobody.
func WebServerLocalTrustError(entries []string) error {
	entry, covered, err := netutil.HostLocalProxyEntry(entries)
	if err != nil {
		return fmt.Errorf("web_server.trusted_proxies: cannot check the entries: %v", err)
	}
	if entry == "" {
		return nil
	}
	return fmt.Errorf("web_server.trusted_proxies entry %q covers %s, an address of this host: CSM never trusts it, so requests a proxy there forwards count against nobody. Have that proxy's web server log the client address, or remove the entry", entry, covered)
}

// validateTrustedProxies refuses an entry in either key that is not an IP
// address or CIDR range: dropping it silently would resolve clients behind
// that proxy to the proxy itself, or trust more than the operator listed.
func validateTrustedProxies(cfg *Config) error {
	for _, key := range []struct {
		name    string
		entries []string
	}{
		{"web_server.trusted_proxies", cfg.WebServer.TrustedProxies},
		{"challenge.trusted_proxies", cfg.Challenge.TrustedProxies},
	} {
		if _, err := clientaddr.Parse(key.entries); err != nil {
			return fmt.Errorf("%s%w", key.name, err)
		}
	}
	return nil
}
