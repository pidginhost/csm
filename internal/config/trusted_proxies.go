package config

import (
	"errors"
	"fmt"

	"github.com/pidginhost/csm/internal/clientaddr"
	"github.com/pidginhost/csm/internal/netutil"
)

// TrustedProxies returns the one trusted proxy list every HTTP producer and
// the challenge server resolve clients against: web_server.trusted_proxies
// and challenge.trusted_proxies together. An unusable entry is skipped on
// its own, as earlier releases skipped it, and Validate warns about it.
func TrustedProxies(cfg *Config) clientaddr.Trusted {
	if cfg == nil {
		return clientaddr.Trusted{}
	}
	entries := make([]string, 0, len(cfg.WebServer.TrustedProxies)+len(cfg.Challenge.TrustedProxies))
	entries = append(entries, cfg.WebServer.TrustedProxies...)
	entries = append(entries, cfg.Challenge.TrustedProxies...)
	trusted, _ := clientaddr.ParseUsable(entries)
	return trusted
}

// WebServerLocalTrustError reports a web_server.trusted_proxies entry that
// covers an address of this host. CSM never trusts such an entry, since any
// local account can connect from that address and write X-Forwarded-For, so
// the requests a proxy there forwards count against nobody.
func WebServerLocalTrustError(entries []string) error {
	entry, covered, err := netutil.HostLocalProxyEntry(usableTrustedProxyEntries(entries))
	if err != nil {
		return fmt.Errorf("web_server.trusted_proxies: cannot check the entries: %v", err)
	}
	if entry == "" {
		return nil
	}
	return fmt.Errorf("web_server.trusted_proxies entry %q covers %s, an address of this host: CSM never trusts it, so requests a proxy there forwards count against nobody. Have that proxy's web server log the client address, or remove the entry", entry, covered)
}

// unusableTrustedProxyResults reports each entry of key that is empty, not
// an IP address or CIDR range, or a catch-all. Validate reports them as
// warnings, since an error stops a daemon that ran with them; Settings save
// refuses them as errors.
func unusableTrustedProxyResults(level, key string, entries []string) []ValidationResult {
	_, errs := clientaddr.ParseUsable(entries)
	results := make([]ValidationResult, 0, len(errs))
	for _, err := range errs {
		msg := fmt.Sprintf("%s%v: CSM skips this entry", key, err)
		if errors.Is(err, clientaddr.ErrCatchAllEntry) {
			msg = fmt.Sprintf("%s%v: CSM never trusts it, and forwarded requests from the peers it covers count against nobody. List your proxies' addresses instead", key, err)
		}
		results = append(results, ValidationResult{level, key, msg})
	}
	return results
}

// usableTrustedProxyEntries drops the entries CSM skips. A skipped catch-all
// trusts no address, so it is reported as unusable, not as an address of
// this host.
func usableTrustedProxyEntries(entries []string) []string {
	usable := make([]string, 0, len(entries))
	for _, entry := range entries {
		if _, err := clientaddr.Parse([]string{entry}); err == nil {
			usable = append(usable, entry)
		}
	}
	return usable
}
