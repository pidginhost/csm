package daemon

import (
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

const checkTrustedProxyUnusable = "trusted_proxy_unusable"

// trustedProxyFindings reports the trusted_proxies entries cfg skips. A
// proxy CSM does not trust reads as the client of every request it
// forwards, so CSM can block it and every site behind it.
func trustedProxyFindings(cfg *config.Config) []alert.Finding {
	skipped := config.UnusableTrustedProxies(cfg)
	if len(skipped) == 0 {
		return nil
	}
	reasons := make([]string, len(skipped))
	for i, r := range skipped {
		reasons[i] = r.Message
	}
	return []alert.Finding{{
		Severity: alert.High,
		Check:    checkTrustedProxyUnusable,
		Message:  fmt.Sprintf("CSM skips %d trusted_proxies entries; a proxy they meant to list can be blocked as a client", len(skipped)),
		Details: strings.Join(reasons, "\n") +
			"\nFix or remove these entries and restart CSM. Until then, requests through those proxies count against the proxy's own address.",
		Timestamp: time.Now(),
	}}
}

// refreshTrustedProxyFinding keeps the finding in step with the running
// config: raised while it skips an entry, resolved once a config without
// one runs.
func (d *Daemon) refreshTrustedProxyFinding() {
	if d.store == nil {
		return
	}
	cfg := d.currentCfg()
	findings := trustedProxyFindings(cfg)
	// A dismissal covers one episode; a fixed and later repeated mistake
	// notifies again.
	d.store.RearmAbsentDedupFindings([]string{checkTrustedProxyUnusable}, findings)
	d.processScanFindings(cfg, findings, []string{checkTrustedProxyUnusable}, "config")
}
