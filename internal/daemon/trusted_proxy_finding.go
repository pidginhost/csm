package daemon

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

const checkTrustedProxyUnusable = "trusted_proxy_unusable"

// trustedProxyFindings reports skipped entries that can leave proxies
// counted as clients or forwarded requests without attribution.
func trustedProxyFindings(cfg *config.Config) []alert.Finding {
	skipped := config.UnusableTrustedProxies(cfg)
	if len(skipped) == 0 {
		return nil
	}
	reasons := make([]string, len(skipped))
	for i, r := range skipped {
		reasons[i] = r.Message
	}
	details := strings.Join(reasons, "\n")
	// Explicit identities let recovery re-arm dismissals. Include the errors
	// so acknowledging one configuration does not hide a different mistake.
	identity := sha256.Sum256([]byte(details))
	return []alert.Finding{{
		Severity: alert.High,
		Check:    checkTrustedProxyUnusable,
		DedupKey: fmt.Sprintf("%x", identity),
		Message:  fmt.Sprintf("CSM skips %d trusted_proxies entries; a proxy they meant to list can be blocked as a client", len(skipped)),
		Details: details +
			"\nFix or remove these entries and restart CSM. Requests may count against a proxy or against nobody.",
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
