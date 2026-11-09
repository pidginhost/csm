package daemon

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/config"
)

// Config publication replaces immutable snapshots. Retain only the last one
// so whitelist lookup stays constant-time without retaining reload history.
type reputationWhitelist struct {
	mu       sync.Mutex
	cfg      *config.Config
	ips      map[netip.Addr]bool
	literals map[string]bool
}

func (w *reputationWhitelist) contains(cfg *config.Config, addr string) bool {
	if cfg == nil || addr == "" {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cfg != cfg {
		w.ips = make(map[netip.Addr]bool, len(cfg.Reputation.Whitelist))
		w.literals = make(map[string]bool)
		for _, entry := range cfg.Reputation.Whitelist {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if ip, err := netip.ParseAddr(entry); err == nil && ip.Zone() == "" {
				w.ips[ip.Unmap()] = true
			} else {
				// Subnet-spray findings can name a literal CIDR. Preserve
				// exact matches without granting a host-wide subnet exemption.
				w.literals[entry] = true
			}
		}
		w.cfg = cfg
	}
	if ip, err := netip.ParseAddr(addr); err == nil && ip.Zone() == "" {
		return w.ips[ip.Unmap()]
	}
	return w.literals[addr]
}
