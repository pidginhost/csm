package firewall

import (
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

// DynDNSResolver periodically resolves hostnames and updates the firewall allowed set.
type DynDNSResolver struct {
	mu       sync.Mutex
	hosts    []string
	resolved map[string][]string // hostname -> all resolved IPs
	engine   interface {
		AllowIP(ip string, reason string) error
		RemoveAllowIPBySource(ip string, source string) error
	}
}

// NewDynDNSResolver creates a resolver for the given hostnames.
func NewDynDNSResolver(hosts []string, engine interface {
	AllowIP(ip string, reason string) error
	RemoveAllowIPBySource(ip string, source string) error
}) *DynDNSResolver {
	return &DynDNSResolver{
		hosts:    hosts,
		resolved: make(map[string][]string),
		engine:   engine,
	}
}

// Run starts the periodic resolver. Blocks until stopCh is closed.
func (d *DynDNSResolver) Run(stopCh <-chan struct{}) {
	d.resolveAll()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			d.resolveAll()
		}
	}
}

func (d *DynDNSResolver) resolveAll() {
	for _, host := range d.hosts {
		d.resolveHost(host)
	}
}

func (d *DynDNSResolver) resolveHost(host string) {
	newIPs, err := net.LookupHost(host)
	if err != nil || len(newIPs) == 0 {
		fmt.Fprintf(os.Stderr, "dyndns: failed to resolve %s: %v\n", host, err)
		return
	}
	sort.Strings(newIPs)

	d.mu.Lock()
	oldIPs := d.resolved[host]
	d.mu.Unlock()

	oldSet := make(map[string]bool)
	for _, ip := range oldIPs {
		oldSet[ip] = true
	}
	newSet := make(map[string]bool)
	for _, ip := range newIPs {
		newSet[ip] = true
	}

	// Remove IPs no longer in DNS (only remove the dyndns source entry)
	for _, ip := range oldIPs {
		if !newSet[ip] {
			_ = d.engine.RemoveAllowIPBySource(ip, SourceDynDNS)
			fmt.Fprintf(os.Stderr, "dyndns: %s removed %s (no longer resolves)\n", host, ip)
		}
	}

	// Add new IPs
	reason := fmt.Sprintf("dyndns: %s", host)
	var successIPs []string
	for _, ip := range newIPs {
		if oldSet[ip] {
			successIPs = append(successIPs, ip) // already allowed
			continue
		}
		if err := d.engine.AllowIP(ip, reason); err != nil {
			fmt.Fprintf(os.Stderr, "dyndns: error allowing %s (%s): %v\n", ip, host, err)
			continue
		}
		successIPs = append(successIPs, ip)
		fmt.Fprintf(os.Stderr, "dyndns: %s resolved to %s (added)\n", host, ip)
	}

	// Only update resolved map with successfully allowed IPs
	d.mu.Lock()
	d.resolved[host] = successIPs
	d.mu.Unlock()
}
