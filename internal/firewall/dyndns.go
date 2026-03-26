package firewall

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// DynDNSResolver periodically resolves hostnames and updates the firewall allowed set.
type DynDNSResolver struct {
	mu       sync.Mutex
	hosts    []string
	resolved map[string]string // hostname -> last resolved IP
	engine   interface {
		AllowIP(ip string, reason string) error
		RemoveAllowIP(ip string) error
	}
}

// NewDynDNSResolver creates a resolver for the given hostnames.
func NewDynDNSResolver(hosts []string, engine interface {
	AllowIP(ip string, reason string) error
	RemoveAllowIP(ip string) error
}) *DynDNSResolver {
	return &DynDNSResolver{
		hosts:    hosts,
		resolved: make(map[string]string),
		engine:   engine,
	}
}

// Run starts the periodic resolver. Blocks until stopCh is closed.
func (d *DynDNSResolver) Run(stopCh <-chan struct{}) {
	// Resolve immediately on start
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
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, host := range d.hosts {
		ips, err := net.LookupHost(host)
		if err != nil || len(ips) == 0 {
			fmt.Fprintf(os.Stderr, "dyndns: failed to resolve %s: %v\n", host, err)
			continue
		}

		newIP := ips[0] // use first resolved IP
		oldIP := d.resolved[host]

		if newIP == oldIP {
			continue // no change
		}

		// Remove old IP if it was previously resolved
		if oldIP != "" {
			_ = d.engine.RemoveAllowIP(oldIP)
			fmt.Fprintf(os.Stderr, "dyndns: %s changed %s -> %s\n", host, oldIP, newIP)
		} else {
			fmt.Fprintf(os.Stderr, "dyndns: %s resolved to %s\n", host, newIP)
		}

		// Add new IP
		reason := fmt.Sprintf("dyndns: %s", host)
		if err := d.engine.AllowIP(newIP, reason); err != nil {
			fmt.Fprintf(os.Stderr, "dyndns: error allowing %s (%s): %v\n", newIP, host, err)
			continue
		}

		d.resolved[host] = newIP
	}
}
