package firewall

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

// hostHealth tracks per-host resolution state for the re-resolve guard.
type hostHealth struct {
	lastSuccess    time.Time
	firstFailure   time.Time
	findingEmitted bool
}

// DynDNSResolver periodically resolves hostnames and updates the firewall allowed set.
type DynDNSResolver struct {
	mu       sync.Mutex
	hosts    []string
	resolved map[string][]string // hostname -> all resolved IPs
	engine   interface {
		AllowIP(ip string, reason string) error
		RemoveAllowIPBySource(ip string, source string) error
	}

	// lookupFn is the DNS lookup function; defaults to net.LookupHost.
	// Tests may replace this with a stub.
	lookupFn func(host string) ([]string, error)

	// Guard fields for the DNS re-resolve guard (Task 3).
	muGuard      sync.RWMutex
	hostHealth   map[string]*hostHealth
	gracePeriod  time.Duration
	unresolvable map[string]struct{}
	findingSink  func(name string)
}

// NewDynDNSResolver creates a resolver for the given hostnames.
func NewDynDNSResolver(hosts []string, engine interface {
	AllowIP(ip string, reason string) error
	RemoveAllowIPBySource(ip string, source string) error
}) *DynDNSResolver {
	r := &DynDNSResolver{
		hosts:        hosts,
		resolved:     make(map[string][]string),
		engine:       engine,
		hostHealth:   make(map[string]*hostHealth),
		unresolvable: make(map[string]struct{}),
		gracePeriod:  10 * time.Minute,
	}
	r.lookupFn = net.LookupHost
	return r
}

// AddHost appends a hostname to the resolver's host list.
// It is safe to call concurrently. Used in tests to add hosts after construction.
func (d *DynDNSResolver) AddHost(host string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hosts = append(d.hosts, host)
}

// markLastSuccess seeds the lastSuccess timestamp for a host to now.
// Used in tests to simulate a prior successful resolution without a real
// DNS lookup.
func (d *DynDNSResolver) markLastSuccess(host string) {
	d.muGuard.Lock()
	defer d.muGuard.Unlock()
	hh := d.hostHealth[host]
	if hh == nil {
		hh = &hostHealth{}
		d.hostHealth[host] = hh
	}
	hh.lastSuccess = time.Now()
}

// SetFindingSink installs the callback invoked when a host has been
// unresolvable for longer than gracePeriod. Called from the daemon at
// startup, after the alert pipeline is wired.
func (d *DynDNSResolver) SetFindingSink(sink func(host string)) {
	d.muGuard.Lock()
	defer d.muGuard.Unlock()
	d.findingSink = sink
}

// UnresolvableHosts lists infra_ips hostnames currently failing to resolve
// beyond the grace period.
func (d *DynDNSResolver) UnresolvableHosts() []string {
	d.muGuard.RLock()
	defer d.muGuard.RUnlock()
	out := make([]string, 0, len(d.unresolvable))
	for h := range d.unresolvable {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Run starts the periodic resolver. Blocks until stopCh is closed.
func (d *DynDNSResolver) Run(stopCh <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-stopCh
		cancel()
	}()

	d.tickOnce(ctx)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			d.tickOnce(ctx)
		}
	}
}

// tickOnce performs one resolution cycle over all registered hosts.
// The periodic Run loop calls this; tests can call it directly.
func (d *DynDNSResolver) tickOnce(_ context.Context) {
	d.mu.Lock()
	hosts := make([]string, len(d.hosts))
	copy(hosts, d.hosts)
	d.mu.Unlock()

	for _, host := range hosts {
		d.resolveHost(host)
	}
}

// resolveAll is retained for backward compatibility with existing tests.
func (d *DynDNSResolver) resolveAll() {
	d.tickOnce(context.Background())
}

func (d *DynDNSResolver) resolveHost(host string) {
	newIPs, err := d.lookupFn(host)
	if err != nil || len(newIPs) == 0 {
		fmt.Fprintf(os.Stderr, "dyndns: failed to resolve %s: %v\n", host, err)
		d.updateGuardFailure(host)
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

	// Successful resolution: clear any guard state.
	d.updateGuardSuccess(host)
}

// updateGuardSuccess marks a host as successfully resolved in the guard state.
func (d *DynDNSResolver) updateGuardSuccess(host string) {
	d.muGuard.Lock()
	hh := d.hostHealth[host]
	if hh == nil {
		hh = &hostHealth{}
		d.hostHealth[host] = hh
	}
	hh.lastSuccess = time.Now()
	hh.firstFailure = time.Time{}
	if _, was := d.unresolvable[host]; was {
		delete(d.unresolvable, host)
		fmt.Fprintf(os.Stderr, "dyndns: %s recovered (resolution succeeded)\n", host)
	}
	hh.findingEmitted = false
	d.muGuard.Unlock()
}

// updateGuardFailure updates guard state after a failed resolution for a host.
// If the host has been unresolvable beyond gracePeriod and no finding has been
// emitted yet, it marks the host unresolvable and invokes the finding sink.
func (d *DynDNSResolver) updateGuardFailure(host string) {
	d.muGuard.Lock()
	hh := d.hostHealth[host]
	if hh == nil {
		hh = &hostHealth{}
		d.hostHealth[host] = hh
	}
	now := time.Now()
	if hh.firstFailure.IsZero() {
		hh.firstFailure = now
	}
	since := hh.lastSuccess
	if since.IsZero() {
		since = hh.firstFailure
	}

	var sinkToCall func(string)
	if now.Sub(since) > d.gracePeriod &&
		!hh.findingEmitted {
		d.unresolvable[host] = struct{}{}
		hh.findingEmitted = true
		sinkToCall = d.findingSink
	}
	d.muGuard.Unlock()

	// Invoke sink outside the lock to prevent deadlock if sink calls back in.
	if sinkToCall != nil {
		sinkToCall(host)
	}
}
