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
	// infraHosts is the subset of hosts that also feed the engine's
	// infra-IP guard. When a host appears here, every successful
	// resolution additionally calls engine.UpdateInfraResolved so the
	// hostname stays blockable-refusable even when the IP behind it
	// rotates. Hosts not in this map only feed the allowed-IPs set.
	infraHosts map[string]struct{}
	engine     interface {
		AllowIP(ip string, reason string) error
		RemoveAllowIPBySource(ip string, source string) error
	}
	// infraEngine receives infra-mode updates. Optional - separate
	// interface so the AllowIP/RemoveAllowIPBySource consumers don't
	// have to grow when an operator does not declare any infra hosts.
	infraEngine interface {
		UpdateInfraResolved(host string, ips []string)
		DropInfraResolved(host string)
	}

	// lookupFn is the context-bound DNS lookup function. Defaults to
	// net.DefaultResolver.LookupHost so callers can bound a stuck
	// resolver by cancelling the parent context. Tests may replace this
	// with a stub.
	lookupFn func(ctx context.Context, host string) ([]string, error)

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
	r.lookupFn = net.DefaultResolver.LookupHost
	return r
}

// AddHost appends a hostname to the resolver's host list.
// It is safe to call concurrently. Used in tests to add hosts after construction.
func (d *DynDNSResolver) AddHost(host string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hosts = append(d.hosts, host)
}

// RegisterInfraHost marks host as an infra hostname. Every subsequent
// successful resolution will, in addition to AllowIP, call
// engine.UpdateInfraResolved so the resolved IPs feed the infra-block
// guard. Idempotent. Wire an infra engine via SetInfraEngine before
// the resolver's first tick to make this effective.
func (d *DynDNSResolver) RegisterInfraHost(host string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.infraHosts == nil {
		d.infraHosts = make(map[string]struct{})
	}
	d.infraHosts[host] = struct{}{}
}

// SetInfraEngine wires the engine that receives infra-mode resolution
// updates. Setting it to nil disables infra routing without affecting
// the regular allowed-IPs path.
func (d *DynDNSResolver) SetInfraEngine(eng interface {
	UpdateInfraResolved(host string, ips []string)
	DropInfraResolved(host string)
}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.infraEngine = eng
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
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	go func() {
		<-stopCh
		cancelParent()
	}()

	d.runTick(parent)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			d.runTick(parent)
		}
	}
}

// runTick is the periodic Run helper. It bounds a single resolution
// cycle so a stuck DNS server cannot hold the ticker beyond its budget
// and stack late ticks. The per-tick budget is purposely larger than
// the default 30-second per-resolver timeout but smaller than the
// 5-minute ticker period.
func (d *DynDNSResolver) runTick(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, dyndnsTickBudget)
	defer cancel()
	d.tickOnce(ctx)
}

const dyndnsTickBudget = 60 * time.Second

// tickOnce performs one resolution cycle over all registered hosts.
// The periodic Run loop calls this; tests can call it directly. The
// context bounds the whole cycle so a single stuck DNS server cannot
// hold the tick for the resolver's implicit timeout (~30s) and pile
// late ticks on top of the configured 5-minute period.
func (d *DynDNSResolver) tickOnce(ctx context.Context) {
	d.mu.Lock()
	hosts := make([]string, len(d.hosts))
	copy(hosts, d.hosts)
	d.mu.Unlock()

	for _, host := range hosts {
		if ctx.Err() != nil {
			return
		}
		d.resolveHost(ctx, host)
	}
}

// resolveAll is retained for backward compatibility with existing tests.
func (d *DynDNSResolver) resolveAll() {
	d.tickOnce(context.Background())
}

func (d *DynDNSResolver) resolveHost(ctx context.Context, host string) {
	newIPs, err := d.lookupFn(ctx, host)
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
	var infraIPs []string
	for _, ip := range newIPs {
		newSet[ip] = true
		if parsed := net.ParseIP(ip); parsed != nil {
			infraIPs = append(infraIPs, parsed.String())
		}
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
	isInfra := false
	if _, ok := d.infraHosts[host]; ok {
		isInfra = true
	}
	infraEngine := d.infraEngine
	d.mu.Unlock()

	// Infra mode feeds the block guard from DNS itself, not from the
	// allow-list mutation result. A transient nftables write failure
	// should not make a resolved management hostname blockable.
	if isInfra && infraEngine != nil {
		infraEngine.UpdateInfraResolved(host, infraIPs)
	}

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
