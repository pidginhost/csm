//go:build linux

package firewall

import "slices"

// ResolvedInfraIPs copies the last successful DNS answers for the requested
// infrastructure hosts. Callers choose which configured hosts they protect.
func (e *Engine) ResolvedInfraIPs(hosts []string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ips []string
	for _, host := range hosts {
		for ip := range e.infraResolved[host] {
			ips = append(ips, ip)
		}
	}
	slices.Sort(ips)
	return slices.Compact(ips)
}
