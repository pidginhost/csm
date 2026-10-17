//go:build !linux

package firewall

// ResolvedInfraIPs is empty on platforms without the firewall resolver.
func (e *Engine) ResolvedInfraIPs(_ []string) []string { return nil }
