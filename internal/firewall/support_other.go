//go:build !linux

package firewall

// Supported reports whether this build includes the nftables engine.
func Supported() bool { return false }
