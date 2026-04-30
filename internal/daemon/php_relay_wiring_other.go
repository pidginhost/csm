//go:build !linux

package daemon

// startPHPRelayLinux is a no-op on non-Linux platforms. The full wiring
// requires inotify and other linux-only primitives; on darwin (and any
// other non-linux GOOS) we skip it entirely so cross-compilation and
// local development stay clean.
func startPHPRelayLinux(_ *Daemon) {}
