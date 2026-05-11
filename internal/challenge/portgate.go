package challenge

import (
	"net"
	"strings"
	"time"
)

// PortGate locks the challenge listener TCP port to specific source IPs
// via the host firewall. An IP is allowed only while it is on the
// challenge IPList (plus operator infra IPs and loopback). Everything
// else gets dropped at the kernel before the listener sees the SYN, so
// the listener is invisible to port scanners and stays reachable only
// for the visitors the daemon has actually redirected.
//
// Implementations are pluggable so the netlink-backed Linux variant
// can be swapped for a stub on platforms that do not have nftables.
// All methods are safe to call on a nil PortGate (no-op), so callers
// do not need to nil-check at every IPList Add/Remove site.
type PortGate interface {
	// Allow opens the gate for the source IP for at most ttl. The
	// underlying firewall enforces the TTL via the set's own timeout
	// so the entry expires even if Revoke is never called (daemon
	// crash, missed expiry). Returns nil on success or when the IP
	// cannot be parsed (best-effort; the IPList accepts only validated
	// IPs upstream, so a parse miss here is a bug to log, not block).
	Allow(ip string, ttl time.Duration) error
	// Revoke closes the gate for ip immediately. Safe to call for IPs
	// that were never on the gate (no-op).
	Revoke(ip string) error
	// Close tears down the gate's nftables footprint (chain, sets,
	// table). The port reverts to whatever the rest of the host
	// firewall would do with it.
	Close() error
}

// PortGateConfig wraps the inputs the gate needs to install rules.
type PortGateConfig struct {
	ListenAddr string
	ListenPort int
	InfraCIDRs []string
}

// NewPortGate returns the platform-appropriate gate. On Linux it
// installs a dedicated `csm_chal` inet table; on non-Linux it returns
// nil so callers naturally no-op via the nil PortGate handling on the
// IPList side.
//
// Returns nil + nil when the listen address is loopback because no
// gate is needed (loopback traffic cannot originate from off-host).
// Caller treats nil as "gate not active" and proceeds without it.
func NewPortGate(cfg PortGateConfig) (PortGate, error) {
	if isLoopbackListenAddr(cfg.ListenAddr) {
		return nil, nil
	}
	return newPortGate(cfg)
}

// portGateFamily picks which address families the gate should bind to
// based on the listen address. 0.0.0.0 / blank -> v4 only; :: -> dual
// stack; a specific literal IP gates only that family.
type portGateFamily struct {
	v4 bool
	v6 bool
}

func familyForListenAddr(addr string) portGateFamily {
	addr = strings.Trim(strings.TrimSpace(addr), "[]")
	switch addr {
	case "", "0.0.0.0":
		return portGateFamily{v4: true}
	case "::":
		return portGateFamily{v4: true, v6: true}
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return portGateFamily{v4: true}
	}
	if ip.To4() != nil {
		return portGateFamily{v4: true}
	}
	return portGateFamily{v6: true}
}
