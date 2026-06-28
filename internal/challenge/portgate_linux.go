//go:build linux

package challenge

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// linuxPortGate owns the nftables `csm_chal` table. The table is kept
// separate from the firewall package's `csm` table so the two can be
// installed and torn down independently (challenge can run with or
// without csm.firewall enabled).
type linuxPortGate struct {
	mu     sync.Mutex
	conn   *nftables.Conn
	cfg    PortGateConfig
	family portGateFamily

	table       *nftables.Table
	setChalIPs  *nftables.Set
	setChalIPs6 *nftables.Set
	setInfra    *nftables.Set
	setInfra6   *nftables.Set
}

func newPortGate(cfg PortGateConfig) (PortGate, error) {
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf("port-gate: invalid listen port %d", cfg.ListenPort)
	}
	fam := familyForListenAddr(cfg.ListenAddr)
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("port-gate: nftables open: %w", err)
	}
	g := &linuxPortGate{conn: conn, cfg: cfg, family: fam}
	if err := g.install(); err != nil {
		return nil, err
	}
	return g, nil
}

// install lays down the table, sets, chain, and per-port rules. Any
// pre-existing `csm_chal` table is deleted first so a daemon restart
// always converges on a clean rule shape (and stale rules from a
// crashed previous run do not linger).
func (g *linuxPortGate) install() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.dropExistingTableLocked()

	g.table = g.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "csm_chal",
	})

	if g.family.v4 {
		g.setChalIPs = &nftables.Set{
			Table:      g.table,
			Name:       "chal_ips",
			KeyType:    nftables.TypeIPAddr,
			HasTimeout: true,
		}
		if err := g.conn.AddSet(g.setChalIPs, nil); err != nil {
			return fmt.Errorf("port-gate: add chal_ips: %w", err)
		}
		g.setInfra = &nftables.Set{
			Table:    g.table,
			Name:     "chal_infra",
			KeyType:  nftables.TypeIPAddr,
			Interval: true,
		}
		if err := g.conn.AddSet(g.setInfra, infraElementsV4(g.cfg.InfraCIDRs)); err != nil {
			return fmt.Errorf("port-gate: add chal_infra: %w", err)
		}
	}
	if g.family.v6 {
		g.setChalIPs6 = &nftables.Set{
			Table:      g.table,
			Name:       "chal_ips6",
			KeyType:    nftables.TypeIP6Addr,
			HasTimeout: true,
		}
		if err := g.conn.AddSet(g.setChalIPs6, nil); err != nil {
			return fmt.Errorf("port-gate: add chal_ips6: %w", err)
		}
		g.setInfra6 = &nftables.Set{
			Table:    g.table,
			Name:     "chal_infra6",
			KeyType:  nftables.TypeIP6Addr,
			Interval: true,
		}
		if err := g.conn.AddSet(g.setInfra6, infraElementsV6(g.cfg.InfraCIDRs)); err != nil {
			return fmt.Errorf("port-gate: add chal_infra6: %w", err)
		}
	}

	prio := nftables.ChainPriority(-200)
	policy := nftables.ChainPolicyAccept
	chain := g.conn.AddChain(&nftables.Chain{
		Name:     "challenge_gate",
		Table:    g.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &prio,
		Policy:   &policy,
	})

	g.addAcceptRules(chain)
	g.addDropRule(chain)

	if err := g.conn.Flush(); err != nil {
		return fmt.Errorf("port-gate: install flush: %w", err)
	}
	return nil
}

// dropExistingTableLocked is idempotent: ListTables + DelTable so a
// re-install does not stack rules on top of a stale chain.
func (g *linuxPortGate) dropExistingTableLocked() {
	tables, err := g.conn.ListTables()
	if err != nil {
		return
	}
	for _, t := range tables {
		if t.Family == nftables.TableFamilyINet && t.Name == "csm_chal" {
			g.conn.DelTable(t)
			_ = g.conn.Flush()
			return
		}
	}
}

func (g *linuxPortGate) addAcceptRules(chain *nftables.Chain) {
	port := portU16(g.cfg.ListenPort)
	if g.family.v4 {
		// loopback bypass
		g.addRule(chain, exprsTCPDportFromV4(port, net.IPv4(127, 0, 0, 0).To4(), net.IPv4Mask(255, 0, 0, 0), expr.VerdictAccept))
		g.addRule(chain, exprsTCPDportSetMatchV4(port, g.setInfra, expr.VerdictAccept))
		g.addRule(chain, exprsTCPDportSetMatchV4(port, g.setChalIPs, expr.VerdictAccept))
	}
	if g.family.v6 {
		loop6 := net.ParseIP("::1").To16()
		mask128 := net.CIDRMask(128, 128)
		g.addRule(chain, exprsTCPDportFromV6(port, loop6, mask128, expr.VerdictAccept))
		g.addRule(chain, exprsTCPDportSetMatchV6(port, g.setInfra6, expr.VerdictAccept))
		g.addRule(chain, exprsTCPDportSetMatchV6(port, g.setChalIPs6, expr.VerdictAccept))
	}
}

func (g *linuxPortGate) addDropRule(chain *nftables.Chain) {
	port := portU16(g.cfg.ListenPort)
	// Any packet that reached this rule with dport == challenge port
	// did not match an accept above; drop it.
	g.conn.AddRule(&nftables.Rule{
		Table: g.table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})
}

func (g *linuxPortGate) addRule(chain *nftables.Chain, exprs []expr.Any) {
	g.conn.AddRule(&nftables.Rule{Table: g.table, Chain: chain, Exprs: exprs})
}

func (g *linuxPortGate) Allow(ip string, ttl time.Duration) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("port-gate: invalid ip %q", ip)
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if !portGateFamilyAcceptsIP(g.family, parsed) {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if ip4 := parsed.To4(); ip4 != nil && g.setChalIPs != nil {
		if err := g.conn.SetAddElements(g.setChalIPs, []nftables.SetElement{
			{Key: ip4, Timeout: ttl},
		}); err != nil {
			return fmt.Errorf("port-gate: add v4 %s: %w", ip, err)
		}
		return g.conn.Flush()
	}
	if g.setChalIPs6 != nil {
		if err := g.conn.SetAddElements(g.setChalIPs6, []nftables.SetElement{
			{Key: parsed.To16(), Timeout: ttl},
		}); err != nil {
			return fmt.Errorf("port-gate: add v6 %s: %w", ip, err)
		}
		return g.conn.Flush()
	}
	// IP family is not gated (e.g., v6 IP on a v4-only listener); silently
	// no-op so the IPList Add path does not surface an unactionable error.
	return nil
}

func (g *linuxPortGate) Revoke(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("port-gate: invalid ip %q", ip)
	}
	if !portGateFamilyAcceptsIP(g.family, parsed) {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if ip4 := parsed.To4(); ip4 != nil && g.setChalIPs != nil {
		if err := g.conn.SetDeleteElements(g.setChalIPs, []nftables.SetElement{{Key: ip4}}); err != nil {
			return fmt.Errorf("port-gate: del v4 %s: %w", ip, err)
		}
		return ignoreNftNotFound(g.conn.Flush())
	}
	if g.setChalIPs6 != nil {
		if err := g.conn.SetDeleteElements(g.setChalIPs6, []nftables.SetElement{{Key: parsed.To16()}}); err != nil {
			return fmt.Errorf("port-gate: del v6 %s: %w", ip, err)
		}
		return ignoreNftNotFound(g.conn.Flush())
	}
	return nil
}

// ignoreNftNotFound treats a "no such file or directory" netlink error from a
// set-element delete as success. Gate elements carry a TTL, so the kernel may
// have already expired the element by the time Revoke runs; deleting an absent
// element is a benign no-op, not a failure worth surfacing.
func ignoreNftNotFound(err error) error {
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}

func (g *linuxPortGate) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.table == nil {
		return nil
	}
	g.conn.DelTable(g.table)
	if err := g.conn.Flush(); err != nil {
		return fmt.Errorf("port-gate: close flush: %w", err)
	}
	g.table = nil
	g.setChalIPs = nil
	g.setChalIPs6 = nil
	g.setInfra = nil
	g.setInfra6 = nil
	return nil
}

func portU16(p int) uint16 {
	if p < 0 || p > 65535 {
		return 0
	}
	// #nosec G115 -- bounds-checked above.
	return uint16(p)
}

// infraElementsV4 builds nftables interval-set elements from the
// operator's infra_ips list, keeping only IPv4 entries. The interval
// set wants [start, end) pairs; net.ParseCIDR + binaryutil pack them
// the same way the firewall engine's infra set does.
func infraElementsV4(cidrs []string) []nftables.SetElement {
	var out []nftables.SetElement
	for _, raw := range cidrs {
		ipnet := parseCIDROrIP(raw)
		if ipnet == nil {
			continue
		}
		start := ipnet.IP.To4()
		if start == nil {
			continue
		}
		end := lastIPv4(ipnet)
		out = append(out,
			nftables.SetElement{Key: start},
			nftables.SetElement{Key: ipv4Inc(end), IntervalEnd: true},
		)
	}
	return out
}

func infraElementsV6(cidrs []string) []nftables.SetElement {
	var out []nftables.SetElement
	for _, raw := range cidrs {
		ipnet := parseCIDROrIP(raw)
		if ipnet == nil {
			continue
		}
		if ipnet.IP.To4() != nil {
			continue
		}
		start := ipnet.IP.To16()
		end := lastIPv6(ipnet)
		out = append(out,
			nftables.SetElement{Key: start},
			nftables.SetElement{Key: ipv6Inc(end), IntervalEnd: true},
		)
	}
	return out
}

// parseCIDROrIP accepts both "1.2.3.4" and "1.2.3.0/24". A bare IP is
// treated as a /32 (or /128 for v6).
func parseCIDROrIP(raw string) *net.IPNet {
	if _, ipnet, err := net.ParseCIDR(raw); err == nil {
		return ipnet
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
}

func lastIPv4(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	out := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		out[i] = ip[i] | ^n.Mask[i]
	}
	return out
}

func lastIPv6(n *net.IPNet) net.IP {
	ip := n.IP.To16()
	out := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		out[i] = ip[i] | ^n.Mask[i]
	}
	return out
}

func ipv4Inc(ip net.IP) net.IP {
	out := make(net.IP, 4)
	copy(out, ip.To4())
	for i := 3; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			return out
		}
	}
	return out
}

func ipv6Inc(ip net.IP) net.IP {
	out := make(net.IP, 16)
	copy(out, ip.To16())
	for i := 15; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			return out
		}
	}
	return out
}

// exprsTCPDportFromV4 produces "L4=TCP, src in CIDR, dport=port -> verdict".
// Mask is the 4-byte IPv4 subnet mask.
func exprsTCPDportFromV4(port uint16, network net.IP, mask net.IPMask, verdict expr.VerdictKind) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Verdict{Kind: verdict},
	}
}

func exprsTCPDportFromV6(port uint16, network net.IP, mask net.IPMask, verdict expr.VerdictKind) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 16, Mask: mask, Xor: make([]byte, 16)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Verdict{Kind: verdict},
	}
}

func exprsTCPDportSetMatchV4(port uint16, set *nftables.Set, verdict expr.VerdictKind) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Verdict{Kind: verdict},
	}
}

func exprsTCPDportSetMatchV6(port uint16, set *nftables.Set, verdict expr.VerdictKind) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Verdict{Kind: verdict},
	}
}
