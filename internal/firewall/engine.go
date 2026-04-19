//go:build linux

package firewall

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// Engine manages the nftables firewall ruleset.
// Manages the nftables ruleset via netlink.
type Engine struct {
	mu   sync.Mutex
	conn *nftables.Conn
	cfg  *FirewallConfig

	table    *nftables.Table
	chainIn  *nftables.Chain
	chainOut *nftables.Chain

	setBlocked    *nftables.Set
	setBlockedNet *nftables.Set
	setAllowed    *nftables.Set
	setInfra      *nftables.Set
	setCountry    *nftables.Set

	// Cloudflare IP whitelist sets (interval for CIDR matching)
	setCFWhitelist  *nftables.Set // IPv4
	setCFWhitelist6 *nftables.Set // IPv6

	// IPv6 sets (nil if IPv6 disabled)
	setBlocked6    *nftables.Set
	setBlockedNet6 *nftables.Set
	setAllowed6    *nftables.Set
	setInfra6      *nftables.Set

	// Meters for per-IP rate limiting
	meterSYN     *nftables.Set
	meterConn    *nftables.Set
	meterUDP     *nftables.Set
	meterConnlim *nftables.Set

	statePath string
}

// BlockedEntry represents a blocked IP with metadata.
type BlockedEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source,omitempty"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"` // zero = permanent
}

// AllowedEntry represents an allowed IP with metadata.
type AllowedEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source,omitempty"`
	Port      int       `json:"port,omitempty"`       // 0 = all ports
	ExpiresAt time.Time `json:"expires_at,omitempty"` // zero = permanent
}

// SubnetEntry represents a blocked CIDR range.
type SubnetEntry struct {
	CIDR      string    `json:"cidr"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source,omitempty"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// PortAllowEntry represents a port-specific IP allow (e.g. tcp|in|d=PORT|s=IP).
type PortAllowEntry struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Proto  string `json:"proto"` // "tcp" or "udp"
	Reason string `json:"reason"`
	Source string `json:"source,omitempty"`
}

// FirewallState is persisted to disk for restore on restart.
type FirewallState struct {
	Blocked     []BlockedEntry   `json:"blocked"`
	BlockedNet  []SubnetEntry    `json:"blocked_nets"`
	Allowed     []AllowedEntry   `json:"allowed"`
	PortAllowed []PortAllowEntry `json:"port_allowed"`
}

// portU16 converts an operator-configured int port to the uint16 nftables
// expects. Returns 0 for out-of-range values; 0 is an unroutable TCP/UDP port
// so a misconfigured rule fails closed (no traffic matches) rather than
// wrapping silently to a valid-but-wrong port.
func portU16(p int) uint16 {
	if p < 0 || p > 65535 {
		return 0
	}
	// #nosec G115 -- bounded above.
	return uint16(p)
}

// NewEngine creates a new nftables firewall engine.
func NewEngine(cfg *FirewallConfig, statePath string) (*Engine, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables connection: %w", err)
	}

	e := &Engine{
		conn:      conn,
		cfg:       cfg,
		statePath: filepath.Join(statePath, "firewall"),
	}
	_ = os.MkdirAll(e.statePath, 0700)

	return e, nil
}

// ConnectExisting connects to an already-running CSM firewall.
// Used by CLI commands to modify the live ruleset without reapplying all rules.
func ConnectExisting(cfg *FirewallConfig, statePath string) (*Engine, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables connection: %w", err)
	}

	// Find existing CSM table
	tables, err := conn.ListTables()
	if err != nil {
		return nil, fmt.Errorf("listing tables: %w", err)
	}

	var table *nftables.Table
	for _, t := range tables {
		if t.Name == "csm" && t.Family == nftables.TableFamilyINet {
			table = t
			break
		}
	}
	if table == nil {
		return nil, fmt.Errorf("CSM firewall not running (table 'csm' not found) - run 'csm firewall restart' first")
	}

	setBlocked, err := conn.GetSetByName(table, "blocked_ips")
	if err != nil {
		return nil, fmt.Errorf("blocked_ips set not found: %w", err)
	}
	setBlockedNet, err := conn.GetSetByName(table, "blocked_nets")
	if err != nil {
		return nil, fmt.Errorf("blocked_nets set not found: %w", err)
	}
	setAllowed, err := conn.GetSetByName(table, "allowed_ips")
	if err != nil {
		return nil, fmt.Errorf("allowed_ips set not found: %w", err)
	}
	setInfra, err := conn.GetSetByName(table, "infra_ips")
	if err != nil {
		return nil, fmt.Errorf("infra_ips set not found: %w", err)
	}

	e := &Engine{
		conn:          conn,
		cfg:           cfg,
		table:         table,
		setBlocked:    setBlocked,
		setBlockedNet: setBlockedNet,
		setAllowed:    setAllowed,
		setInfra:      setInfra,
		statePath:     filepath.Join(statePath, "firewall"),
	}

	// Try to find Cloudflare whitelist sets (optional)
	if s, err := conn.GetSetByName(table, "cf_whitelist"); err == nil {
		e.setCFWhitelist = s
	}
	if s, err := conn.GetSetByName(table, "cf_whitelist6"); err == nil {
		e.setCFWhitelist6 = s
	}

	// Try to find IPv6 sets (optional - may not exist if IPv6 disabled)
	if s, err := conn.GetSetByName(table, "blocked_ips6"); err == nil {
		e.setBlocked6 = s
	}
	if s, err := conn.GetSetByName(table, "blocked_nets6"); err == nil {
		e.setBlockedNet6 = s
	}
	if s, err := conn.GetSetByName(table, "allowed_ips6"); err == nil {
		e.setAllowed6 = s
	}
	if s, err := conn.GetSetByName(table, "infra_ips6"); err == nil {
		e.setInfra6 = s
	}

	return e, nil
}

// Apply builds and atomically applies the complete nftables ruleset.
// All operations (delete old table + create new table/rules) are batched
// into a single netlink transaction. If the flush fails, the kernel keeps
// whatever ruleset was running before - the server is never left without a firewall.
func (e *Engine) Apply() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if existing CSM table needs replacing.
	// If so, include the delete in the same atomic batch as the new table.
	tables, _ := e.conn.ListTables()
	for _, t := range tables {
		if t.Name == "csm" && t.Family == nftables.TableFamilyINet {
			e.conn.DelTable(t)
			break
		}
	}

	// Create table - all operations below are batched, nothing is sent until Flush()
	e.table = e.conn.AddTable(&nftables.Table{
		Name:   "csm",
		Family: nftables.TableFamilyINet,
	})

	// Create IP sets
	if err := e.createSets(); err != nil {
		return fmt.Errorf("creating sets: %w", err)
	}

	// Create chains and rules
	if err := e.createInputChain(); err != nil {
		return fmt.Errorf("creating input chain: %w", err)
	}
	if err := e.createOutputChain(); err != nil {
		return fmt.Errorf("creating output chain: %w", err)
	}

	// Apply atomically - if this fails, nftables keeps whatever was running before
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("applying ruleset: %w", err)
	}

	// Populate sets from persisted state
	if err := e.loadState(); err != nil {
		fmt.Fprintf(os.Stderr, "firewall: warning loading state: %v\n", err)
	}

	return nil
}

// createSets creates the nftables named sets for IP management.
func (e *Engine) createSets() error {
	// Blocked IPs set (with per-element timeout)
	e.setBlocked = &nftables.Set{
		Table:      e.table,
		Name:       "blocked_ips",
		KeyType:    nftables.TypeIPAddr,
		HasTimeout: true,
		Timeout:    24 * time.Hour,
	}
	if err := e.conn.AddSet(e.setBlocked, nil); err != nil {
		return fmt.Errorf("blocked set: %w", err)
	}

	// Blocked subnets set (interval for CIDR ranges, permanent)
	e.setBlockedNet = &nftables.Set{
		Table:    e.table,
		Name:     "blocked_nets",
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	if err := e.conn.AddSet(e.setBlockedNet, nil); err != nil {
		return fmt.Errorf("blocked nets set: %w", err)
	}

	// Allowed IPs set
	e.setAllowed = &nftables.Set{
		Table:   e.table,
		Name:    "allowed_ips",
		KeyType: nftables.TypeIPAddr,
	}
	if err := e.conn.AddSet(e.setAllowed, nil); err != nil {
		return fmt.Errorf("allowed set: %w", err)
	}

	// Infra IPs set (interval for CIDR support) - split IPv4 and IPv6
	e.setInfra = &nftables.Set{
		Table:    e.table,
		Name:     "infra_ips",
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}

	var infraElements []nftables.SetElement
	var infra6Elements []nftables.SetElement
	for _, cidr := range e.cfg.InfraIPs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				infraElements = append(infraElements,
					nftables.SetElement{Key: ip4},
					nftables.SetElement{Key: nextIP(ip4), IntervalEnd: true},
				)
			} else if e.cfg.IPv6 {
				ip16 := ip.To16()
				infra6Elements = append(infra6Elements,
					nftables.SetElement{Key: ip16},
					nftables.SetElement{Key: nextIP(ip16), IntervalEnd: true},
				)
			}
			continue
		}
		if network.IP.To4() != nil {
			start := network.IP.To4()
			end := lastIPInRange(network)
			if start != nil && end != nil {
				infraElements = append(infraElements,
					nftables.SetElement{Key: start},
					nftables.SetElement{Key: nextIP(end), IntervalEnd: true},
				)
			}
		} else if e.cfg.IPv6 {
			start := network.IP.To16()
			end := lastIPInRange(network)
			if start != nil && end != nil {
				infra6Elements = append(infra6Elements,
					nftables.SetElement{Key: start},
					nftables.SetElement{Key: nextIP(end), IntervalEnd: true},
				)
			}
		}
	}

	if err := e.conn.AddSet(e.setInfra, infraElements); err != nil {
		return fmt.Errorf("infra set: %w", err)
	}

	// Cloudflare IP whitelist sets (interval for CIDR ranges, accept on 80/443 only)
	e.setCFWhitelist = &nftables.Set{
		Table:    e.table,
		Name:     "cf_whitelist",
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	if err := e.conn.AddSet(e.setCFWhitelist, nil); err != nil {
		return fmt.Errorf("cf_whitelist set: %w", err)
	}
	e.setCFWhitelist6 = &nftables.Set{
		Table:    e.table,
		Name:     "cf_whitelist6",
		KeyType:  nftables.TypeIP6Addr,
		Interval: true,
	}
	if err := e.conn.AddSet(e.setCFWhitelist6, nil); err != nil {
		return fmt.Errorf("cf_whitelist6 set: %w", err)
	}

	// Country-blocked IPs set (interval for CIDR ranges)
	if len(e.cfg.CountryBlock) > 0 && e.cfg.CountryDBPath != "" {
		e.setCountry = &nftables.Set{
			Table:    e.table,
			Name:     "country_blocked",
			KeyType:  nftables.TypeIPAddr,
			Interval: true,
		}

		var countryElements []nftables.SetElement
		for _, code := range e.cfg.CountryBlock {
			countryElements = append(countryElements, loadCountryCIDRs(e.cfg.CountryDBPath, code)...)
		}

		if err := e.conn.AddSet(e.setCountry, countryElements); err != nil {
			fmt.Fprintf(os.Stderr, "firewall: warning creating country set: %v\n", err)
			e.setCountry = nil
		} else if len(countryElements) > 0 {
			fmt.Fprintf(os.Stderr, "firewall: loaded %d country block ranges for %v\n",
				len(countryElements)/2, e.cfg.CountryBlock)
		}
	}

	// IPv6 sets
	if e.cfg.IPv6 {
		e.setBlocked6 = &nftables.Set{
			Table: e.table, Name: "blocked_ips6",
			KeyType: nftables.TypeIP6Addr, HasTimeout: true, Timeout: 24 * time.Hour,
		}
		if err := e.conn.AddSet(e.setBlocked6, nil); err != nil {
			return fmt.Errorf("blocked6 set: %w", err)
		}

		e.setBlockedNet6 = &nftables.Set{
			Table: e.table, Name: "blocked_nets6",
			KeyType: nftables.TypeIP6Addr, Interval: true,
		}
		if err := e.conn.AddSet(e.setBlockedNet6, nil); err != nil {
			return fmt.Errorf("blocked_nets6 set: %w", err)
		}

		e.setAllowed6 = &nftables.Set{
			Table: e.table, Name: "allowed_ips6",
			KeyType: nftables.TypeIP6Addr,
		}
		if err := e.conn.AddSet(e.setAllowed6, nil); err != nil {
			return fmt.Errorf("allowed6 set: %w", err)
		}

		e.setInfra6 = &nftables.Set{
			Table: e.table, Name: "infra_ips6",
			KeyType: nftables.TypeIP6Addr, Interval: true,
		}
		if err := e.conn.AddSet(e.setInfra6, infra6Elements); err != nil {
			return fmt.Errorf("infra6 set: %w", err)
		}
	}

	// Meter sets for per-IP rate limiting (dynamic sets)
	if e.cfg.SYNFloodProtection {
		e.meterSYN = &nftables.Set{
			Table: e.table, Name: "meter_syn", KeyType: nftables.TypeIPAddr,
			Dynamic: true, HasTimeout: true, Timeout: time.Minute,
		}
		_ = e.conn.AddSet(e.meterSYN, nil)
	}
	if e.cfg.ConnRateLimit > 0 {
		e.meterConn = &nftables.Set{
			Table: e.table, Name: "meter_conn", KeyType: nftables.TypeIPAddr,
			Dynamic: true, HasTimeout: true, Timeout: time.Minute,
		}
		_ = e.conn.AddSet(e.meterConn, nil)
	}
	if e.cfg.UDPFlood && e.cfg.UDPFloodRate > 0 {
		e.meterUDP = &nftables.Set{
			Table: e.table, Name: "meter_udp", KeyType: nftables.TypeIPAddr,
			Dynamic: true, HasTimeout: true, Timeout: time.Minute,
		}
		_ = e.conn.AddSet(e.meterUDP, nil)
	}
	if e.cfg.ConnLimit > 0 {
		e.meterConnlim = &nftables.Set{
			Table: e.table, Name: "meter_connlimit", KeyType: nftables.TypeIPAddr,
			Dynamic: true,
		}
		_ = e.conn.AddSet(e.meterConnlim, nil)
	}

	return nil
}

// createInputChain builds the input filter chain with proper rule ordering.
func (e *Engine) createInputChain() error {
	policy := nftables.ChainPolicyDrop
	e.chainIn = e.conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    e.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	// Rule 1: Allow established/related connections
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Rule 2: Allow loopback
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("lo\x00"),
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Rule 3: Drop INVALID conntrack state (malformed packets)
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitINVALID),
				Xor:  binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	// Rule 4: Allow infra IPs FIRST - infra must NEVER be blocked, even accidentally
	e.addSetMatchRule(e.setInfra, expr.VerdictAccept)
	e.addSetMatchRuleV6(e.setInfra6, expr.VerdictAccept)

	// Rule 4b: Cloudflare IP whitelist - accept on TCP 80/443 only.
	// CF IPs can still be blocked on other ports (unlike infra).
	e.addCFWhitelistRule(e.setCFWhitelist, false)
	e.addCFWhitelistRule(e.setCFWhitelist6, true)

	// Rule 5: Drop blocked IPs (O(1) hash set lookup)
	e.addSetMatchRule(e.setBlocked, expr.VerdictDrop)
	e.addSetMatchRuleV6(e.setBlocked6, expr.VerdictDrop)

	// Rule 6: Drop blocked subnets (interval set for CIDR ranges)
	e.addSetMatchRule(e.setBlockedNet, expr.VerdictDrop)
	e.addSetMatchRuleV6(e.setBlockedNet6, expr.VerdictDrop)

	// Rule 7: Allow explicitly allowed IPs
	e.addSetMatchRule(e.setAllowed, expr.VerdictAccept)
	e.addSetMatchRuleV6(e.setAllowed6, expr.VerdictAccept)

	// Rule 8: Port-specific allows (IP+port, e.g. MySQL access for specific IPs)
	state := e.loadStateFile()
	for _, pa := range state.PortAllowed {
		parsed := net.ParseIP(pa.IP)
		if parsed == nil {
			continue
		}
		proto := byte(6) // TCP
		if pa.Proto == "udp" {
			proto = 17
		}
		if ip4 := parsed.To4(); ip4 != nil {
			e.conn.AddRule(&nftables.Rule{
				Table: e.table,
				Chain: e.chainIn,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip4},
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(pa.Port))},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
		} else if e.cfg.IPv6 {
			ip16 := parsed.To16()
			e.conn.AddRule(&nftables.Rule{
				Table: e.table,
				Chain: e.chainIn,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
					&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10}},
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip16},
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(pa.Port))},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
		}
	}

	// ICMPv4 echo-request (type 8)
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}}, // ICMPv4
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{8}}, // echo-request
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// ICMPv6 echo-request (type 128) + neighbor discovery (types 133-137, required for IPv6)
	if e.cfg.IPv6 {
		for _, icmp6Type := range []byte{128, 133, 134, 135, 136, 137} {
			e.conn.AddRule(&nftables.Rule{
				Table: e.table,
				Chain: e.chainIn,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{58}}, // ICMPv6
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{icmp6Type}},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
		}
	}

	// Per-IP SYN flood protection via meter
	if e.cfg.SYNFloodProtection && e.meterSYN != nil {
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x12}, Xor: []byte{0x00}},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}}, // SYN only
				// Load source IP for per-IP metering
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Dynset{
					SrcRegKey: 1,
					SetName:   e.meterSYN.Name,
					SetID:     e.meterSYN.ID,
					Operation: 1, // NFT_DYNSET_OP_UPDATE
					Exprs: []expr.Any{
						&expr.Limit{Type: expr.LimitTypePkts, Rate: 25, Unit: expr.LimitTimeSecond, Burst: 100, Over: true},
					},
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	// Per-IP new connection rate limit via meter
	if e.cfg.ConnRateLimit > 0 && e.meterConn != nil {
		// #nosec G115 -- ConnRateLimit is an operator-configured int (typical 10–1000);
		// /2 is non-negative and well below uint32 max.
		burst := uint32(e.cfg.ConnRateLimit / 2)
		if burst < 5 {
			burst = 5
		}
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
				&expr.Bitwise{
					SourceRegister: 1, DestRegister: 1, Len: 4,
					Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
					Xor:  binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
				// Load source IP for per-IP metering
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Dynset{
					SrcRegKey: 1,
					SetName:   e.meterConn.Name,
					SetID:     e.meterConn.ID,
					Operation: 1,
					Exprs: []expr.Any{
						&expr.Limit{Type: expr.LimitTypePkts, Rate: uint64(e.cfg.ConnRateLimit), Unit: expr.LimitTimeMinute, Burst: burst, Over: true},
					},
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	// Per-IP concurrent connection limit (CONNLIMIT)
	if e.cfg.ConnLimit > 0 && e.meterConnlim != nil {
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
				&expr.Bitwise{
					SourceRegister: 1, DestRegister: 1, Len: 4,
					Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
					Xor:  binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Dynset{
					SrcRegKey: 1,
					SetName:   e.meterConnlim.Name,
					SetID:     e.meterConnlim.ID,
					Operation: 1,
					Exprs: []expr.Any{
						// #nosec G115 -- ConnLimit is operator-configured non-negative int; fits in uint32.
						&expr.Connlimit{Count: uint32(e.cfg.ConnLimit), Flags: 1}, // 1 = over
					},
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	// Rule 9: Country block - drop traffic from blocked countries
	if e.setCountry != nil {
		e.addSetMatchRule(e.setCountry, expr.VerdictDrop)
	}

	// Per-port flood protection - rate limit new connections per port
	for _, pf := range e.cfg.PortFlood {
		if pf.Hits <= 0 || pf.Seconds <= 0 {
			continue
		}
		proto := byte(6) // TCP
		if pf.Proto == "udp" {
			proto = 17
		}
		// Convert hits/seconds to per-minute rate (multiply first to reduce truncation)
		ratePerMin := uint64(pf.Hits) * 60 / uint64(pf.Seconds)
		if ratePerMin < 1 {
			ratePerMin = 1
		}
		burst := uint32(ratePerMin / 4)
		if burst < 2 {
			burst = 2
		}
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
				&expr.Bitwise{
					SourceRegister: 1, DestRegister: 1, Len: 4,
					Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
					Xor:  binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(pf.Port))},
				&expr.Limit{Type: expr.LimitTypePkts, Rate: ratePerMin, Unit: expr.LimitTimeMinute, Burst: burst, Over: true},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	// Per-IP UDP flood protection via meter
	if e.cfg.UDPFlood && e.cfg.UDPFloodRate > 0 && e.meterUDP != nil {
		// #nosec G115 -- UDPFloodBurst is operator-configured non-negative int.
		burst := uint32(e.cfg.UDPFloodBurst)
		if burst < 10 {
			burst = 10
		}
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}}, // UDP
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Dynset{
					SrcRegKey: 1,
					SetName:   e.meterUDP.Name,
					SetID:     e.meterUDP.ID,
					Operation: 1,
					Exprs: []expr.Any{
						&expr.Limit{Type: expr.LimitTypePkts, Rate: uint64(e.cfg.UDPFloodRate), Unit: expr.LimitTimeSecond, Burst: burst, Over: true},
					},
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	// Build restricted port set - these are only reachable via infra IPs (rule 4)
	restricted := make(map[int]bool)
	for _, p := range e.cfg.RestrictedTCP {
		restricted[p] = true
	}

	// Open TCP ports (public) - restricted ports excluded
	for _, port := range e.cfg.TCPIn {
		if restricted[port] {
			continue
		}
		e.addPortAcceptRule(port, true)
	}

	// Open UDP ports (public)
	for _, port := range e.cfg.UDPIn {
		e.addPortAcceptRule(port, false)
	}

	// Passive FTP range
	if e.cfg.PassiveFTPStart > 0 && e.cfg.PassiveFTPEnd > 0 {
		e.addPortRangeAcceptRule(e.cfg.PassiveFTPStart, e.cfg.PassiveFTPEnd, true)
	}

	// Silent drop for commonly-scanned ports (no logging)
	for _, port := range e.cfg.DropNoLog {
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(port))},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}}, // UDP
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(port))},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	// Rate-limited log for remaining dropped packets
	if e.cfg.LogDropped {
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				&expr.Limit{
					Type:  expr.LimitTypePkts,
					Rate:  uint64(max(e.cfg.LogRate, 1)),
					Unit:  expr.LimitTimeMinute,
					Burst: 5,
				},
				&expr.Log{Key: 1, Data: []byte("CSM-DROP: ")},
			},
		})
	}

	// Default policy is DROP - anything not matched above is dropped

	return nil
}

// createOutputChain builds the output filter chain.
// Restricts outbound to configured ports only (prevents C2 on non-standard ports).
func (e *Engine) createOutputChain() error {
	if len(e.cfg.TCPOut) == 0 && len(e.cfg.UDPOut) == 0 {
		// No outbound restrictions configured - accept all
		policy := nftables.ChainPolicyAccept
		e.chainOut = e.conn.AddChain(&nftables.Chain{
			Name:     "output",
			Table:    e.table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &policy,
		})
		return nil
	}

	// Outbound filtering enabled
	policy := nftables.ChainPolicyDrop
	e.chainOut = e.conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    e.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	// Allow established/related outbound
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainOut,
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Allow loopback outbound
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainOut,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("lo\x00")},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// SMTP block - restrict outbound mail to allowed users only
	smtpBlocked := make(map[int]bool)
	if e.cfg.SMTPBlock && len(e.cfg.SMTPPorts) > 0 {
		// Resolve usernames to UIDs
		var allowedUIDs []uint32
		for _, username := range e.cfg.SMTPAllowUsers {
			u, err := user.Lookup(username)
			if err != nil {
				fmt.Fprintf(os.Stderr, "firewall: smtp_allow_users: unknown user %q\n", username)
				continue
			}
			uid, parseErr := strconv.ParseUint(u.Uid, 10, 32)
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "firewall: smtp_allow_users: invalid uid for %s: %v\n", username, parseErr)
				continue
			}
			allowedUIDs = append(allowedUIDs, uint32(uid))
		}
		// Always allow root
		allowedUIDs = append(allowedUIDs, 0)

		for _, port := range e.cfg.SMTPPorts {
			smtpBlocked[port] = true
			// Accept from each allowed UID
			for _, uid := range allowedUIDs {
				e.conn.AddRule(&nftables.Rule{
					Table: e.table,
					Chain: e.chainOut,
					Exprs: []expr.Any{
						&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
						&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
						&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
						&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(port))},
						&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
						&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uid)},
						&expr.Verdict{Kind: expr.VerdictAccept},
					},
				})
			}
			// Drop SMTP from everyone else
			e.conn.AddRule(&nftables.Rule{
				Table: e.table,
				Chain: e.chainOut,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(port))},
					&expr.Verdict{Kind: expr.VerdictDrop},
				},
			})
		}
	}

	// Allow configured outbound TCP ports (skip SMTP-blocked ports - handled above)
	for _, port := range e.cfg.TCPOut {
		if smtpBlocked[port] {
			continue
		}
		e.addOutboundPortRule(port, true)
	}

	// Allow configured outbound UDP ports
	for _, port := range e.cfg.UDPOut {
		e.addOutboundPortRule(port, false)
	}

	// Allow only safe ICMP outbound (echo-reply + echo-request, block dest-unreachable)
	// Blocking ICMP type 3 (dest-unreachable) prevents leaking closed port info to scanners
	for _, icmpType := range []byte{0, 8} { // 0=echo-reply, 8=echo-request
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainOut,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}}, // ICMP
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{icmpType}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}
	// ICMPv6 outbound - allow echo-reply (129) + echo-request (128) + ND (133-137)
	if e.cfg.IPv6 {
		for _, icmp6Type := range []byte{128, 129, 133, 134, 135, 136, 137} {
			e.conn.AddRule(&nftables.Rule{
				Table: e.table,
				Chain: e.chainOut,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{58}}, // ICMPv6
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{icmp6Type}},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
		}
	}

	// REJECT outbound TCP with RST (faster failure than silent DROP)
	// UDP still silently drops via chain policy.
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainOut,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
			&expr.Reject{Type: 1}, // NFT_REJECT_TCP_RST
		},
	})

	return nil
}

// --- Helper methods ---

// resolveIPSet returns the appropriate set and key bytes for an IP address.
// Falls back to IPv6 set if the IP is not IPv4.
func (e *Engine) resolveIPSet(ip string, set4, set6 *nftables.Set) (*nftables.Set, []byte, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, nil, fmt.Errorf("invalid IP: %s", ip)
	}
	if ip4 := parsed.To4(); ip4 != nil {
		return set4, ip4, nil
	}
	if set6 == nil {
		return nil, nil, fmt.Errorf("IPv6 not enabled in firewall config: %s", ip)
	}
	return set6, parsed.To16(), nil
}

// addSetMatchRule adds an IPv4 source-IP set match rule on the input chain.
func (e *Engine) addSetMatchRule(set *nftables.Set, verdict expr.VerdictKind) {
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
			&expr.Verdict{Kind: verdict},
		},
	})
}

// addSetMatchRuleV6 adds an IPv6 source-IP set match rule on the input chain.
func (e *Engine) addSetMatchRuleV6(set *nftables.Set, verdict expr.VerdictKind) {
	if set == nil {
		return
	}
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10}}, // NFPROTO_IPV6
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
			&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
			&expr.Verdict{Kind: verdict},
		},
	})
}

// addCFWhitelistRule adds an accept rule for Cloudflare IPs on TCP ports 80 and 443.
// Equivalent to: ip saddr @cf_whitelist tcp dport {80, 443} accept
func (e *Engine) addCFWhitelistRule(set *nftables.Set, ipv6 bool) {
	if set == nil {
		return
	}
	for _, port := range []uint16{80, 443} {
		var exprs []expr.Any
		if ipv6 {
			exprs = append(exprs,
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10}}, // NFPROTO_IPV6
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
			)
		} else {
			exprs = append(exprs,
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			)
		}
		exprs = append(exprs,
			&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		)
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: exprs,
		})
	}
}

func (e *Engine) addPortAcceptRule(port int, tcp bool) {
	proto := byte(6) // TCP
	if !tcp {
		proto = 17 // UDP
	}
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(port))},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
}

func (e *Engine) addPortRangeAcceptRule(startPort, endPort int, tcp bool) {
	proto := byte(6)
	if !tcp {
		proto = 17
	}
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			// Load dest port once, check range
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(startPort))},
			&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(endPort))},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
}

func (e *Engine) addOutboundPortRule(port int, tcp bool) {
	proto := byte(6)
	if !tcp {
		proto = 17
	}
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainOut,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(port))},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
}

// --- Public API ---

// BlockIP adds an IP to the blocked set with optional timeout.
// timeout 0 = permanent block.
func (e *Engine) BlockIP(ip string, reason string, timeout time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	targetSet, key, err := e.resolveIPSet(ip, e.setBlocked, e.setBlocked6)
	if err != nil {
		return err
	}

	// SAFETY: never block infra IPs - prevents admin lockout
	for _, cidr := range e.cfg.InfraIPs {
		_, network, cidrErr := net.ParseCIDR(cidr)
		if cidrErr != nil {
			if cidr == ip {
				return fmt.Errorf("refusing to block infra IP: %s", ip)
			}
			continue
		}
		if network.Contains(net.ParseIP(ip)) {
			return fmt.Errorf("refusing to block infra IP: %s (in %s)", ip, cidr)
		}
	}

	// Enforce deny IP limits
	if e.cfg.DenyIPLimit > 0 || e.cfg.DenyTempIPLimit > 0 {
		st := e.loadStateFile()
		perm, temp := 0, 0
		for _, b := range st.Blocked {
			if b.ExpiresAt.IsZero() {
				perm++
			} else {
				temp++
			}
		}
		if timeout == 0 && e.cfg.DenyIPLimit > 0 && perm >= e.cfg.DenyIPLimit {
			return fmt.Errorf("permanent deny limit reached (%d)", e.cfg.DenyIPLimit)
		}
		if timeout > 0 && e.cfg.DenyTempIPLimit > 0 && temp >= e.cfg.DenyTempIPLimit {
			return fmt.Errorf("temporary deny limit reached (%d)", e.cfg.DenyTempIPLimit)
		}
	}

	elem := []nftables.SetElement{{Key: key, Timeout: timeout}}
	if err := e.conn.SetAddElements(targetSet, elem); err != nil {
		return fmt.Errorf("adding to blocked set: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	// Persist - zero ExpiresAt means permanent
	entry := BlockedEntry{
		IP:        ip,
		Reason:    reason,
		Source:    InferProvenance("block", reason),
		BlockedAt: time.Now(),
	}
	if timeout > 0 {
		entry.ExpiresAt = time.Now().Add(timeout)
	}
	e.saveBlockedEntry(entry)
	AppendAudit(e.statePath, "block", ip, reason, entry.Source, timeout)

	return nil
}

// UnblockIP removes an IP from the blocked set and state.
func (e *Engine) UnblockIP(ip string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	targetSet, key, err := e.resolveIPSet(ip, e.setBlocked, e.setBlocked6)
	if err != nil {
		return err
	}

	if err := e.conn.SetDeleteElements(targetSet, []nftables.SetElement{{Key: key}}); err != nil {
		return fmt.Errorf("removing from blocked set: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	e.removeBlockedState(ip)
	AppendAudit(e.statePath, "unblock", ip, "", "", 0)

	return nil
}

// IsBlocked returns true if the IP is currently in the engine's blocked state.
// Uses the persisted state file (which is cleaned of expired entries on load).
func (e *Engine) IsBlocked(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	st := e.loadStateFile()
	for _, entry := range st.Blocked {
		if entry.IP == ip {
			return true
		}
	}
	return false
}

// AllowIP adds an IP to the allowed set and persists it.
// If the IP is currently blocked, the block is removed first.
func (e *Engine) AllowIP(ip string, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	blockedSet, blockedKey, _ := e.resolveIPSet(ip, e.setBlocked, e.setBlocked6)
	allowedSet, allowedKey, err := e.resolveIPSet(ip, e.setAllowed, e.setAllowed6)
	if err != nil {
		return err
	}

	// Remove from blocked set + add to allowed set in same batch
	if blockedSet != nil {
		_ = e.conn.SetDeleteElements(blockedSet, []nftables.SetElement{{Key: blockedKey}})
	}
	if err := e.conn.SetAddElements(allowedSet, []nftables.SetElement{{Key: allowedKey}}); err != nil {
		return fmt.Errorf("adding to allowed set: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	// State mutations only after successful flush
	e.removeBlockedState(ip)
	entry := AllowedEntry{IP: ip, Reason: reason, Source: InferProvenance("allow", reason)}
	e.saveAllowedEntry(entry)
	AppendAudit(e.statePath, "allow", ip, reason, entry.Source, 0)

	return nil
}

// TempAllowIP adds a temporary allow with expiry. Uses the same allowed set
// but tracks expiry in state - CleanExpiredAllows removes them periodically.
func (e *Engine) TempAllowIP(ip string, reason string, timeout time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	blockedSet, blockedKey, _ := e.resolveIPSet(ip, e.setBlocked, e.setBlocked6)
	allowedSet, allowedKey, err := e.resolveIPSet(ip, e.setAllowed, e.setAllowed6)
	if err != nil {
		return err
	}

	if blockedSet != nil {
		_ = e.conn.SetDeleteElements(blockedSet, []nftables.SetElement{{Key: blockedKey}})
	}
	if err := e.conn.SetAddElements(allowedSet, []nftables.SetElement{{Key: allowedKey}}); err != nil {
		return fmt.Errorf("adding to allowed set: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	e.removeBlockedState(ip)
	entry := AllowedEntry{IP: ip, Reason: reason, Source: InferProvenance("temp_allow", reason)}
	if timeout > 0 {
		entry.ExpiresAt = time.Now().Add(timeout)
	}
	e.saveAllowedEntry(entry)
	AppendAudit(e.statePath, "temp_allow", ip, reason, entry.Source, timeout)

	return nil
}

// CleanExpiredAllows removes expired temporary allows from the set and state.
// An IP is only removed from nftables if no non-expired entries remain for it.
// Called periodically by the daemon.
func (e *Engine) CleanExpiredAllows() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.loadStateFile()
	now := time.Now()
	var active []AllowedEntry
	expiredIPs := make(map[string]bool)
	removed := 0

	for _, entry := range state.Allowed {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			expiredIPs[entry.IP] = true
			removed++
			AppendAudit(e.statePath, "temp_allow_expired", entry.IP, "", SourceSystem, 0)
		} else {
			active = append(active, entry)
		}
	}

	if removed > 0 {
		// Only remove from nftables if no active entries remain for the IP
		activeIPs := make(map[string]bool)
		for _, entry := range active {
			activeIPs[entry.IP] = true
		}
		for ip := range expiredIPs {
			if !activeIPs[ip] {
				if set, key, err := e.resolveIPSet(ip, e.setAllowed, e.setAllowed6); err == nil {
					_ = e.conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}})
				}
			}
		}
		if err := e.conn.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "firewall: error flushing expired allows: %v\n", err)
			return 0 // don't update state; will retry on next tick
		}
		state.Allowed = active
		e.saveState(&state)
	}
	return removed
}

// CleanExpiredSubnets removes expired temporary subnet blocks from nftables and state.
func (e *Engine) CleanExpiredSubnets() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.loadStateFile()
	now := time.Now()
	var active []SubnetEntry
	removed := 0

	for _, entry := range state.BlockedNet {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			if _, network, err := net.ParseCIDR(entry.CIDR); err == nil {
				if set, start, end := e.resolveSubnetSet(network); set != nil {
					_ = e.conn.SetDeleteElements(set, []nftables.SetElement{
						{Key: start},
						{Key: nextIP(end), IntervalEnd: true},
					})
				}
			}
			removed++
			AppendAudit(e.statePath, "temp_subnet_expired", entry.CIDR, "", SourceSystem, 0)
			continue
		}
		active = append(active, entry)
	}

	if removed > 0 {
		_ = e.conn.Flush()
		state.BlockedNet = active
		e.saveState(&state)
	}
	return removed
}

// RemoveAllowIP removes an IP from the allowed set and state.
func (e *Engine) RemoveAllowIP(ip string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	targetSet, key, err := e.resolveIPSet(ip, e.setAllowed, e.setAllowed6)
	if err != nil {
		return err
	}

	if err := e.conn.SetDeleteElements(targetSet, []nftables.SetElement{{Key: key}}); err != nil {
		return fmt.Errorf("removing from allowed set: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	e.removeAllowedState(ip)
	AppendAudit(e.statePath, "remove_allow", ip, "", "", 0)
	return nil
}

// RemoveAllowIPBySource removes only allow entries from a specific source.
// The IP is only removed from the nftables set if no other sources remain.
func (e *Engine) RemoveAllowIPBySource(ip, source string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	ipGone := e.removeAllowedStateBySource(ip, source)
	if ipGone {
		targetSet, key, err := e.resolveIPSet(ip, e.setAllowed, e.setAllowed6)
		if err != nil {
			return err
		}
		if err := e.conn.SetDeleteElements(targetSet, []nftables.SetElement{{Key: key}}); err != nil {
			return fmt.Errorf("removing from allowed set: %w", err)
		}
		if err := e.conn.Flush(); err != nil {
			return fmt.Errorf("flushing: %w", err)
		}
	}

	AppendAudit(e.statePath, "remove_allow", ip, "source: "+source, source, 0)
	return nil
}

// AllowIPPort adds a port-specific IP allow. The rule is persisted to state
// and applied on the next Apply(). For immediate effect, call Apply() after.
func (e *Engine) AllowIPPort(ip string, port int, proto string, reason string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %d", port)
	}
	if proto != "tcp" && proto != "udp" {
		proto = "tcp"
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	st := e.loadStateFile()
	// Deduplicate
	for _, existing := range st.PortAllowed {
		if existing.IP == ip && existing.Port == port && existing.Proto == proto {
			return nil // already exists
		}
	}
	st.PortAllowed = append(st.PortAllowed, PortAllowEntry{
		IP: ip, Port: port, Proto: proto, Reason: reason, Source: InferProvenance("allow_port", reason),
	})
	e.saveState(&st)
	AppendAudit(e.statePath, "allow_port", fmt.Sprintf("%s:%d/%s", ip, port, proto), reason, InferProvenance("allow_port", reason), 0)
	return nil
}

// RemoveAllowIPPort removes a port-specific IP allow from state.
func (e *Engine) RemoveAllowIPPort(ip string, port int, proto string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	st := e.loadStateFile()
	var remaining []PortAllowEntry
	found := false
	for _, entry := range st.PortAllowed {
		if entry.IP == ip && entry.Port == port && entry.Proto == proto {
			found = true
			continue
		}
		remaining = append(remaining, entry)
	}
	if !found {
		return fmt.Errorf("port allow not found: %s:%d/%s", ip, port, proto)
	}
	st.PortAllowed = remaining
	e.saveState(&st)
	AppendAudit(e.statePath, "remove_port_allow", fmt.Sprintf("%s:%d/%s", ip, port, proto), "", "", 0)
	return nil
}

// FlushBlocked removes all IPs from the blocked set and clears persisted state.
func (e *Engine) FlushBlocked() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.conn.FlushSet(e.setBlocked)
	if e.setBlocked6 != nil {
		e.conn.FlushSet(e.setBlocked6)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("flushing blocked set: %w", err)
	}

	state := e.loadStateFile()
	count := len(state.Blocked)
	state.Blocked = nil
	e.saveState(&state)
	AppendAudit(e.statePath, "flush", "", fmt.Sprintf("cleared %d entries", count), SourceSystem, 0)

	return nil
}

// BlockSubnet adds a CIDR range to the blocked subnets set (IPv4 or IPv6).
// timeout 0 = permanent block.
func (e *Engine) BlockSubnet(cidr string, reason string, timeout time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}

	targetSet, start, end := e.resolveSubnetSet(network)
	if targetSet == nil {
		return fmt.Errorf("no matching set for %s (IPv6 disabled?)", cidr)
	}

	elements := []nftables.SetElement{
		{Key: start},
		{Key: nextIP(end), IntervalEnd: true},
	}
	if err := e.conn.SetAddElements(targetSet, elements); err != nil {
		return fmt.Errorf("adding to blocked_nets: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	entry := SubnetEntry{
		CIDR:      network.String(),
		Reason:    reason,
		Source:    InferProvenance("block_subnet", reason),
		BlockedAt: time.Now(),
	}
	if timeout > 0 {
		entry.ExpiresAt = time.Now().Add(timeout)
	}
	e.saveSubnetEntry(entry)
	AppendAudit(e.statePath, "block_subnet", network.String(), reason, entry.Source, timeout)
	return nil
}

// UnblockSubnet removes a CIDR range from the blocked subnets set (IPv4 or IPv6).
func (e *Engine) UnblockSubnet(cidr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}

	targetSet, start, end := e.resolveSubnetSet(network)
	if targetSet == nil {
		return fmt.Errorf("no matching set for %s (IPv6 disabled?)", cidr)
	}

	elements := []nftables.SetElement{
		{Key: start},
		{Key: nextIP(end), IntervalEnd: true},
	}
	if err := e.conn.SetDeleteElements(targetSet, elements); err != nil {
		return fmt.Errorf("removing from blocked_nets: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	e.removeSubnetState(network.String())
	AppendAudit(e.statePath, "unblock_subnet", network.String(), "", "", 0)
	return nil
}

// resolveSubnetSet returns the correct blocked_nets set and start/end keys
// for a CIDR. Returns (nil, nil, nil) when IPv6 is disabled for a v6 CIDR,
// or when lastIPInRange cannot produce an interval end (malformed
// net.IPNet whose IP is neither 4 nor 16 bytes) -- callers already check
// for a nil set, so this also short-circuits the degenerate case where
// nextIP(nil) would feed an empty Key to the kernel.
func (e *Engine) resolveSubnetSet(network *net.IPNet) (*nftables.Set, net.IP, net.IP) {
	end := lastIPInRange(network)
	if end == nil {
		return nil, nil, nil
	}
	if start := network.IP.To4(); start != nil {
		return e.setBlockedNet, start, end
	}
	if e.setBlockedNet6 != nil {
		return e.setBlockedNet6, network.IP.To16(), end
	}
	return nil, nil, nil
}

// Status returns current firewall statistics.
func (e *Engine) Status() map[string]interface{} {
	state := e.loadStateFile()
	return map[string]interface{}{
		"enabled":     e.cfg.Enabled,
		"tcp_in":      e.cfg.TCPIn,
		"tcp_out":     e.cfg.TCPOut,
		"udp_in":      e.cfg.UDPIn,
		"udp_out":     e.cfg.UDPOut,
		"infra_ips":   e.cfg.InfraIPs,
		"blocked":     len(state.Blocked),
		"allowed":     len(state.Allowed),
		"log_dropped": e.cfg.LogDropped,
	}
}

// --- State persistence ---

func (e *Engine) loadState() error {
	// Each SetAddElements call queues a separate netlink message whose ack
	// the kernel streams back at Flush time. Previously this function
	// issued one call per entry, so a host with a few hundred persisted
	// blocks overflowed the netlink socket's SO_RCVBUF and recvmsg
	// returned ENOBUFS ("no buffer space available"). Accumulating into
	// one slice per target set collapses the batch into at most six
	// netlink messages regardless of how many entries are persisted.
	state := e.loadStateFile()
	now := time.Now()

	var (
		blocked4, blocked6       []nftables.SetElement
		allowed4, allowed6       []nftables.SetElement
		blockedNet4, blockedNet6 []nftables.SetElement
	)

	for _, entry := range state.Blocked {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			continue
		}
		parsed := net.ParseIP(entry.IP)
		if parsed == nil {
			continue
		}
		timeout := time.Duration(0)
		if !entry.ExpiresAt.IsZero() {
			timeout = time.Until(entry.ExpiresAt)
		}
		if ip4 := parsed.To4(); ip4 != nil {
			blocked4 = append(blocked4, nftables.SetElement{Key: ip4, Timeout: timeout})
		} else if e.setBlocked6 != nil {
			blocked6 = append(blocked6, nftables.SetElement{Key: parsed.To16(), Timeout: timeout})
		}
	}

	restoredAllowed := make(map[string]bool)
	for _, entry := range state.Allowed {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			continue
		}
		if restoredAllowed[entry.IP] {
			continue // already added from another source entry
		}
		parsed := net.ParseIP(entry.IP)
		if parsed == nil {
			continue
		}
		if ip4 := parsed.To4(); ip4 != nil {
			allowed4 = append(allowed4, nftables.SetElement{Key: ip4})
		} else if e.setAllowed6 != nil {
			allowed6 = append(allowed6, nftables.SetElement{Key: parsed.To16()})
		}
		restoredAllowed[entry.IP] = true
	}

	for _, entry := range state.BlockedNet {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			continue
		}
		_, network, err := net.ParseCIDR(entry.CIDR)
		if err != nil {
			continue
		}
		end := lastIPInRange(network)
		if end == nil {
			continue // malformed net.IPNet — neither v4 nor v6 byte length
		}
		if start := network.IP.To4(); start != nil {
			blockedNet4 = append(blockedNet4,
				nftables.SetElement{Key: start},
				nftables.SetElement{Key: nextIP(end), IntervalEnd: true},
			)
		} else if e.setBlockedNet6 != nil {
			blockedNet6 = append(blockedNet6,
				nftables.SetElement{Key: network.IP.To16()},
				nftables.SetElement{Key: nextIP(end), IntervalEnd: true},
			)
		}
	}

	e.addElementsChunked(e.setBlocked, blocked4)
	if e.setBlocked6 != nil {
		e.addElementsChunked(e.setBlocked6, blocked6)
	}
	e.addElementsChunked(e.setAllowed, allowed4)
	if e.setAllowed6 != nil {
		e.addElementsChunked(e.setAllowed6, allowed6)
	}
	e.addElementsChunked(e.setBlockedNet, blockedNet4)
	if e.setBlockedNet6 != nil {
		e.addElementsChunked(e.setBlockedNet6, blockedNet6)
	}

	return e.conn.Flush()
}

// addElementsChunked issues SetAddElements in fixed-size chunks. A single
// SetAddElements call encodes all elements into one netlink message whose
// size scales linearly with len(elems); the kernel's netlink socket rmem
// (typically 208 KB, tunable via net.core.rmem_max) caps how big that
// message can be before the receive path refuses it with ENOBUFS. At
// ~28 bytes per element worst-case a 1000-element chunk is ~28 KB, well
// under the default rmem and comfortably below any realistic rmem_max.
// The batch size must stay even so interval sets (blocked_net, where each
// CIDR expands to a consecutive {start, IntervalEnd} pair) never split a
// pair across chunks.
func (e *Engine) addElementsChunked(s *nftables.Set, elems []nftables.SetElement) {
	const chunk = 1000
	for i := 0; i < len(elems); i += chunk {
		end := i + chunk
		if end > len(elems) {
			end = len(elems)
		}
		_ = e.conn.SetAddElements(s, elems[i:end])
	}
}

func (e *Engine) loadStateFile() FirewallState {
	var state FirewallState
	stateFile := filepath.Join(e.statePath, "state.json")
	if !fileExistsFirewall(stateFile) {
		return state
	}
	// #nosec G304 -- filepath.Join under operator-configured statePath.
	data, _ := os.ReadFile(stateFile)
	_ = json.Unmarshal(data, &state)

	// Clean expired entries
	now := time.Now()
	var active []BlockedEntry
	for _, entry := range state.Blocked {
		if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
			active = append(active, entry)
		}
	}
	state.Blocked = active

	var activeNets []SubnetEntry
	for _, entry := range state.BlockedNet {
		if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
			activeNets = append(activeNets, entry)
		}
	}
	state.BlockedNet = activeNets

	var activeAllowed []AllowedEntry
	for _, entry := range state.Allowed {
		if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
			activeAllowed = append(activeAllowed, entry)
		}
	}
	state.Allowed = activeAllowed

	return state
}

func (e *Engine) saveState(state *FirewallState) {
	path := filepath.Join(e.statePath, "state.json")
	data, _ := json.MarshalIndent(state, "", "  ")
	tmpPath := path + ".tmp"
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, path)
}

func (e *Engine) saveBlockedEntry(entry BlockedEntry) {
	if entry.Source == "" {
		entry.Source = InferProvenance("block", entry.Reason)
	}
	state := e.loadStateFile()
	// Deduplicate
	for i, existing := range state.Blocked {
		if existing.IP == entry.IP {
			state.Blocked[i] = entry
			e.saveState(&state)
			return
		}
	}
	state.Blocked = append(state.Blocked, entry)
	e.saveState(&state)
}

func (e *Engine) removeBlockedState(ip string) {
	state := e.loadStateFile()
	var remaining []BlockedEntry
	for _, entry := range state.Blocked {
		if entry.IP != ip {
			remaining = append(remaining, entry)
		}
	}
	state.Blocked = remaining
	e.saveState(&state)
}

func (e *Engine) saveAllowedEntry(entry AllowedEntry) {
	if entry.Source == "" {
		entry.Source = InferProvenance("allow", entry.Reason)
	}
	state := e.loadStateFile()
	for i, existing := range state.Allowed {
		if existing.IP == entry.IP && existing.Source == entry.Source {
			state.Allowed[i] = entry // update reason/expiry for same source
			e.saveState(&state)
			return
		}
	}
	state.Allowed = append(state.Allowed, entry)
	e.saveState(&state)
}

func (e *Engine) removeAllowedState(ip string) {
	state := e.loadStateFile()
	var remaining []AllowedEntry
	for _, entry := range state.Allowed {
		if entry.IP != ip {
			remaining = append(remaining, entry)
		}
	}
	state.Allowed = remaining
	e.saveState(&state)
}

// removeAllowedStateBySource removes only entries matching ip+source.
// Returns true if no entries remain for that IP (caller should remove from nftables).
// Returns false if the IP was not in state at all (no action needed).
func (e *Engine) removeAllowedStateBySource(ip, source string) bool {
	state := e.loadStateFile()
	var remaining []AllowedEntry
	found := false
	ipStillPresent := false
	for _, entry := range state.Allowed {
		if entry.IP == ip && entry.Source == source {
			found = true
			continue
		}
		remaining = append(remaining, entry)
		if entry.IP == ip {
			ipStillPresent = true
		}
	}
	if !found {
		return false // IP+source not in state, nothing to do
	}
	state.Allowed = remaining
	e.saveState(&state)
	return !ipStillPresent
}

func (e *Engine) saveSubnetEntry(entry SubnetEntry) {
	if entry.Source == "" {
		entry.Source = InferProvenance("block_subnet", entry.Reason)
	}
	state := e.loadStateFile()
	for _, existing := range state.BlockedNet {
		if existing.CIDR == entry.CIDR {
			return
		}
	}
	state.BlockedNet = append(state.BlockedNet, entry)
	e.saveState(&state)
}

func (e *Engine) removeSubnetState(cidr string) {
	state := e.loadStateFile()
	var remaining []SubnetEntry
	for _, entry := range state.BlockedNet {
		if entry.CIDR != cidr {
			remaining = append(remaining, entry)
		}
	}
	state.BlockedNet = remaining
	e.saveState(&state)
}

// IP helpers (nextIP, lastIPInRange, fileExistsFirewall) moved to ip_helpers.go (no build tag).

// loadCountryCIDRs reads CIDR ranges from a country file.
// Expected format: one CIDR per line in {dbPath}/{CODE}.cidr
func loadCountryCIDRs(dbPath, countryCode string) []nftables.SetElement {
	file := filepath.Join(dbPath, strings.ToUpper(countryCode)+".cidr")
	// #nosec G304 -- filepath.Join under operator-configured GeoIP dbPath.
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	var elements []nftables.SetElement
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		start := network.IP.To4()
		end := lastIPInRange(network)
		if start != nil && end != nil {
			elements = append(elements,
				nftables.SetElement{Key: start},
				nftables.SetElement{Key: nextIP(end), IntervalEnd: true},
			)
		}
	}
	return elements
}
