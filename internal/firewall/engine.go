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
// Replaces CSF with native Go nftables via netlink.
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
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"` // zero = permanent
}

// AllowedEntry represents an allowed IP with metadata.
type AllowedEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Port      int       `json:"port,omitempty"`       // 0 = all ports
	ExpiresAt time.Time `json:"expires_at,omitempty"` // zero = permanent
}

// SubnetEntry represents a blocked CIDR range.
type SubnetEntry struct {
	CIDR      string    `json:"cidr"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
}

// FirewallState is persisted to disk for restore on restart.
type FirewallState struct {
	Blocked    []BlockedEntry `json:"blocked"`
	BlockedNet []SubnetEntry  `json:"blocked_nets"`
	Allowed    []AllowedEntry `json:"allowed"`
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
		return nil, fmt.Errorf("CSM firewall not running (table 'csm' not found) — run 'csm firewall restart' first")
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

	// Try to find IPv6 sets (optional — may not exist if IPv6 disabled)
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
// whatever ruleset was running before — the server is never left without a firewall.
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

	// Create table — all operations below are batched, nothing is sent until Flush()
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

	// Apply atomically — if this fails, nftables keeps whatever was running before
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

	// Infra IPs set (interval for CIDR support) — split IPv4 and IPv6
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

	// Rule 4: Drop blocked IPs (O(1) hash set lookup)
	e.addSetMatchRule(e.setBlocked, expr.VerdictDrop)
	e.addSetMatchRuleV6(e.setBlocked6, expr.VerdictDrop)

	// Rule 5: Drop blocked subnets (interval set for CIDR ranges)
	e.addSetMatchRule(e.setBlockedNet, expr.VerdictDrop)
	e.addSetMatchRuleV6(e.setBlockedNet6, expr.VerdictDrop)

	// Rule 6: Allow infra IPs (all ports)
	e.addSetMatchRule(e.setInfra, expr.VerdictAccept)
	e.addSetMatchRuleV6(e.setInfra6, expr.VerdictAccept)

	// Rule 7: Allow explicitly allowed IPs
	e.addSetMatchRule(e.setAllowed, expr.VerdictAccept)
	e.addSetMatchRuleV6(e.setAllowed6, expr.VerdictAccept)

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
						&expr.Connlimit{Count: uint32(e.cfg.ConnLimit), Flags: 1}, // 1 = over
					},
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	// Rule 9: Country block — drop traffic from blocked countries
	if e.setCountry != nil {
		e.addSetMatchRule(e.setCountry, expr.VerdictDrop)
	}

	// Per-port flood protection — rate limit new connections per port
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
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(pf.Port))},
				&expr.Limit{Type: expr.LimitTypePkts, Rate: ratePerMin, Unit: expr.LimitTimeMinute, Burst: burst, Over: true},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	// Per-IP UDP flood protection via meter
	if e.cfg.UDPFlood && e.cfg.UDPFloodRate > 0 && e.meterUDP != nil {
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

	// Build restricted port set — these are only reachable via infra IPs (rule 4)
	restricted := make(map[int]bool)
	for _, p := range e.cfg.RestrictedTCP {
		restricted[p] = true
	}

	// Open TCP ports (public) — restricted ports excluded
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
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
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
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
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

	// Default policy is DROP — anything not matched above is dropped

	return nil
}

// createOutputChain builds the output filter chain.
// Restricts outbound to configured ports only (prevents C2 on non-standard ports).
func (e *Engine) createOutputChain() error {
	if len(e.cfg.TCPOut) == 0 && len(e.cfg.UDPOut) == 0 {
		// No outbound restrictions configured — accept all
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

	// SMTP block — restrict outbound mail to allowed users only
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
						&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
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
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
					&expr.Verdict{Kind: expr.VerdictDrop},
				},
			})
		}
	}

	// Allow configured outbound TCP ports (skip SMTP-blocked ports — handled above)
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

	// Allow ICMP outbound
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainOut,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

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
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
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
			&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(startPort))},
			&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(endPort))},
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
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
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

	// Persist — zero ExpiresAt means permanent
	entry := BlockedEntry{
		IP:        ip,
		Reason:    reason,
		BlockedAt: time.Now(),
	}
	if timeout > 0 {
		entry.ExpiresAt = time.Now().Add(timeout)
	}
	e.saveBlockedEntry(entry)
	AppendAudit(e.statePath, "block", ip, reason, timeout)

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
	AppendAudit(e.statePath, "unblock", ip, "", 0)

	return nil
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
	e.saveAllowedEntry(AllowedEntry{IP: ip, Reason: reason})
	AppendAudit(e.statePath, "allow", ip, reason, 0)

	return nil
}

// TempAllowIP adds a temporary allow with expiry. Uses the same allowed set
// but tracks expiry in state — CleanExpiredAllows removes them periodically.
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
	entry := AllowedEntry{IP: ip, Reason: reason}
	if timeout > 0 {
		entry.ExpiresAt = time.Now().Add(timeout)
	}
	e.saveAllowedEntry(entry)
	AppendAudit(e.statePath, "temp_allow", ip, reason, timeout)

	return nil
}

// CleanExpiredAllows removes expired temporary allows from the set and state.
// Called periodically by the daemon.
func (e *Engine) CleanExpiredAllows() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.loadStateFile()
	now := time.Now()
	var active []AllowedEntry
	removed := 0

	for _, entry := range state.Allowed {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			// Remove from nftables
			if set, key, err := e.resolveIPSet(entry.IP, e.setAllowed, e.setAllowed6); err == nil {
				_ = e.conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}})
			}
			removed++
			AppendAudit(e.statePath, "temp_allow_expired", entry.IP, "", 0)
		} else {
			active = append(active, entry)
		}
	}

	if removed > 0 {
		_ = e.conn.Flush()
		state.Allowed = active
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
	AppendAudit(e.statePath, "remove_allow", ip, "", 0)
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
	AppendAudit(e.statePath, "flush", "", fmt.Sprintf("cleared %d entries", count), 0)

	return nil
}

// BlockSubnet adds a CIDR range to the blocked subnets set (IPv4 or IPv6).
func (e *Engine) BlockSubnet(cidr string, reason string) error {
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

	e.saveSubnetEntry(SubnetEntry{CIDR: network.String(), Reason: reason, BlockedAt: time.Now()})
	AppendAudit(e.statePath, "block_subnet", network.String(), reason, 0)
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
	AppendAudit(e.statePath, "unblock_subnet", network.String(), "", 0)
	return nil
}

// resolveSubnetSet returns the correct blocked_nets set and start/end keys for a CIDR.
func (e *Engine) resolveSubnetSet(network *net.IPNet) (*nftables.Set, net.IP, net.IP) {
	end := lastIPInRange(network)
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
	state := e.loadStateFile()
	now := time.Now()

	// Restore blocked IPs (skip expired, route to IPv4 or IPv6 set)
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
			_ = e.conn.SetAddElements(e.setBlocked, []nftables.SetElement{{Key: ip4, Timeout: timeout}})
		} else if e.setBlocked6 != nil {
			_ = e.conn.SetAddElements(e.setBlocked6, []nftables.SetElement{{Key: parsed.To16(), Timeout: timeout}})
		}
	}

	// Restore allowed IPs (route to IPv4 or IPv6 set)
	for _, entry := range state.Allowed {
		parsed := net.ParseIP(entry.IP)
		if parsed == nil {
			continue
		}
		if ip4 := parsed.To4(); ip4 != nil {
			_ = e.conn.SetAddElements(e.setAllowed, []nftables.SetElement{{Key: ip4}})
		} else if e.setAllowed6 != nil {
			_ = e.conn.SetAddElements(e.setAllowed6, []nftables.SetElement{{Key: parsed.To16()}})
		}
	}

	// Restore blocked subnets (route to IPv4 or IPv6 set)
	for _, entry := range state.BlockedNet {
		_, network, err := net.ParseCIDR(entry.CIDR)
		if err != nil {
			continue
		}
		start := network.IP.To4()
		end := lastIPInRange(network)
		if start != nil && end != nil {
			_ = e.conn.SetAddElements(e.setBlockedNet, []nftables.SetElement{
				{Key: start},
				{Key: nextIP(end), IntervalEnd: true},
			})
		} else if e.setBlockedNet6 != nil {
			start6 := network.IP.To16()
			end6 := lastIPInRange(network)
			_ = e.conn.SetAddElements(e.setBlockedNet6, []nftables.SetElement{
				{Key: start6},
				{Key: nextIP(end6), IntervalEnd: true},
			})
		}
	}

	return e.conn.Flush()
}

func (e *Engine) loadStateFile() FirewallState {
	var state FirewallState
	stateFile := filepath.Join(e.statePath, "state.json")
	if !fileExistsFirewall(stateFile) {
		return state
	}
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
	state := e.loadStateFile()
	for _, existing := range state.Allowed {
		if existing.IP == entry.IP {
			return // already exists
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

func (e *Engine) saveSubnetEntry(entry SubnetEntry) {
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

// --- IP helpers ---

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func fileExistsFirewall(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func lastIPInRange(network *net.IPNet) net.IP {
	ip := network.IP.To4()
	if ip == nil {
		ip = network.IP.To16()
	}
	if ip == nil {
		return nil
	}
	mask := network.Mask
	last := make(net.IP, len(ip))
	for i := range ip {
		if i < len(mask) {
			last[i] = ip[i] | ^mask[i]
		} else {
			last[i] = ip[i]
		}
	}
	return last
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// loadCountryCIDRs reads CIDR ranges from a country file.
// Expected format: one CIDR per line in {dbPath}/{CODE}.cidr
func loadCountryCIDRs(dbPath, countryCode string) []nftables.SetElement {
	file := filepath.Join(dbPath, strings.ToUpper(countryCode)+".cidr")
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
