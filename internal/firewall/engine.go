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

	setBlocked *nftables.Set
	setAllowed *nftables.Set
	setInfra   *nftables.Set
	setCountry *nftables.Set

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
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	Port   int    `json:"port,omitempty"` // 0 = all ports
}

// FirewallState is persisted to disk for restore on restart.
type FirewallState struct {
	Blocked []BlockedEntry `json:"blocked"`
	Allowed []AllowedEntry `json:"allowed"`
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
	setAllowed, err := conn.GetSetByName(table, "allowed_ips")
	if err != nil {
		return nil, fmt.Errorf("allowed_ips set not found: %w", err)
	}
	setInfra, err := conn.GetSetByName(table, "infra_ips")
	if err != nil {
		return nil, fmt.Errorf("infra_ips set not found: %w", err)
	}

	return &Engine{
		conn:       conn,
		cfg:        cfg,
		table:      table,
		setBlocked: setBlocked,
		setAllowed: setAllowed,
		setInfra:   setInfra,
		statePath:  filepath.Join(statePath, "firewall"),
	}, nil
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

	// Allowed IPs set
	e.setAllowed = &nftables.Set{
		Table:   e.table,
		Name:    "allowed_ips",
		KeyType: nftables.TypeIPAddr,
	}
	if err := e.conn.AddSet(e.setAllowed, nil); err != nil {
		return fmt.Errorf("allowed set: %w", err)
	}

	// Infra IPs set (interval for CIDR support)
	e.setInfra = &nftables.Set{
		Table:    e.table,
		Name:     "infra_ips",
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}

	var infraElements []nftables.SetElement
	for _, cidr := range e.cfg.InfraIPs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 != nil {
				infraElements = append(infraElements,
					nftables.SetElement{Key: ip4},
					nftables.SetElement{Key: nextIP(ip4), IntervalEnd: true},
				)
			}
			continue
		}
		start := network.IP.To4()
		end := lastIPInRange(network)
		if start != nil && end != nil {
			infraElements = append(infraElements,
				nftables.SetElement{Key: start},
				nftables.SetElement{Key: nextIP(end), IntervalEnd: true},
			)
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

	// Rule 4: Drop blocked IPs (O(1) set lookup)
	e.addSetMatchRule(e.setBlocked, expr.VerdictDrop)

	// Rule 4: Allow infra IPs (all ports)
	e.addSetMatchRule(e.setInfra, expr.VerdictAccept)

	// Rule 5: Allow explicitly allowed IPs
	e.addSetMatchRule(e.setAllowed, expr.VerdictAccept)

	// Rule 6: ICMP echo-request only (type 8)
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}}, // ICMP
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0, // ICMP type field
				Len:          1,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{8}}, // echo-request
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Rule 7: SYN flood protection — rate limit initial SYN packets
	if e.cfg.SYNFloodProtection {
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP
				// Match SYN flag set, ACK flag not set (initial SYN only)
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x12}, Xor: []byte{0x00}},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
				// Drop when SYN rate exceeds 25/second (burst 100)
				&expr.Limit{Type: expr.LimitTypePkts, Rate: 25, Unit: expr.LimitTimeSecond, Burst: 100, Over: true},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	// Rule 8: New connection rate limit — drop excessive new connections
	if e.cfg.ConnRateLimit > 0 {
		burst := uint32(e.cfg.ConnRateLimit / 2)
		if burst < 5 {
			burst = 5
		}
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				// Match new connections only
				&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
				&expr.Bitwise{
					SourceRegister: 1, DestRegister: 1, Len: 4,
					Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
					Xor:  binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
				// Drop when new connection rate exceeds limit
				&expr.Limit{
					Type:  expr.LimitTypePkts,
					Rate:  uint64(e.cfg.ConnRateLimit),
					Unit:  expr.LimitTimeMinute,
					Burst: burst,
					Over:  true,
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

	// UDP flood protection — global rate limit on UDP packets
	if e.cfg.UDPFlood && e.cfg.UDPFloodRate > 0 {
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
				&expr.Limit{
					Type: expr.LimitTypePkts, Rate: uint64(e.cfg.UDPFloodRate),
					Unit: expr.LimitTimeSecond, Burst: burst, Over: true,
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

	return nil
}

// --- Helper methods ---

func (e *Engine) addSetMatchRule(set *nftables.Set, verdict expr.VerdictKind) {
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // source IP
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        set.Name,
				SetID:          set.ID,
			},
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

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv6 not yet supported: %s", ip)
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

	elem := []nftables.SetElement{{Key: ip4, Timeout: timeout}}
	if err := e.conn.SetAddElements(e.setBlocked, elem); err != nil {
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

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv6 not yet supported: %s", ip)
	}

	if err := e.conn.SetDeleteElements(e.setBlocked, []nftables.SetElement{{Key: ip4}}); err != nil {
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

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv6 not yet supported: %s", ip)
	}

	// Remove from blocked set + add to allowed set in same batch
	_ = e.conn.SetDeleteElements(e.setBlocked, []nftables.SetElement{{Key: ip4}})
	if err := e.conn.SetAddElements(e.setAllowed, []nftables.SetElement{{Key: ip4}}); err != nil {
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

// RemoveAllowIP removes an IP from the allowed set and state.
func (e *Engine) RemoveAllowIP(ip string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv6 not yet supported: %s", ip)
	}

	if err := e.conn.SetDeleteElements(e.setAllowed, []nftables.SetElement{{Key: ip4}}); err != nil {
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

	// Restore blocked IPs (skip expired)
	for _, entry := range state.Blocked {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			continue
		}
		parsed := net.ParseIP(entry.IP)
		if parsed == nil {
			continue
		}
		ip4 := parsed.To4()
		if ip4 == nil {
			continue
		}
		timeout := time.Duration(0)
		if !entry.ExpiresAt.IsZero() {
			timeout = time.Until(entry.ExpiresAt)
		}
		_ = e.conn.SetAddElements(e.setBlocked, []nftables.SetElement{{Key: ip4, Timeout: timeout}})
	}

	// Restore allowed IPs
	for _, entry := range state.Allowed {
		parsed := net.ParseIP(entry.IP)
		if parsed == nil {
			continue
		}
		ip4 := parsed.To4()
		if ip4 == nil {
			continue
		}
		_ = e.conn.SetAddElements(e.setAllowed, []nftables.SetElement{{Key: ip4}})
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
	mask := network.Mask
	last := make(net.IP, len(ip))
	for i := range ip {
		last[i] = ip[i] | ^mask[i]
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
