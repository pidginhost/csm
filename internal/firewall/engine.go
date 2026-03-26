//go:build linux

package firewall

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// Apply builds and atomically applies the complete nftables ruleset.
func (e *Engine) Apply() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Flush existing CSM table if it exists
	e.conn.FlushTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	_ = e.conn.Flush()

	// Create table
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

	// Apply atomically
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("applying ruleset: %w", err)
	}

	// Populate sets from state
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
		Timeout:    24 * time.Hour, // default timeout
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

	// Populate infra IPs from config
	var infraElements []nftables.SetElement
	for _, cidr := range e.cfg.InfraIPs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as plain IP
			ip := net.ParseIP(cidr)
			if ip != nil {
				ip4 := ip.To4()
				if ip4 != nil {
					infraElements = append(infraElements,
						nftables.SetElement{Key: ip4},
						nftables.SetElement{Key: nextIP(ip4), IntervalEnd: true},
					)
				}
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

	return nil
}

// createInputChain builds the input filter chain.
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

	// Rule 3: Drop blocked IPs (O(1) set lookup)
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        e.setBlocked.Name,
				SetID:          e.setBlocked.ID,
			},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	// Rule 4: Allow infra IPs (all ports)
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        e.setInfra.Name,
				SetID:          e.setInfra.ID,
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Rule 5: Allow explicitly allowed IPs
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        e.setAllowed.Name,
				SetID:          e.setAllowed.ID,
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Rule 6: ICMP rate limited
	e.addICMPRule()

	// Rule 7: Open TCP ports
	for _, port := range e.cfg.TCPIn {
		e.addPortAcceptRule(port, true)
	}

	// Rule 8: Open UDP ports
	for _, port := range e.cfg.UDPIn {
		e.addPortAcceptRule(port, false)
	}

	// Rule 9: Passive FTP range
	if e.cfg.PassiveFTPStart > 0 && e.cfg.PassiveFTPEnd > 0 {
		e.addPortRangeAcceptRule(e.cfg.PassiveFTPStart, e.cfg.PassiveFTPEnd, true)
	}

	// Rule 10: Log dropped packets (rate limited)
	if e.cfg.LogDropped {
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainIn,
			Exprs: []expr.Any{
				&expr.Log{Key: 1, Data: []byte("CSM-DROP: ")},
			},
		})
	}

	return nil
}

// createOutputChain builds the output filter chain (permissive by default).
func (e *Engine) createOutputChain() error {
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

func (e *Engine) addICMPRule() {
	// Allow ICMP echo-request (ping)
	e.conn.AddRule(&nftables.Rule{
		Table: e.table,
		Chain: e.chainIn,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{1}, // ICMP protocol
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
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
			// Match protocol
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{proto},
			},
			// Match destination port
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(port)),
			},
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
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{proto},
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpGte,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(startPort)),
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpLte,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(endPort)),
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
}

// BlockIP adds an IP to the blocked set with optional timeout.
func (e *Engine) BlockIP(ip string, reason string, timeout time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}

	elem := []nftables.SetElement{{
		Key:     parsed,
		Timeout: timeout,
	}}

	if err := e.conn.SetAddElements(e.setBlocked, elem); err != nil {
		return fmt.Errorf("adding to blocked set: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	// Persist to state
	e.appendBlockedState(BlockedEntry{
		IP:        ip,
		Reason:    reason,
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(timeout),
	})

	return nil
}

// UnblockIP removes an IP from the blocked set.
func (e *Engine) UnblockIP(ip string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}

	if err := e.conn.SetDeleteElements(e.setBlocked, []nftables.SetElement{{Key: parsed}}); err != nil {
		return fmt.Errorf("removing from blocked set: %w", err)
	}
	return e.conn.Flush()
}

// AllowIP adds an IP to the allowed set.
func (e *Engine) AllowIP(ip string, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}

	if err := e.conn.SetAddElements(e.setAllowed, []nftables.SetElement{{Key: parsed}}); err != nil {
		return fmt.Errorf("adding to allowed set: %w", err)
	}
	return e.conn.Flush()
}

// Status returns current firewall statistics.
func (e *Engine) Status() map[string]interface{} {
	return map[string]interface{}{
		"enabled":     e.cfg.Enabled,
		"tcp_in":      e.cfg.TCPIn,
		"udp_in":      e.cfg.UDPIn,
		"infra_ips":   e.cfg.InfraIPs,
		"log_dropped": e.cfg.LogDropped,
	}
}

// --- State persistence ---

func (e *Engine) loadState() error {
	stateFile := filepath.Join(e.statePath, "state.json")
	if !fileExistsFirewall(stateFile) {
		return nil
	}
	data, _ := os.ReadFile(stateFile)

	var state FirewallState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	now := time.Now()

	// Restore blocked IPs
	for _, entry := range state.Blocked {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			continue // expired
		}
		parsed := net.ParseIP(entry.IP).To4()
		if parsed == nil {
			continue
		}
		timeout := time.Duration(0)
		if !entry.ExpiresAt.IsZero() {
			timeout = time.Until(entry.ExpiresAt)
		}
		elem := []nftables.SetElement{{Key: parsed, Timeout: timeout}}
		_ = e.conn.SetAddElements(e.setBlocked, elem)
	}

	// Restore allowed IPs
	for _, entry := range state.Allowed {
		parsed := net.ParseIP(entry.IP).To4()
		if parsed == nil {
			continue
		}
		_ = e.conn.SetAddElements(e.setAllowed, []nftables.SetElement{{Key: parsed}})
	}

	return e.conn.Flush()
}

func (e *Engine) appendBlockedState(entry BlockedEntry) {
	path := filepath.Join(e.statePath, "state.json")
	var state FirewallState

	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, &state)
	}

	state.Blocked = append(state.Blocked, entry)

	newData, _ := json.MarshalIndent(state, "", "  ")
	tmpPath := path + ".tmp"
	_ = os.WriteFile(tmpPath, newData, 0600)
	_ = os.Rename(tmpPath, path)
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
