//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/pidginhost/csm/internal/atomicio"
)

// Engine manages the nftables firewall ruleset.
// Manages the nftables ruleset via netlink.
type Engine struct {
	mu   sync.Mutex
	conn *nftables.Conn
	cfg  *FirewallConfig

	// dryRunRecorder is called by BlockIP when auto_response.dry_run is
	// active. Set by SetDryRunRecorder after construction so the firewall
	// package does not import internal/store (which would be a cycle).
	dryRunRecorder func(ip, reason string, timeout time.Duration)
	// dryRunEnabled reports whether auto_response.dry_run is active.
	// Set by the daemon so this package does not import internal/config.
	dryRunEnabled func() bool
	// verdictAsker, when set, is consulted after local block validation and
	// before the dry-run gate. The callback returns (verdict, tenantID, note,
	// error). Verdict "allow" short-circuits the block; "block" or empty
	// proceeds with the default flow.
	// Errors are fail-open: the daemon proceeds with the default block and
	// logs the failure. Daemon owns the underlying verdict.Client; this
	// package stays free of the internal/verdict import.
	verdictAsker func(ctx context.Context, ip, reason string) (verdict, tenantID, note string, err error)

	// shutdownCtx, when set, scopes the lifetime of any in-flight verdict
	// callback to daemon shutdown. Without it, BlockIPOutcome used
	// context.Background() and a wedged panel callback kept the
	// auto-block caller waiting for the full http.Client.Timeout during
	// graceful restart. Nil falls back to context.Background() so unit
	// tests that build the Engine literal without a daemon keep working.
	shutdownCtx context.Context

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
	meterSYN        *nftables.Set
	meterConn       *nftables.Set
	meterUDP        *nftables.Set
	meterConnlim    *nftables.Set
	meterPortFlood4 map[string]*nftables.Set
	meterPortFlood6 map[string]*nftables.Set

	statePath string

	// Cached parsed firewall state. Population is lazy: the first call
	// to loadStateFile under e.mu reads + parses state.json once, then
	// subsequent calls return a deep copy from the in-memory cache as
	// long as the on-disk metadata key is unchanged.
	//
	// Before this cache existed, every single mutator (BlockIP,
	// AllowIP, saveBlockedEntry, etc.) reloaded and re-parsed the full
	// 325 KiB state.json from disk, and every IsBlocked / IsAllowed
	// call did a linear scan over the parsed slices. On a busy
	// production host that meant ~72 state.json opens per second
	// steady state, which showed up as the dominant CPU hot spot in
	// roadmap audit 7.1.
	//
	// All four fields are written only while e.mu is held. The index
	// maps are rebuilt every time stateCache is repopulated so
	// O(1) lookups stay coherent with the cached slices. blockedIPIndex
	// stores the slice position for each IP so saveBlockedEntry can
	// update in place without a linear dedup scan.
	stateCache       *FirewallState
	stateCacheKey    stateFileCacheKey
	blockedIPIndex   map[string]int
	allowedIPIndex   map[string]struct{}
	blockedCIDRIndex map[string]struct{}

	liveBlockLookup func(set *nftables.Set, key []byte) (bool, error)

	// liveBlockCounts, when non-nil, returns the live (perm, temp)
	// element counts across blocked v4 + v6 sets. Tests inject this
	// to avoid spinning up a real nft connection. Nil falls back to
	// GetSetElements queries.
	liveBlockCounts func() (perm, temp int, err error)

	// infraResolved maps a hostname declared under cfg.InfraIPs to its
	// last successfully-resolved set of IPs. blockIPTarget refuses to
	// block any of these so a transient DNS pause cannot let an
	// attacker block CSM's own panel hostname into a lockout. Mutated
	// under e.mu by UpdateInfraResolved / DropInfraResolved from the
	// DynDNS resolver.
	infraResolved map[string]map[string]struct{}

	// localAddrs caches the host's own non-loopback interface addresses.
	// The block guard refuses to block any of these regardless of
	// cfg.InfraIPs so a misconfigured config or a stray scan that loops
	// back to the daemon cannot brick the host. Refreshed lazily under
	// e.mu when localAddrsExpiresAt has elapsed.
	localAddrs          map[string]struct{}
	localAddrsExpiresAt time.Time
	// localAddrsLookup, when non-nil, replaces net.InterfaceAddrs() for
	// tests. Returning an error leaves the cache untouched.
	localAddrsLookup func() ([]string, error)
}

type stateFileCacheKey struct {
	modTime    time.Time
	changeTime time.Time
	size       int64
	dev        uint64
	ino        uint64
}

func stateFileCacheKeyFromInfo(info os.FileInfo) stateFileCacheKey {
	key := stateFileCacheKey{
		modTime: info.ModTime(),
		size:    info.Size(),
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		key.changeTime = time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
		key.dev = uint64(stat.Dev)
		key.ino = uint64(stat.Ino)
	}
	return key
}

func (k stateFileCacheKey) matches(info os.FileInfo) bool {
	other := stateFileCacheKeyFromInfo(info)
	return k.size == other.size &&
		k.dev == other.dev &&
		k.ino == other.ino &&
		k.modTime.Equal(other.modTime) &&
		k.changeTime.Equal(other.changeTime)
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

// SetDryRunRecorder installs a callback that is invoked by BlockIP whenever
// auto_response.dry_run is active. The daemon calls this after construction
// to wire in store.RecordDryRunBlock without creating an import cycle between
// internal/firewall and internal/store.
func (e *Engine) SetDryRunRecorder(fn func(ip, reason string, timeout time.Duration)) {
	e.mu.Lock()
	e.dryRunRecorder = fn
	e.mu.Unlock()
}

// SetDryRunEnabledFunc installs the callback BlockIP uses to decide whether
// auto_response.dry_run should intercept an automatic block. Nil means live.
func (e *Engine) SetDryRunEnabledFunc(fn func() bool) {
	e.mu.Lock()
	e.dryRunEnabled = fn
	e.mu.Unlock()
}

// SetVerdictAsker installs the verdict callback the daemon constructs at
// startup. Nil disables the verdict callback (the gate skips entirely).
func (e *Engine) SetVerdictAsker(fn func(ctx context.Context, ip, reason string) (string, string, string, error)) {
	e.mu.Lock()
	e.verdictAsker = fn
	e.mu.Unlock()
}

func (e *Engine) verdictAskerFn() func(ctx context.Context, ip, reason string) (string, string, string, error) {
	e.mu.Lock()
	fn := e.verdictAsker
	e.mu.Unlock()
	return fn
}

// SetShutdownContext installs a context whose cancellation aborts any
// in-flight verdict callback. The daemon ties this to its stopCh so a
// graceful shutdown does not have to wait for an unresponsive panel
// callback to return.
func (e *Engine) SetShutdownContext(ctx context.Context) {
	e.mu.Lock()
	e.shutdownCtx = ctx
	e.mu.Unlock()
}

func (e *Engine) verdictContext() context.Context {
	e.mu.Lock()
	ctx := e.shutdownCtx
	e.mu.Unlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// Apply builds and atomically applies the complete nftables ruleset.
// All operations (delete old table + create new table/rules +
// populate persisted block/allow entries) are batched into a single
// netlink transaction. If the flush fails, the kernel keeps whatever
// ruleset was running before - the server is never left without a
// firewall. Equally important: the new ruleset never appears with
// EMPTY blocked sets between the table-swap and the persisted-state
// load; an attacker IP from state.json is blocked from the moment
// the new table becomes the live one.
func (e *Engine) Apply() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Compute the elements to seed each set from persisted state
	// BEFORE touching nft. Pure computation; if state.json is
	// missing or malformed the slices stay empty and the new table
	// still applies (no firewall regression on a fresh install).
	initial := e.computeInitialBlockStateLocked()

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

	// Queue initial set elements from persisted state into the same
	// netlink batch as the table+set+chain creation above. Without
	// this, Apply previously Flushed an empty-set ruleset, then a
	// separate loadState() Flush populated the sets - leaving a
	// brief window where the new table existed without the
	// persisted blocks.
	if err := e.queueInitialBlockStateLocked(initial); err != nil {
		return fmt.Errorf("queueing initial firewall state: %w", err)
	}

	// Apply atomically - if this fails, nftables keeps whatever was running before
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("applying ruleset: %w", err)
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
				infraElements = appendIntervalSetElements(infraElements, ip4, ip4)
			} else if e.cfg.IPv6 {
				ip16 := ip.To16()
				infra6Elements = appendIntervalSetElements(infra6Elements, ip16, ip16)
			}
			continue
		}
		if network.IP.To4() != nil {
			start := network.IP.To4()
			end := lastIPInRange(network)
			if start != nil && end != nil {
				infraElements = appendIntervalSetElements(infraElements, start, end)
			}
		} else if e.cfg.IPv6 {
			start := network.IP.To16()
			end := lastIPInRange(network)
			if start != nil && end != nil {
				infra6Elements = appendIntervalSetElements(infra6Elements, start, end)
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
	if portFloodNeedsMeter(e.cfg.PortFlood) {
		e.meterPortFlood4 = make(map[string]*nftables.Set)
		if e.cfg.IPv6 {
			e.meterPortFlood6 = make(map[string]*nftables.Set)
		}
		for _, pf := range e.cfg.PortFlood {
			if !usablePortFloodRule(pf) {
				continue
			}
			name4 := portFloodMeterName(pf, portFloodIPv4)
			if _, ok := e.meterPortFlood4[name4]; !ok {
				set := &nftables.Set{
					Table: e.table, Name: name4, KeyType: nftables.TypeIPAddr,
					Dynamic: true, HasTimeout: true, Timeout: time.Minute,
				}
				_ = e.conn.AddSet(set, nil)
				e.meterPortFlood4[name4] = set
			}
			if e.cfg.IPv6 {
				name6 := portFloodMeterName(pf, portFloodIPv6)
				if _, ok := e.meterPortFlood6[name6]; !ok {
					set := &nftables.Set{
						Table: e.table, Name: name6, KeyType: nftables.TypeIP6Addr,
						Dynamic: true, HasTimeout: true, Timeout: time.Minute,
					}
					_ = e.conn.AddSet(set, nil)
					e.meterPortFlood6[name6] = set
				}
			}
		}
	}

	return nil
}

// portFloodNeedsMeter reports whether any port_flood rule has a usable rate,
// so the meter set is only created when at least one rule will reference it.
func portFloodNeedsMeter(rules []PortFloodRule) bool {
	for _, pf := range rules {
		if usablePortFloodRule(pf) {
			return true
		}
	}
	return false
}

func usablePortFloodRule(pf PortFloodRule) bool {
	return pf.Hits > 0 && pf.Seconds > 0 && pf.Port > 0
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

	// Rule 1: Allow loopback
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

	// Rule 2: Drop INVALID conntrack state (malformed packets)
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

	// Rule 3: Allow infra IPs FIRST - infra must NEVER be blocked, even accidentally
	e.addSetMatchRule(e.setInfra, expr.VerdictAccept)
	e.addSetMatchRuleV6(e.setInfra6, expr.VerdictAccept)

	// Rule 4: Cloudflare IP whitelist - accept on TCP 80/443 only.
	// CF IPs can still be blocked on other ports (unlike infra).
	e.addCFWhitelistRule(e.setCFWhitelist, false)
	e.addCFWhitelistRule(e.setCFWhitelist6, true)

	// Rule 5: Drop blocked IPs before established/related so active
	// keep-alive connections do not bypass a new block.
	e.addSetMatchRule(e.setBlocked, expr.VerdictDrop)
	e.addSetMatchRuleV6(e.setBlocked6, expr.VerdictDrop)

	// Rule 6: Drop blocked subnets (interval set for CIDR ranges)
	e.addSetMatchRule(e.setBlockedNet, expr.VerdictDrop)
	e.addSetMatchRuleV6(e.setBlockedNet6, expr.VerdictDrop)

	// Rule 7: Allow established/related connections after block checks.
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

	// Rule 8: Allow explicitly allowed IPs
	e.addSetMatchRule(e.setAllowed, expr.VerdictAccept)
	e.addSetMatchRuleV6(e.setAllowed6, expr.VerdictAccept)

	// Rule 9: Port-specific allows (IP+port, e.g. MySQL access for specific IPs)
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

	// Per-port flood protection - rate-limit new connections per source IP.
	// Each rule has separate IPv4 and IPv6 meters so ports and families do not
	// consume each other's token buckets.
	for _, pf := range e.cfg.PortFlood {
		items := []struct {
			family portFloodIPFamily
			meter  *nftables.Set
		}{
			{family: portFloodIPv4, meter: e.meterPortFlood4[portFloodMeterName(pf, portFloodIPv4)]},
		}
		if e.cfg.IPv6 {
			items = append(items, struct {
				family portFloodIPFamily
				meter  *nftables.Set
			}{family: portFloodIPv6, meter: e.meterPortFlood6[portFloodMeterName(pf, portFloodIPv6)]})
		}
		for _, item := range items {
			exprs := buildPortFloodExprs(pf, item.meter, item.family)
			if exprs == nil {
				continue
			}
			e.conn.AddRule(&nftables.Rule{
				Table: e.table,
				Chain: e.chainIn,
				Exprs: exprs,
			})
		}
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

	// SMTP block - restrict outbound mail to allowed users only.
	// resolveSMTPAllowedUIDs unconditionally includes root and mailnull
	// (exim's queue runner); without mailnull on the allow list queued
	// mail is silently dropped while CSM still reports healthy.
	smtpBlocked := make(map[int]bool)
	if e.cfg.SMTPBlock && len(e.cfg.SMTPPorts) > 0 {
		allowedUIDs := resolveSMTPAllowedUIDs(e.cfg.SMTPAllowUsers)

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
//
// Thin wrapper over BlockIPOutcome that discards the outcome. Existing
// callers that only need success/error semantics keep working; auto-
// response callers should use BlockIPOutcome so they can suppress local
// side effects (state mutation, AUTO-BLOCK alert) when the kernel was
// not actually touched.
func (e *Engine) BlockIP(ip string, reason string, timeout time.Duration) error {
	_, err := e.BlockIPOutcome(ip, reason, timeout)
	return err
}

// BlockIPOutcome is the AUTO-RESPONSE entry point. It performs the same
// guards, verdict-callback consultation, and dry-run gating as BlockIP,
// but additionally reports which path was taken via BlockOutcome so the
// caller can decide whether to record local state. See the BlockOutcome
// godoc for the meaning of each return value.
//
// Operator-initiated commands (csm firewall block, Web UI manual block) must
// call BlockIPForce instead, which skips the dry-run gate unconditionally.
func (e *Engine) BlockIPOutcome(ip string, reason string, timeout time.Duration) (BlockOutcome, error) {
	// Local safety checks always run before consulting the external callback.
	// The callback can downgrade a block decision, but it cannot bypass
	// malformed-IP, IPv6-disabled, infra-IP, or block-limit guards.
	alreadyBlocked, err := e.validateBlockIP(ip, timeout, true)
	if err != nil {
		return BlockOutcomeNoop, err
	}
	if alreadyBlocked {
		return BlockOutcomeNoop, nil
	}

	// Verdict gate: consult the panel after local validation and before the
	// dry-run gate so that an "allow" verdict short-circuits everything.
	// Fail-open: errors proceed with the default block. Nil callback skips
	// the gate entirely.
	if asker := e.verdictAskerFn(); asker != nil {
		v, tenant, note, err := asker(e.verdictContext(), ip, reason)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "[%s] verdict callback failed for %s: %v - proceeding with default block\n",
				time.Now().Format("2006-01-02 15:04:05"), ip, err)
		case v == "allow":
			fmt.Fprintf(os.Stderr, "[%s] verdict callback returned allow for %s (tenant=%q note=%q) - not blocking\n",
				time.Now().Format("2006-01-02 15:04:05"), ip, tenant, note)
			return BlockOutcomeAllowed, nil
		case tenant != "" || note != "":
			fmt.Fprintf(os.Stderr, "[%s] verdict callback returned block for %s (tenant=%q note=%q) - proceeding with default block\n",
				time.Now().Format("2006-01-02 15:04:05"), ip, tenant, note)
		}
		// "block" / empty / error -> proceed with default flow.
	}

	// Dry-run gate: the daemon callback reads the current daemon config at
	// call time so a SIGHUP takes effect without a daemon restart. Nil
	// callback means live.
	if e.autoResponseDryRunEnabled() {
		fmt.Fprintf(os.Stderr, "[%s] auto_response dry_run: would have blocked %s (%s)\n",
			time.Now().Format("2006-01-02 15:04:05"), ip, reason)
		e.recordDryRunBlock(ip, reason, timeout)
		return BlockOutcomeDryRun, nil
	}
	if err := e.blockIPLocked(ip, reason, timeout, true); err != nil {
		return BlockOutcomeNoop, err
	}
	return BlockOutcomeLive, nil
}

func (e *Engine) autoResponseDryRunEnabled() bool {
	e.mu.Lock()
	fn := e.dryRunEnabled
	e.mu.Unlock()
	return fn != nil && fn()
}

// BlockIPForce adds an IP to the blocked set unconditionally, bypassing the
// auto_response.dry_run gate. Use this for operator-initiated commands (CLI,
// Web UI manual block) where the operator has explicitly decided to block.
func (e *Engine) BlockIPForce(ip string, reason string, timeout time.Duration) error {
	return e.blockIPLocked(ip, reason, timeout, false)
}

// PromoteToPermanentBlock upgrades an existing temporary block on ip to a
// permanent one: it clears the kernel timeout by deleting the timed element
// and re-adding it without a timeout, and zeroes ExpiresAt in state. The
// ordinary block path cannot do this during PermBlock escalation because it
// skips an already-blocked IP, so the kernel timeout would otherwise expire
// the block the operator wanted made permanent. Returns an error if the IP is
// not currently blocked (nothing to promote).
func (e *Engine) PromoteToPermanentBlock(ip, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	targetSet, key, err := e.resolveIPSet(ip, e.setBlocked, e.setBlocked6)
	if err != nil {
		return err
	}

	priorState := e.loadStateFile()
	entry := BlockedEntry{IP: ip, Reason: reason, Source: SourceSystem, BlockedAt: time.Now()}
	found := false
	wasTemporary := false
	for _, b := range priorState.Blocked {
		if b.IP == ip {
			found = true
			wasTemporary = !b.ExpiresAt.IsZero()
			entry.BlockedAt = b.BlockedAt
			if b.Source != "" {
				entry.Source = b.Source
			}
			break
		}
	}
	if !found {
		return fmt.Errorf("cannot promote %s: not currently blocked", ip)
	}
	if e.cfg != nil && wasTemporary && e.cfg.DenyIPLimit > 0 {
		perm, _, ok := e.livePermTempCountsLocked(priorState)
		if !ok {
			perm = countPermanentBlockedEntries(priorState)
		}
		if perm >= e.cfg.DenyIPLimit {
			return fmt.Errorf("permanent deny limit reached (%d)", e.cfg.DenyIPLimit)
		}
	}
	// ExpiresAt left zero: permanent.
	nextState := copyFirewallState(priorState)
	upsertBlockedEntryInState(&nextState, entry)
	if err := e.saveState(&nextState); err != nil {
		return fmt.Errorf("persisting permanent promotion for %s: %w", ip, err)
	}

	// Delete the timed element and re-add it without a timeout in one
	// transaction, so the address is never unblocked in between.
	if err := e.conn.SetDeleteElements(targetSet, []nftables.SetElement{{Key: key}}); err != nil {
		if restoreErr := e.restoreBlockStateAfterFailureLocked(priorState, ip); restoreErr != nil {
			return fmt.Errorf("promoting %s: delete timed element: %w (state restore failed: %v)", ip, err, restoreErr)
		}
		return fmt.Errorf("promoting %s: delete timed element: %w", ip, err)
	}
	if err := e.conn.SetAddElements(targetSet, []nftables.SetElement{{Key: key}}); err != nil {
		if restoreErr := e.restoreBlockStateAfterFailureLocked(priorState, ip); restoreErr != nil {
			return fmt.Errorf("promoting %s: re-add permanent element: %w (state restore failed: %v)", ip, err, restoreErr)
		}
		return fmt.Errorf("promoting %s: re-add permanent element: %w", ip, err)
	}
	if err := e.conn.Flush(); err != nil {
		if restoreErr := e.restoreBlockStateAfterFailureLocked(priorState, ip); restoreErr != nil {
			return fmt.Errorf("promoting %s: flush: %w (state restore failed: %v)", ip, err, restoreErr)
		}
		return fmt.Errorf("promoting %s: flush: %w", ip, err)
	}
	AppendAudit(e.statePath, "permblock", ip, reason, entry.Source, 0)
	return nil
}

// recordDryRunBlock persists a dry-run record through the daemon-installed
// recorder so operators can review the count via /api/v1/status.
// No-op when no recorder is installed.
func (e *Engine) recordDryRunBlock(ip, reason string, timeout time.Duration) {
	e.mu.Lock()
	recorder := e.dryRunRecorder
	e.mu.Unlock()
	if recorder != nil {
		recorder(ip, reason, timeout)
	}
}

// blockIPLocked is the real implementation called by both BlockIP and BlockIPForce.
func (e *Engine) blockIPLocked(ip string, reason string, timeout time.Duration, skipExisting bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	targetSet, key, alreadyBlocked, evictTempIP, err := e.blockIPTarget(ip, timeout, skipExisting)
	if err != nil {
		return err
	}
	if alreadyBlocked {
		return nil
	}

	// Persist to state BEFORE adding the kernel element. state.json is the
	// seed source on the next Apply, so a crash after this point but before the
	// kernel add leaves a durable record that Apply re-applies. The previous
	// ordering (kernel first, then state) left a window where a process kill
	// produced a permanent kernel block with no state row: it never expired
	// (timeout 0) yet a later state-seeded Apply would silently drop it.
	// Zero ExpiresAt means permanent.
	entry := BlockedEntry{
		IP:        ip,
		Reason:    reason,
		Source:    InferProvenance("block", reason),
		BlockedAt: time.Now(),
	}
	if timeout > 0 {
		entry.ExpiresAt = time.Now().Add(timeout)
	}

	var evictSet *nftables.Set
	var evictKey []byte
	if evictTempIP != "" {
		evictSet, evictKey, err = e.resolveIPSet(evictTempIP, e.setBlocked, e.setBlocked6)
		if err != nil {
			return fmt.Errorf("resolving temp block eviction target %s: %w", evictTempIP, err)
		}
	}

	priorState := e.loadStateFile()
	nextState := copyFirewallState(priorState)
	if evictTempIP != "" {
		removeBlockedIPFromState(&nextState, evictTempIP)
	}
	upsertBlockedEntryInState(&nextState, entry)
	if err := e.saveState(&nextState); err != nil {
		return fmt.Errorf("persisting block for %s: %w", ip, err)
	}

	elem := []nftables.SetElement{{Key: key, Timeout: timeout}}
	if err := e.conn.SetAddElements(targetSet, elem); err != nil {
		if restoreErr := e.restoreBlockStateAfterFailureLocked(priorState, ip); restoreErr != nil {
			return fmt.Errorf("adding to blocked set: %w (state restore failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("adding to blocked set: %w", err)
	}
	if evictTempIP != "" {
		if err := e.conn.SetDeleteElements(evictSet, []nftables.SetElement{{Key: evictKey}}); err != nil {
			if restoreErr := e.restoreBlockStateAfterFailureLocked(priorState, ip); restoreErr != nil {
				return fmt.Errorf("evicting temp block %s: %w (state restore failed: %v)", evictTempIP, err, restoreErr)
			}
			return fmt.Errorf("evicting temp block %s: %w", evictTempIP, err)
		}
	}
	if err := e.conn.Flush(); err != nil {
		if restoreErr := e.restoreBlockStateAfterFailureLocked(priorState, ip); restoreErr != nil {
			return fmt.Errorf("flushing: %w (state restore failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("flushing: %w", err)
	}
	if evictTempIP != "" {
		AppendAudit(e.statePath, "evict_temp", evictTempIP, "temp deny limit reached; evicted soonest-expiring entry", SourceSystem, 0)
	}
	AppendAudit(e.statePath, "block", ip, reason, entry.Source, timeout)

	return nil
}

func (e *Engine) validateBlockIP(ip string, timeout time.Duration, skipExisting bool) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _, alreadyBlocked, _, err := e.blockIPTarget(ip, timeout, skipExisting)
	return alreadyBlocked, err
}

func (e *Engine) blockIPTarget(ip string, timeout time.Duration, skipExisting bool) (*nftables.Set, []byte, bool, string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, nil, false, "", fmt.Errorf("invalid IP: %s", ip)
	}

	// SAFETY: never block infra IPs - prevents admin lockout.
	// Runs before resolveIPSet so that an IPv6-disabled config (set6 == nil)
	// cannot bypass the infra guard when the caller passes the canonical
	// IPv6 form of a listed infra address.
	for _, cidr := range e.cfg.InfraIPs {
		_, network, cidrErr := net.ParseCIDR(cidr)
		if cidrErr != nil {
			if infraIP := net.ParseIP(cidr); infraIP != nil && infraIP.String() == parsed.String() {
				return nil, nil, false, "", fmt.Errorf("refusing to block infra IP: %s", ip)
			}
			continue
		}
		if network.Contains(parsed) {
			return nil, nil, false, "", fmt.Errorf("refusing to block infra IP: %s (in %s)", ip, cidr)
		}
	}
	// Hostnames in cfg.InfraIPs are resolved by the DynDNS loop and
	// pushed in via UpdateInfraResolved. Without this check a hostname
	// listed as infra would only be honoured when the operator also
	// pinned the IP, so a moving panel IP would silently drop out of
	// the lockout guard.
	if host, ok := e.infraIPResolvedHostLocked(ip); ok {
		return nil, nil, false, "", fmt.Errorf("refusing to block infra IP: %s (resolved from %s)", ip, host)
	}
	// Daemon's own interface addresses are always off-limits. Without
	// this guard a stray request from the host to itself (cron, panel
	// callback, internal probe) could trigger an auto-block that
	// firewalls every customer hosted on the same IP.
	if e.isLocalAddrLocked(ip) {
		return nil, nil, false, "", fmt.Errorf("refusing to block local host IP: %s (own interface address)", ip)
	}

	targetSet, key, err := e.resolveIPSet(ip, e.setBlocked, e.setBlocked6)
	if err != nil {
		return nil, nil, false, "", err
	}

	st := e.loadStateFile()
	cachedBlockMissingLive := false
	if skipExisting && firewallStateHasBlocked(st, ip) {
		liveBlocked, liveErr := e.isBlockedLiveLocked(ip)
		if liveErr != nil || liveBlocked {
			// Treat a probe error as "still blocked" so we never demote a
			// cached block on transient netlink trouble. Returning nil
			// here is intentional and the conservative posture.
			return targetSet, key, true, "", nil //nolint:nilerr // intentional fail-safe on netlink probe error
		}
		cachedBlockMissingLive = true
	}

	// Enforce deny IP limits. Prefer counts from the live nft set
	// so an entry the kernel already expired no longer counts
	// against the cap. Fall back to the cached state.json count
	// (existing behaviour) if the live query is unavailable.
	if e.cfg.DenyIPLimit > 0 || e.cfg.DenyTempIPLimit > 0 {
		perm, temp, ok := e.livePermTempCountsLocked(st)
		if !ok {
			perm, temp = 0, 0
			for _, b := range st.Blocked {
				if cachedBlockMissingLive && b.IP == ip {
					continue
				}
				if b.ExpiresAt.IsZero() {
					perm++
				} else {
					temp++
				}
			}
		}
		if timeout == 0 && e.cfg.DenyIPLimit > 0 && perm >= e.cfg.DenyIPLimit {
			return nil, nil, false, "", fmt.Errorf("permanent deny limit reached (%d)", e.cfg.DenyIPLimit)
		}
		if timeout > 0 && e.cfg.DenyTempIPLimit > 0 && temp >= e.cfg.DenyTempIPLimit {
			// Validation must stay read-only because verdict and dry-run gates run
			// after it. The live block path applies this eviction target.
			victim, ok := soonestExpiringTempIP(st, ip)
			if !ok {
				return nil, nil, false, "", fmt.Errorf("temporary deny limit reached (%d) and no temp entry to evict", e.cfg.DenyTempIPLimit)
			}
			if _, _, err := e.resolveIPSet(victim, e.setBlocked, e.setBlocked6); err != nil {
				return nil, nil, false, "", fmt.Errorf("temporary deny limit reached (%d) and eviction target %s is unusable: %w", e.cfg.DenyTempIPLimit, victim, err)
			}
			return targetSet, key, false, victim, nil
		}
	}

	return targetSet, key, false, "", nil
}

// soonestExpiringTempIP returns the IP of the temporary block closest to
// expiry, skipping permanent blocks and excludeIP. Pure helper so the
// eviction policy is unit-testable without nftables.
func soonestExpiringTempIP(st FirewallState, excludeIP string) (string, bool) {
	var best string
	var bestExp time.Time
	found := false
	for _, b := range st.Blocked {
		if b.IP == excludeIP || b.ExpiresAt.IsZero() {
			continue
		}
		if !found || b.ExpiresAt.Before(bestExp) {
			best, bestExp, found = b.IP, b.ExpiresAt, true
		}
	}
	return best, found
}

func firewallStateHasBlocked(state FirewallState, ip string) bool {
	for _, entry := range state.Blocked {
		if entry.IP == ip {
			return true
		}
	}
	return false
}

func countPermanentBlockedEntries(state FirewallState) int {
	count := 0
	for _, entry := range state.Blocked {
		if entry.ExpiresAt.IsZero() {
			count++
		}
	}
	return count
}

// UnblockIP removes an IP from the blocked set and state.
func (e *Engine) UnblockIP(ip string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	targetSet, key, err := e.resolveIPSet(ip, e.setBlocked, e.setBlocked6)
	if err != nil {
		return err
	}

	// Remove from state BEFORE the kernel delete: a crash between the two
	// must converge to the operator's intent (unblocked) on the next Apply,
	// not silently re-block the IP from a stale state row. On kernel failure
	// the prior state is restored so the entry stays visible for a retry.
	priorState := e.loadStateFile()
	nextState := copyFirewallState(priorState)
	removeBlockedIPFromState(&nextState, ip)
	if err := e.saveState(&nextState); err != nil {
		return fmt.Errorf("persisting unblock for %s: %w", ip, err)
	}

	if err := e.conn.SetDeleteElements(targetSet, []nftables.SetElement{{Key: key}}); err != nil {
		if restoreErr := e.saveState(&priorState); restoreErr != nil {
			return fmt.Errorf("removing from blocked set: %w (state restore failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("removing from blocked set: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		if isNftNotFound(err) {
			// The delete target already disappeared from nft, so the
			// persisted unblock is the only remaining state to keep.
			AppendAudit(e.statePath, "unblock", ip, "", "", 0)
			return nil
		}
		if restoreErr := e.saveState(&priorState); restoreErr != nil {
			return fmt.Errorf("flushing: %w (state restore failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("flushing: %w", err)
	}

	AppendAudit(e.statePath, "unblock", ip, "", "", 0)

	return nil
}

// IsBlocked returns true if the IP is currently in the engine's blocked state.
// Uses the persisted state file (which is cleaned of expired entries on load).
//
// The lookup is O(1) via the blockedIPIndex map populated from the
// cached state. Linear scans over the parsed slice are gone -- on
// hosts with hundreds of persisted blocks the scan was the dominant
// cost of every connection-handler IsBlocked check.
func (e *Engine) IsBlocked(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ensureStateCacheLocked()
	_, ok := e.blockedIPIndex[ip]
	return ok
}

// IsBlockedLive queries the live nftables set, not the in-memory cache built
// from state.json. The cache can drift from the kernel when nft auto-expires
// entries faster than CSM rewrites state.json, or when an out-of-band flush
// happens. Reconcile loops should consult this method so the local tracker
// shrinks in lock-step with the kernel; per-packet hot paths should stay on
// IsBlocked since this issues a netlink RTT.
//
// Malformed IPs are reported as absent. Netlink and engine-initialization
// failures are returned so callers can keep their cached answer instead of
// deleting local state on a transient lookup failure.
func (e *Engine) IsBlockedLive(ip string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isBlockedLiveLocked(ip)
}

// livePermTempCountsLocked returns the count of permanent and temporary
// entries across the blocked v4 + v6 nft sets. Used by blockIPTarget so
// the deny limits trip against the kernel's actual state instead of
// stale state.json entries that the kernel already expired. Live keys
// that still exist in CSM state are classified from state because nft
// timeout attributes can reflect inherited/default set behaviour rather
// than the operator's block intent. Out-of-state live keys fall back to
// the kernel expiration attributes.
//
// Must be called with e.mu held; blockIPTarget already holds the lock
// at the only call site.
func (e *Engine) livePermTempCountsLocked(state FirewallState) (perm, temp int, ok bool) {
	if e.liveBlockCounts != nil {
		p, t, err := e.liveBlockCounts()
		if err != nil {
			return 0, 0, false
		}
		return p, t, true
	}
	if e.conn == nil {
		return 0, 0, false
	}
	stateTempByIP := blockedStateTempByIP(state)
	gotAny := false
	for _, set := range []*nftables.Set{e.setBlocked, e.setBlocked6} {
		if set == nil {
			continue
		}
		elements, err := e.conn.GetSetElements(set)
		if err != nil {
			return 0, 0, false
		}
		gotAny = true
		p, t := countLiveBlockElements(elements, stateTempByIP)
		perm += p
		temp += t
	}
	if !gotAny {
		return 0, 0, false
	}
	return perm, temp, true
}

func blockedStateTempByIP(state FirewallState) map[string]bool {
	byIP := make(map[string]bool, len(state.Blocked)*2)
	for _, entry := range state.Blocked {
		if entry.IP == "" {
			continue
		}
		temp := !entry.ExpiresAt.IsZero()
		byIP[entry.IP] = temp
		if parsed := net.ParseIP(entry.IP); parsed != nil {
			byIP[parsed.String()] = temp
		}
	}
	return byIP
}

func countLiveBlockElements(elements []nftables.SetElement, stateTempByIP map[string]bool) (perm, temp int) {
	for _, el := range elements {
		if ip, ok := setElementIPString(el.Key); ok {
			if stateTemp, found := stateTempByIP[ip]; found {
				if stateTemp {
					temp++
				} else {
					perm++
				}
				continue
			}
		}
		if el.Timeout > 0 || el.Expires > 0 {
			temp++
		} else {
			perm++
		}
	}
	return perm, temp
}

func setElementIPString(key []byte) (string, bool) {
	switch len(key) {
	case net.IPv4len:
		return net.IP(key).String(), true
	case net.IPv6len:
		return net.IP(key).String(), true
	default:
		return "", false
	}
}

func (e *Engine) isBlockedLiveLocked(ip string) (bool, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, nil
	}
	var (
		set *nftables.Set
		key []byte
	)
	if ip4 := parsed.To4(); ip4 != nil {
		set = e.setBlocked
		key = ip4
	} else {
		set = e.setBlocked6
		key = parsed.To16()
	}
	if set == nil {
		return false, fmt.Errorf("blocked set unavailable for %s", ip)
	}
	if e.liveBlockLookup != nil {
		return e.liveBlockLookup(set, key)
	}
	if e.conn == nil {
		return false, fmt.Errorf("nftables connection unavailable")
	}
	elements, err := e.conn.GetSetElements(set)
	if err != nil {
		return false, fmt.Errorf("listing blocked set: %w", err)
	}
	for _, el := range elements {
		if bytes.Equal(el.Key, key) {
			return true, nil
		}
	}
	return false, nil
}

// AllowIP adds an IP to the allowed set and persists it.
// If the IP is currently blocked, the block is removed first.
func (e *Engine) AllowIP(ip string, reason string) error {
	return e.allowIP(ip, reason, 0, "allow")
}

// TempAllowIP adds a temporary allow with expiry. Uses the same allowed set
// but tracks expiry in state - CleanExpiredAllows removes them periodically.
func (e *Engine) TempAllowIP(ip string, reason string, timeout time.Duration) error {
	return e.allowIP(ip, reason, timeout, "temp_allow")
}

func (e *Engine) allowIP(ip string, reason string, timeout time.Duration, action string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	blockedSet, blockedKey, _ := e.resolveIPSet(ip, e.setBlocked, e.setBlocked6)
	allowedSet, allowedKey, err := e.resolveIPSet(ip, e.setAllowed, e.setAllowed6)
	if err != nil {
		return err
	}
	if allowedSet == nil {
		return fmt.Errorf("allowed set unavailable for %s", ip)
	}

	entry := AllowedEntry{IP: ip, Reason: reason, Source: InferProvenance(action, reason)}
	if action == "temp_allow" && timeout > 0 {
		entry.ExpiresAt = time.Now().Add(timeout)
	}

	priorState := e.loadStateFile()
	nextState := copyFirewallState(priorState)
	removeBlockedIPFromState(&nextState, ip)
	upsertAllowedEntryInState(&nextState, entry)
	if err := e.saveState(&nextState); err != nil {
		return fmt.Errorf("persisting %s for %s: %w", action, ip, err)
	}

	if blockedSet != nil {
		if err := e.conn.SetDeleteElements(blockedSet, []nftables.SetElement{{Key: blockedKey}}); err != nil {
			if restoreErr := e.saveState(&priorState); restoreErr != nil {
				return fmt.Errorf("removing from blocked set: %w (state restore failed: %v)", err, restoreErr)
			}
			logNftSetOpErr(action+" remove from blocked", ip, err)
			return fmt.Errorf("removing from blocked set: %w", err)
		}
	}
	if err := e.conn.SetAddElements(allowedSet, []nftables.SetElement{{Key: allowedKey}}); err != nil {
		if restoreErr := e.saveState(&priorState); restoreErr != nil {
			return fmt.Errorf("adding to allowed set: %w (state restore failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("adding to allowed set: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		retryErr := e.retryAllowAfterBenignFlushError(blockedSet, blockedKey, allowedSet, allowedKey, err)
		if retryErr == nil {
			AppendAudit(e.statePath, action, ip, reason, entry.Source, timeout)
			return nil
		}
		if restoreErr := e.saveState(&priorState); restoreErr != nil {
			return fmt.Errorf("flushing: %w (state restore failed: %v)", err, restoreErr)
		}
		if isNftNotFound(err) {
			return fmt.Errorf("flushing: %w (retry failed: %v)", err, retryErr)
		}
		return fmt.Errorf("flushing: %w", err)
	}

	AppendAudit(e.statePath, action, ip, reason, entry.Source, timeout)

	return nil
}

func (e *Engine) retryAllowAfterBenignFlushError(blockedSet *nftables.Set, blockedKey []byte, allowedSet *nftables.Set, allowedKey []byte, flushErr error) error {
	if !isNftNotFound(flushErr) {
		return flushErr
	}
	if blockedSet != nil {
		if err := e.conn.SetDeleteElements(blockedSet, []nftables.SetElement{{Key: blockedKey}}); err != nil {
			return fmt.Errorf("retry removing from blocked set: %w", err)
		}
		if err := e.conn.Flush(); err != nil && !isNftNotFound(err) {
			return fmt.Errorf("retry flushing blocked delete: %w", err)
		}
	}
	if err := e.conn.SetAddElements(allowedSet, []nftables.SetElement{{Key: allowedKey}}); err != nil {
		return fmt.Errorf("retry adding to allowed set: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("retry flushing allowed add: %w", err)
	}
	return nil
}

// CleanExpiredAllows removes expired temporary allows from the set and state.
// An IP is only removed from nftables if no non-expired entries remain for it.
// Called periodically by the daemon.
func (e *Engine) CleanExpiredAllows() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	state, ok := e.loadStateFileRawLocked()
	if !ok {
		return 0
	}
	now := time.Now()
	var active []AllowedEntry
	expiredIPs := make(map[string]bool)
	var expired []AllowedEntry
	removed := 0

	for _, entry := range state.Allowed {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			expiredIPs[entry.IP] = true
			expired = append(expired, entry)
			removed++
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
		queueFailedIPs := make(map[string]bool)
		queuedDeletes := false
		for ip := range expiredIPs {
			if !activeIPs[ip] {
				if set, key, err := e.resolveIPSet(ip, e.setAllowed, e.setAllowed6); err == nil {
					if err := e.conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}}); err != nil {
						logNftSetOpErr("CleanExpiredAllows remove", ip, err)
						queueFailedIPs[ip] = true
					} else {
						queuedDeletes = true
					}
				}
			}
		}
		if queuedDeletes {
			if err := e.conn.Flush(); err != nil {
				// The netlink batch is atomic: a failed flush applied nothing,
				// so keep every expired row in state and retry next tick.
				fmt.Fprintf(os.Stderr, "firewall: nft flush after expired-allow cleanup failed: %v\n", err)
				return 0
			}
		}
		// Drop state rows whose kernel element was removed (or had none to
		// remove). Rows whose queue op failed stay in state so the next tick
		// retries the kernel delete instead of wedging forever: the previous
		// all-or-nothing handling kept already-flushed deletes in state, and
		// re-deleting their missing elements failed every following tick.
		dropped := make([]AllowedEntry, 0, len(expired))
		for _, entry := range expired {
			if queueFailedIPs[entry.IP] {
				active = append(active, entry)
				continue
			}
			dropped = append(dropped, entry)
		}
		state.Allowed = active
		_ = e.saveState(&state)
		for _, entry := range dropped {
			AppendAudit(e.statePath, "temp_allow_expired", entry.IP, "", SourceSystem, 0)
		}
		return len(dropped)
	}
	return removed
}

// CleanExpiredSubnets removes expired temporary subnet blocks from nftables and state.
func (e *Engine) CleanExpiredSubnets() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	state, ok := e.loadStateFileRawLocked()
	if !ok {
		return 0
	}
	now := time.Now()
	var active []SubnetEntry
	var expired []SubnetEntry
	removed := 0
	queueFailedCIDRs := make(map[string]bool)
	queuedDeletes := false

	for _, entry := range state.BlockedNet {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			if _, network, err := net.ParseCIDR(entry.CIDR); err == nil {
				if set, start, end := e.resolveSubnetSet(network); set != nil {
					if elements := intervalSetElements(start, end); len(elements) > 0 {
						if err := e.conn.SetDeleteElements(set, elements); err != nil {
							logNftSetOpErr("CleanExpiredSubnets remove", entry.CIDR, err)
							queueFailedCIDRs[entry.CIDR] = true
						} else {
							queuedDeletes = true
						}
					}
				}
			}
			expired = append(expired, entry)
			removed++
			continue
		}
		active = append(active, entry)
	}

	if removed > 0 {
		if queuedDeletes {
			if err := e.conn.Flush(); err != nil {
				// The netlink batch is atomic: a failed flush applied nothing,
				// so keep every expired row in state and retry next tick.
				fmt.Fprintf(os.Stderr, "firewall: nft flush after expired-subnet cleanup failed: %v\n", err)
				return 0
			}
		}
		// Keep queue-failed rows in state for a retry next tick; drop the
		// rest. See CleanExpiredAllows for the wedge this avoids.
		dropped := make([]SubnetEntry, 0, len(expired))
		for _, entry := range expired {
			if queueFailedCIDRs[entry.CIDR] {
				active = append(active, entry)
				continue
			}
			dropped = append(dropped, entry)
		}
		state.BlockedNet = active
		_ = e.saveState(&state)
		for _, entry := range dropped {
			AppendAudit(e.statePath, "temp_subnet_expired", entry.CIDR, "", SourceSystem, 0)
		}
		return len(dropped)
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
	_ = e.saveState(&st)
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
	_ = e.saveState(&st)
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
	_ = e.saveState(&state)
	AppendAudit(e.statePath, "flush", "", fmt.Sprintf("cleared %d entries", count), SourceSystem, 0)

	return nil
}

// subnetSafetyGuardLocked refuses a CIDR block that would firewall traffic the
// daemon must keep reachable: infra IPs or ranges, DNS-resolved infra hosts,
// local interface addresses, full-IP allows, port-specific allows, or the
// default route. Subnet blocks cover many addresses, and the output chain has
// no infra carve-out, so an unsafe subnet can lock out operators or kill the
// daemon's own egress.
// Must be called with e.mu held.
func (e *Engine) subnetSafetyGuardLocked(network *net.IPNet) error {
	if ones, _ := network.Mask.Size(); ones == 0 {
		return fmt.Errorf("refusing to block default route: %s", network.String())
	}

	for _, raw := range e.cfg.InfraIPs {
		if _, infraNet, cidrErr := net.ParseCIDR(raw); cidrErr == nil {
			if network.Contains(infraNet.IP) || infraNet.Contains(network.IP) {
				return fmt.Errorf("refusing to block subnet %s: overlaps infra range %s", network.String(), raw)
			}
			continue
		}
		if infraIP := net.ParseIP(raw); infraIP != nil && network.Contains(infraIP) {
			return fmt.Errorf("refusing to block subnet %s: contains infra IP %s", network.String(), raw)
		}
	}

	for host, set := range e.infraResolved {
		for key := range set {
			if ip := net.ParseIP(key); ip != nil && network.Contains(ip) {
				return fmt.Errorf("refusing to block subnet %s: contains infra IP %s (resolved from %s)", network.String(), key, host)
			}
		}
	}

	e.refreshLocalAddrsLocked()
	for key := range e.localAddrs {
		if ip := net.ParseIP(key); ip != nil && network.Contains(ip) {
			return fmt.Errorf("refusing to block subnet %s: contains local host IP %s", network.String(), key)
		}
	}

	state := e.loadStateFile()
	for _, entry := range state.Allowed {
		if ip := net.ParseIP(entry.IP); ip != nil && network.Contains(ip) {
			return fmt.Errorf("refusing to block subnet %s: contains allowed IP %s", network.String(), entry.IP)
		}
	}
	for _, entry := range state.PortAllowed {
		if ip := net.ParseIP(entry.IP); ip != nil && network.Contains(ip) {
			return fmt.Errorf("refusing to block subnet %s: contains port-allowed IP %s", network.String(), entry.IP)
		}
	}

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
	if err := e.subnetSafetyGuardLocked(network); err != nil {
		return err
	}
	if e.isSubnetBlockedStateLocked(network.String()) {
		return nil
	}

	targetSet, start, end := e.resolveSubnetSet(network)
	if targetSet == nil {
		return fmt.Errorf("no matching set for %s (IPv6 disabled?)", cidr)
	}

	elements := intervalSetElements(start, end)
	if len(elements) == 0 {
		return fmt.Errorf("CIDR has no safe interval end: %s", network.String())
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

	// Persist to state BEFORE the kernel add, mirroring blockIPLocked: state
	// seeds the next Apply, so a crash between the kernel add and a later
	// state write would otherwise leave a kernel block that silently
	// disappears on restart. On kernel failure the prior state is restored.
	priorState := e.loadStateFile()
	nextState := copyFirewallState(priorState)
	addSubnetEntryIfMissingInState(&nextState, entry)
	if err := e.saveState(&nextState); err != nil {
		return fmt.Errorf("persisting subnet block for %s: %w", network.String(), err)
	}

	if err := e.conn.SetAddElements(targetSet, elements); err != nil {
		if restoreErr := e.saveState(&priorState); restoreErr != nil {
			return fmt.Errorf("adding to blocked_nets: %w (state restore failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("adding to blocked_nets: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		if restoreErr := e.saveState(&priorState); restoreErr != nil {
			return fmt.Errorf("flushing: %w (state restore failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("flushing: %w", err)
	}

	AppendAudit(e.statePath, "block_subnet", network.String(), reason, entry.Source, timeout)
	return nil
}

// IsSubnetBlocked returns true if the CIDR is present in the persisted subnet block state.
func (e *Engine) IsSubnetBlocked(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isSubnetBlockedStateLocked(network.String())
}

// BlockedSubnetCovering reports the blocked CIDR (if any) that contains ip.
// The input-chain drops blocked_nets before the allowed_ips accept, so an
// allow on an IP inside a blocked subnet has no effect: the subnet drop still
// fires. Callers surface this so an operator is not told an IP is reachable
// when a subnet rule still blocks it. The subnet block stays authoritative by
// design (see subnetSafetyGuardLocked); this only reports, it does not unblock.
func (e *Engine) BlockedSubnetCovering(ip string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return subnetCovering(e.loadStateFile().BlockedNet, ip)
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

	elements := intervalSetElements(start, end)
	if len(elements) == 0 {
		e.removeSubnetState(network.String())
		AppendAudit(e.statePath, "unblock_subnet", network.String(), "", "", 0)
		return nil
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

func intervalSetElements(start, end net.IP) []nftables.SetElement {
	if start == nil || end == nil {
		return nil
	}
	return appendIntervalSetElements(nil, start, end)
}

func appendIntervalSetElements(dst []nftables.SetElement, start, end net.IP) []nftables.SetElement {
	if start == nil || end == nil {
		return dst
	}
	endMarker, ok := nextIPSafe(end)
	if !ok {
		// The interval end marker is exclusive. An all-ones end has no
		// successor, so encoding it would either wrap or widen the range.
		return dst
	}
	return append(dst,
		nftables.SetElement{Key: start},
		nftables.SetElement{Key: endMarker, IntervalEnd: true},
	)
}

// UpdateInfraResolved records the IP set last resolved for an infra
// hostname. Replaces any previous entry for that host so the resolver's
// per-tick refresh leaves no stale ghost IPs. Pass an empty ips slice
// to remove the host entirely (e.g. when DNS stopped resolving).
func (e *Engine) UpdateInfraResolved(host string, ips []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if host == "" {
		return
	}
	if e.infraResolved == nil {
		e.infraResolved = make(map[string]map[string]struct{})
	}
	if len(ips) == 0 {
		delete(e.infraResolved, host)
		return
	}
	set := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		// Normalise via net.ParseIP so canonical form is stored
		// (collapses IPv6 forms and drops malformed values).
		if parsed := net.ParseIP(ip); parsed != nil {
			set[parsed.String()] = struct{}{}
		}
	}
	if len(set) == 0 {
		delete(e.infraResolved, host)
		return
	}
	e.infraResolved[host] = set
}

// DropInfraResolved clears all resolved IPs for a host. Equivalent to
// UpdateInfraResolved(host, nil); separate name surfaces operator
// intent at call sites that purposefully retire a hostname.
func (e *Engine) DropInfraResolved(host string) {
	e.UpdateInfraResolved(host, nil)
}

// infraIPResolvedHostLocked reports whether ip matches any IP recorded
// for any tracked infra hostname. Must be called with e.mu held; the
// existing blockIPTarget path already does so. The lookup normalizes ip
// to the same canonical form the storage path applies (net.ParseIP
// collapses IPv6 and rewrites ::ffff:1.2.3.4 to 1.2.3.4), so a caller
// passing the IPv4-mapped or uncanonical form still hits the guard.
func (e *Engine) infraIPResolvedHostLocked(ip string) (string, bool) {
	if e.infraResolved == nil {
		return "", false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	key := parsed.String()
	for host, set := range e.infraResolved {
		if _, ok := set[key]; ok {
			return host, true
		}
	}
	return "", false
}

// localAddrsCacheTTL bounds how stale the host-own-IP set can get before
// the next block call rebuilds it. The trade-off: a newly assigned local
// address could be auto-blocked for up to this window if a flagged source
// happens to share that address. Local-address changes (operator running
// `ip addr add`) are rare, so 60s keeps both the FP window and the steady
// per-block syscall cost negligible. Refreshing every miss instead would
// pin the cache to permanently-fresh under any scan storm.
const localAddrsCacheTTL = 60 * time.Second

// refreshLocalAddrsLocked rebuilds the cache of host-own interface
// addresses when the TTL has expired. Must be called with e.mu held.
// Failure leaves the previous cache in place so a transient netlink
// hiccup cannot demote the lockout guard.
func (e *Engine) refreshLocalAddrsLocked() {
	if e.localAddrs != nil && !e.localAddrsExpiresAt.IsZero() && time.Now().Before(e.localAddrsExpiresAt) {
		return
	}
	var ips []string
	if e.localAddrsLookup != nil {
		got, err := e.localAddrsLookup()
		if err != nil {
			return
		}
		ips = got
	} else {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ips = append(ips, ipnet.IP.String())
		}
	}
	set := make(map[string]struct{}, len(ips))
	for _, raw := range ips {
		key, ok := localAddrGuardKey(raw)
		if !ok {
			continue
		}
		set[key] = struct{}{}
	}
	e.localAddrs = set
	e.localAddrsExpiresAt = time.Now().Add(localAddrsCacheTTL)
}

func localAddrGuardKey(raw string) (string, bool) {
	parsed := net.ParseIP(raw)
	if parsed == nil {
		return "", false
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return "", false
	}
	return parsed.String(), true
}

// isLocalAddrLocked reports whether ip is one of the daemon's own host
// addresses. Must be called with e.mu held.
func (e *Engine) isLocalAddrLocked(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	e.refreshLocalAddrsLocked()
	if len(e.localAddrs) == 0 {
		return false
	}
	_, ok := e.localAddrs[parsed.String()]
	return ok
}

// BlockedCount returns the number of live blocked IP entries the engine
// is enforcing. Sourced from the same state file Status() uses, so
// `/api/v1/status` and `csm firewall status` agree on the number. Expired
// entries are pruned by loadStateFile before being counted.
func (e *Engine) BlockedCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.loadStateFile().Blocked)
}

// RuleCounts returns the cardinality of every firewall rule category from
// the engine state file with expired temp bans pruned. Callers needing a
// live count (e.g. Prometheus gauges) must use this rather than the bbolt
// store, which holds only the migration-time snapshot.
func (e *Engine) RuleCounts() RuleCounts {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.loadStateFile()
	return countRuleEntries(s, e.cfg != nil && e.cfg.IPv6)
}

// Status returns current firewall statistics.
//
// Takes e.mu so the cached state can be read coherently. Before the
// cache existed loadStateFile was lock-free because every call did its
// own ReadFile + Unmarshal; now that loadStateFile mutates the shared
// cache + index, the lock is required.
func (e *Engine) Status() map[string]interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()
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

// initialBlockState is the pre-computed pool of nft set elements to
// seed a freshly-built csm table from persisted state. Populated by
// computeInitialBlockStateLocked and consumed by
// queueInitialBlockStateLocked.
type initialBlockState struct {
	blocked4, blocked6       []nftables.SetElement
	allowed4, allowed6       []nftables.SetElement
	blockedNet4, blockedNet6 []nftables.SetElement
}

// computeInitialBlockStateLocked reads state.json and returns the
// nft elements needed to repopulate the blocked / allowed / blocked-
// net sets. Pure computation; does not touch nft. Safe to call from
// Apply before any AddTable / AddSet so the result can be queued
// into the same atomic netlink batch.
func (e *Engine) computeInitialBlockStateLocked() initialBlockState {
	state := e.loadStateFile()
	now := time.Now()
	var ibs initialBlockState
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
			ibs.blocked4 = append(ibs.blocked4, nftables.SetElement{Key: ip4, Timeout: timeout})
		} else if e.cfg.IPv6 {
			ibs.blocked6 = append(ibs.blocked6, nftables.SetElement{Key: parsed.To16(), Timeout: timeout})
		}
	}
	restoredAllowed := make(map[string]bool)
	for _, entry := range state.Allowed {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			continue
		}
		if restoredAllowed[entry.IP] {
			continue
		}
		parsed := net.ParseIP(entry.IP)
		if parsed == nil {
			continue
		}
		if ip4 := parsed.To4(); ip4 != nil {
			ibs.allowed4 = append(ibs.allowed4, nftables.SetElement{Key: ip4})
		} else if e.cfg.IPv6 {
			ibs.allowed6 = append(ibs.allowed6, nftables.SetElement{Key: parsed.To16()})
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
			continue
		}
		if start := network.IP.To4(); start != nil {
			ibs.blockedNet4 = appendIntervalSetElements(ibs.blockedNet4, start, end)
		} else if e.cfg.IPv6 {
			ibs.blockedNet6 = appendIntervalSetElements(ibs.blockedNet6, network.IP.To16(), end)
		}
	}
	return ibs
}

// queueInitialBlockStateLocked queues the previously-computed
// elements into the still-pending Apply netlink batch. Apply Flushes
// the whole batch as one transaction. No Flush here.
func (e *Engine) queueInitialBlockStateLocked(ibs initialBlockState) error {
	if err := e.addElementsChunked(e.setBlocked, ibs.blocked4); err != nil {
		return err
	}
	if e.setBlocked6 != nil {
		if err := e.addElementsChunked(e.setBlocked6, ibs.blocked6); err != nil {
			return err
		}
	}
	if err := e.addElementsChunked(e.setAllowed, ibs.allowed4); err != nil {
		return err
	}
	if e.setAllowed6 != nil {
		if err := e.addElementsChunked(e.setAllowed6, ibs.allowed6); err != nil {
			return err
		}
	}
	if err := e.addElementsChunked(e.setBlockedNet, ibs.blockedNet4); err != nil {
		return err
	}
	if e.setBlockedNet6 != nil {
		if err := e.addElementsChunked(e.setBlockedNet6, ibs.blockedNet6); err != nil {
			return err
		}
	}
	return nil
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
func (e *Engine) addElementsChunked(s *nftables.Set, elems []nftables.SetElement) error {
	const chunk = 1000
	for i := 0; i < len(elems); i += chunk {
		end := i + chunk
		if end > len(elems) {
			end = len(elems)
		}
		if err := e.conn.SetAddElements(s, elems[i:end]); err != nil {
			op := fmt.Sprintf("add elements to set %q chunk %d-%d", s.Name, i, end)
			logNftSetOpErr(op, "initial restore", err)
			return fmt.Errorf("adding initial elements to set %q chunk %d-%d: %w", s.Name, i, end, err)
		}
	}
	return nil
}

// logNftSetOpErr keeps operator-visible nft error logs grep-friendly.
func logNftSetOpErr(op, target string, err error) {
	fmt.Fprintf(os.Stderr, "firewall: nft %s for %s failed: %v\n", op, target, err)
}

// loadStateFile returns a deep copy of the cached firewall state with
// expired entries pruned. The on-disk state.json is re-read only when
// the file metadata key differs from the cached key (or the cache is empty).
//
// All callers must hold e.mu. The returned value is safe to mutate
// without affecting the cache; mutators write back via saveState which
// rebuilds the cache from the passed-in struct.
//
// Hot read paths (IsBlocked, IsSubnetBlocked, IsAllowed) bypass this
// allocation by consulting the index maps directly.
func (e *Engine) loadStateFile() FirewallState {
	e.ensureStateCacheLocked()
	if e.stateCache == nil {
		return FirewallState{}
	}
	s := e.stateCache
	return FirewallState{
		Blocked:     append([]BlockedEntry(nil), s.Blocked...),
		BlockedNet:  append([]SubnetEntry(nil), s.BlockedNet...),
		Allowed:     append([]AllowedEntry(nil), s.Allowed...),
		PortAllowed: append([]PortAllowEntry(nil), s.PortAllowed...),
	}
}

// loadStateFileRawLocked reads state.json without pruning expired entries.
// Expiry cleanup needs the stale rows so it can remove matching nftables
// elements before writing the active state back.
func (e *Engine) loadStateFileRawLocked() (FirewallState, bool) {
	stateFile := filepath.Join(e.statePath, "state.json")
	data, err := os.ReadFile(stateFile) // #nosec G304 -- filepath.Join under operator-configured statePath.
	if err != nil {
		if os.IsNotExist(err) {
			return FirewallState{}, true
		}
		return FirewallState{}, false
	}
	var state FirewallState
	if err := json.Unmarshal(data, &state); err != nil {
		return FirewallState{}, false
	}
	return state, true
}

// ensureStateCacheLocked populates or refreshes e.stateCache. Cheap on
// cache-hit (one stat). On cache-miss it does the full ReadFile +
// json.Unmarshal that the pre-cache implementation did on every call.
//
// Expired entries are pruned in-place after load so IsBlocked and the
// other index-backed lookups never report a stale block. Pruning
// updates the index maps via rebuildIndexLocked.
func (e *Engine) ensureStateCacheLocked() {
	stateFile := filepath.Join(e.statePath, "state.json")
	info, statErr := os.Stat(stateFile)
	if statErr == nil && e.stateCache != nil && e.stateCacheKey.matches(info) {
		e.applyExpiryLocked()
		return
	}

	var fresh FirewallState
	switch {
	case statErr == nil:
		// #nosec G304 -- filepath.Join under operator-configured statePath.
		data, readErr := os.ReadFile(stateFile)
		if readErr != nil {
			e.keepPriorStateCacheLocked()
			return
		}
		if err := json.Unmarshal(data, &fresh); err != nil {
			e.keepPriorStateCacheLocked()
			return
		}
		e.stateCacheKey = stateFileCacheKeyFromInfo(info)
	case os.IsNotExist(statErr):
		e.stateCacheKey = stateFileCacheKey{}
	case e.stateCache != nil:
		// Transient stat error (permission, EIO). Keep the prior
		// cache rather than dropping all blocks.
		e.applyExpiryLocked()
		return
	}

	e.stateCache = &fresh
	e.applyExpiryLocked()
	e.rebuildIndexLocked()
}

func (e *Engine) keepPriorStateCacheLocked() {
	if e.stateCache != nil {
		e.applyExpiryLocked()
		return
	}
	e.stateCache = &FirewallState{}
	e.stateCacheKey = stateFileCacheKey{}
	e.rebuildIndexLocked()
}

// applyExpiryLocked prunes expired entries from the cached state in
// place. Returns whether anything changed; the index maps are rebuilt
// when something did.
func (e *Engine) applyExpiryLocked() {
	if e.stateCache == nil {
		return
	}
	now := time.Now()
	s := e.stateCache
	changed := false
	if pruned, dropped := pruneBlocked(s.Blocked, now); dropped {
		s.Blocked = pruned
		changed = true
	}
	if pruned, dropped := pruneBlockedNet(s.BlockedNet, now); dropped {
		s.BlockedNet = pruned
		changed = true
	}
	if pruned, dropped := pruneAllowed(s.Allowed, now); dropped {
		s.Allowed = pruned
		changed = true
	}
	if changed {
		e.rebuildIndexLocked()
	}
}

// rebuildIndexLocked refreshes the three lookup maps from the cached
// state. Must be called any time e.stateCache is mutated.
func (e *Engine) rebuildIndexLocked() {
	if e.stateCache == nil {
		e.blockedIPIndex = nil
		e.allowedIPIndex = nil
		e.blockedCIDRIndex = nil
		return
	}
	s := e.stateCache
	blocked := make(map[string]int, len(s.Blocked))
	for i, entry := range s.Blocked {
		blocked[entry.IP] = i
	}
	e.blockedIPIndex = blocked
	allowed := make(map[string]struct{}, len(s.Allowed))
	for _, entry := range s.Allowed {
		allowed[entry.IP] = struct{}{}
	}
	e.allowedIPIndex = allowed
	subnets := make(map[string]struct{}, len(s.BlockedNet))
	for _, entry := range s.BlockedNet {
		subnets[entry.CIDR] = struct{}{}
	}
	e.blockedCIDRIndex = subnets
}

// pruneBlocked returns the list with expired blocked-IP entries removed
// and a flag indicating whether anything was dropped. Returns the
// original slice when no entries expired so we avoid pointless
// allocations on the steady-state hot path.
func pruneBlocked(in []BlockedEntry, now time.Time) ([]BlockedEntry, bool) {
	expired := 0
	for _, entry := range in {
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
			expired++
		}
	}
	if expired == 0 {
		return in, false
	}
	out := make([]BlockedEntry, 0, len(in)-expired)
	for _, entry := range in {
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
			continue
		}
		out = append(out, entry)
	}
	return out, true
}

func pruneBlockedNet(in []SubnetEntry, now time.Time) ([]SubnetEntry, bool) {
	expired := 0
	for _, entry := range in {
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
			expired++
		}
	}
	if expired == 0 {
		return in, false
	}
	out := make([]SubnetEntry, 0, len(in)-expired)
	for _, entry := range in {
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
			continue
		}
		out = append(out, entry)
	}
	return out, true
}

func pruneAllowed(in []AllowedEntry, now time.Time) ([]AllowedEntry, bool) {
	expired := 0
	for _, entry := range in {
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
			expired++
		}
	}
	if expired == 0 {
		return in, false
	}
	out := make([]AllowedEntry, 0, len(in)-expired)
	for _, entry := range in {
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
			continue
		}
		out = append(out, entry)
	}
	return out, true
}

var writeFirewallStateJSON = atomicio.AtomicWriteJSON

// saveState writes the firewall state to disk atomically (write to .tmp,
// rename into place) and rebuilds the in-memory cache to reflect the
// just-written snapshot. Callers must hold e.mu.
//
// The cache rebuild deep-copies the input slices so a caller that
// keeps mutating the local FirewallState after saveState returns cannot
// corrupt the cache.
func (e *Engine) saveState(s *FirewallState) error {
	path := filepath.Join(e.statePath, "state.json")
	if err := writeFirewallStateJSON(path, 0o600, s); err != nil {
		if firewallStateFileMatches(path, 0o600, s) {
			fmt.Fprintf(os.Stderr, "firewall: state.json committed with persistence warning: %v\n", err)
			e.setStateCacheLocked(path, s)
			return nil
		}
		fmt.Fprintf(os.Stderr, "firewall: persist state.json failed: %v\n", err)
		e.clearStateCacheLocked()
		return err
	}
	e.setStateCacheLocked(path, s)
	return nil
}

func firewallStateFileMatches(path string, perm os.FileMode, s *FirewallState) bool {
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != perm {
		return false
	}
	want, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return false
	}
	// #nosec G304 -- path is the engine-owned state file path.
	got, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Equal(got, want)
}

func (e *Engine) setStateCacheLocked(path string, s *FirewallState) {
	var cacheKey stateFileCacheKey
	if info, statErr := os.Stat(path); statErr == nil {
		cacheKey = stateFileCacheKeyFromInfo(info)
	}

	e.stateCache = &FirewallState{
		Blocked:     append([]BlockedEntry(nil), s.Blocked...),
		BlockedNet:  append([]SubnetEntry(nil), s.BlockedNet...),
		Allowed:     append([]AllowedEntry(nil), s.Allowed...),
		PortAllowed: append([]PortAllowEntry(nil), s.PortAllowed...),
	}
	e.stateCacheKey = cacheKey
	e.rebuildIndexLocked()
}

func (e *Engine) clearStateCacheLocked() {
	e.stateCache = nil
	e.stateCacheKey = stateFileCacheKey{}
	e.rebuildIndexLocked()
}

func copyFirewallState(s FirewallState) FirewallState {
	return FirewallState{
		Blocked:     append([]BlockedEntry(nil), s.Blocked...),
		BlockedNet:  append([]SubnetEntry(nil), s.BlockedNet...),
		Allowed:     append([]AllowedEntry(nil), s.Allowed...),
		PortAllowed: append([]PortAllowEntry(nil), s.PortAllowed...),
	}
}

func upsertBlockedEntryInState(state *FirewallState, entry BlockedEntry) {
	for i := range state.Blocked {
		if state.Blocked[i].IP == entry.IP {
			state.Blocked[i] = entry
			return
		}
	}
	state.Blocked = append(state.Blocked, entry)
}

func removeBlockedIPFromState(state *FirewallState, ip string) {
	remaining := state.Blocked[:0]
	for _, entry := range state.Blocked {
		if entry.IP == ip {
			continue
		}
		remaining = append(remaining, entry)
	}
	state.Blocked = remaining
}

func upsertAllowedEntryInState(state *FirewallState, entry AllowedEntry) {
	for i, existing := range state.Allowed {
		if existing.IP == entry.IP && existing.Source == entry.Source {
			state.Allowed[i] = entry
			return
		}
	}
	state.Allowed = append(state.Allowed, entry)
}

func addSubnetEntryIfMissingInState(state *FirewallState, entry SubnetEntry) bool {
	for _, existing := range state.BlockedNet {
		if existing.CIDR == entry.CIDR {
			return false
		}
	}
	state.BlockedNet = append(state.BlockedNet, entry)
	return true
}

func isNftNotFound(err error) bool {
	return errors.Is(err, syscall.ENOENT)
}

func (e *Engine) restoreBlockStateAfterFailureLocked(state FirewallState, ip string) error {
	if err := e.saveState(&state); err != nil {
		fmt.Fprintf(os.Stderr, "firewall: restore state after failed block for %s failed: %v\n", ip, err)
		return err
	}
	return nil
}

func (e *Engine) saveBlockedEntry(entry BlockedEntry) error {
	if entry.Source == "" {
		entry.Source = InferProvenance("block", entry.Reason)
	}
	state := e.loadStateFile()
	// Position index makes dedup O(1) instead of a linear scan over every
	// blocked entry per call. Hot during correlator-driven block bursts.
	if i, ok := e.blockedIPIndex[entry.IP]; ok && i >= 0 && i < len(state.Blocked) && state.Blocked[i].IP == entry.IP {
		state.Blocked[i] = entry
		return e.saveState(&state)
	}
	state.Blocked = append(state.Blocked, entry)
	return e.saveState(&state)
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
	_ = e.saveState(&state)
}

func (e *Engine) saveAllowedEntry(entry AllowedEntry) {
	if entry.Source == "" {
		entry.Source = InferProvenance("allow", entry.Reason)
	}
	state := e.loadStateFile()
	for i, existing := range state.Allowed {
		if existing.IP == entry.IP && existing.Source == entry.Source {
			state.Allowed[i] = entry // update reason/expiry for same source
			_ = e.saveState(&state)
			return
		}
	}
	state.Allowed = append(state.Allowed, entry)
	_ = e.saveState(&state)
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
	_ = e.saveState(&state)
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
	_ = e.saveState(&state)
	return !ipStillPresent
}

func (e *Engine) saveSubnetEntry(entry SubnetEntry) {
	if entry.Source == "" {
		entry.Source = InferProvenance("block_subnet", entry.Reason)
	}
	state := e.loadStateFile()
	if !addSubnetEntryIfMissingInState(&state, entry) {
		return
	}
	_ = e.saveState(&state)
}

func (e *Engine) isSubnetBlockedStateLocked(cidr string) bool {
	e.ensureStateCacheLocked()
	_, ok := e.blockedCIDRIndex[cidr]
	return ok
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
	_ = e.saveState(&state)
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
			elements = appendIntervalSetElements(elements, start, end)
		}
	}
	return elements
}
