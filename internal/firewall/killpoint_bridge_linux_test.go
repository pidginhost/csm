//go:build linux

package firewall

import (
	"encoding/binary"
	"maps"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// KillPoint is what ApplyBlockBatch panics with at a kill point.
type KillPoint string

// The steps of ApplyBlockBatch an engine kill-point test stops at.
const (
	KillBeforeIntent   KillPoint = "before the intent write"
	KillBeforeKernel   KillPoint = "after the intent write"
	KillBeforeReadback KillPoint = "after the kernel batch"
	KillBeforeMark     KillPoint = "after the readback"
	KillAfterMark      KillPoint = "after the unknown rows are marked"
	KillBeforeRestore  KillPoint = "before rejected state restore"
	KillAfterRestore   KillPoint = "after rejected state restore"
)

// KillPointTestEngine exposes the real batch, startup and retirement paths
// over the state directory dir to the external kill-point test; no
// production dependency is added. The engine reads wall time and the boot
// it runs in from wall, boot and since. kernel is its blocked sets: an
// acknowledged batch leaves there the addresses keep names, with their
// timeouts, and they stay after the engine is gone, as a kernel outlives a
// killed process. With kill set, ApplyBlockBatch stops there by panicking
// with it. The returned function runs Apply and models its emitted
// netlink transaction.
func KillPointTestEngine(t *testing.T, dir string, wall time.Time, boot string, since time.Duration, kernel, keep map[string]time.Duration, kill KillPoint) (*Engine, func()) {
	t.Helper()
	f := newBatchFixture(t, FirewallState{})
	f.e.statePath = dir
	f.live = kernel
	clock := &leaseSteps{wall: wall, elapsed: wall}
	f.e.leaseClock, f.e.expiryClock = clock.read, func() time.Time { return clock.wall }
	f.e.SetBootClock((&bootReading{id: boot, since: since}).read)
	rejected := kill == KillBeforeRestore || kill == KillAfterRestore
	if rejected {
		f.reply = func(req []netlink.Message) ([]netlink.Message, error) { return nltest.Error(int(syscall.EPERM), req) }
	}
	flushed := false
	if !rejected {
		f.reply = func(req []netlink.Message) ([]netlink.Message, error) {
			for _, msg := range req {
				for ip, ttl := range killElements(t, msg) {
					// Loss may remove a sent element, never invent one.
					if wantTTL, retained := keep[ip]; retained {
						if ttl != wantTTL {
							t.Fatalf("batch sent %s with timeout %v; want %v", ip, ttl, wantTTL)
						}
						kernel[ip] = ttl
					}
				}
			}
			flushed = true
			var acks []netlink.Message
			for _, msg := range req {
				if msg.Header.Flags&netlink.Acknowledge != 0 {
					acks = append(acks, netlink.Message{Header: netlink.Header{Length: 4, Type: netlink.Error, Sequence: msg.Header.Sequence, PID: msg.Header.PID}, Data: []byte{0, 0, 0, 0}})
				}
			}
			return acks, nil
		}
	}
	switch kill {
	case KillBeforeKernel:
		f.reply = func([]netlink.Message) ([]netlink.Message, error) { panic(kill) }
	case KillBeforeReadback:
		dump := f.e.liveBlockedDump
		f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
			if flushed {
				panic(kill)
			}
			return dump(set)
		}
	case KillBeforeIntent, KillBeforeMark, KillAfterMark, KillBeforeRestore, KillAfterRestore:
		// The batch's first state write is its intent; the second marks
		// unknown rows or restores a rejected batch. Later engines write through.
		write, writes := writeFirewallStateJSON, 0
		t.Cleanup(func() { writeFirewallStateJSON = write })
		writeFirewallStateJSON = func(path string, perm os.FileMode, v any) error {
			writes++
			switch {
			case writes == 1 && kill == KillBeforeIntent, writes == 2 && (kill == KillBeforeMark || kill == KillBeforeRestore):
				panic(kill)
			case writes == 2 && (kill == KillAfterMark || kill == KillAfterRestore):
				if err := write(path, perm, v); err != nil {
					t.Errorf("marking unknown rows: %v", err)
				}
				panic(kill)
			}
			return write(path, perm, v)
		}
	}
	return f.e, func() { applyKillKernel(t, f.e, kernel) }
}

// killAttrs decodes emitted messages, never the engine's desired state.
func killAttrs(t *testing.T, data []byte) map[uint16][]byte {
	t.Helper()
	attrs, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint16][]byte{}
	for _, attr := range attrs {
		out[attr.Type&0x3fff] = attr.Data
	}
	return out
}

// killElements models the two address-family sets independently: a key
// sent to the wrong set cannot become a live block in the right family.
func killElements(t *testing.T, msg netlink.Message) map[string]time.Duration {
	t.Helper()
	if msg.Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWSETELEM) {
		return nil
	}
	if len(msg.Data) < 4 {
		t.Fatal("short set-element header")
	}
	if msg.Data[0] != byte(nftables.TableFamilyINet) {
		return nil
	}
	attrs := killAttrs(t, msg.Data[4:])
	table, set := string(attrs[unix.NFTA_SET_ELEM_LIST_TABLE]), string(attrs[unix.NFTA_SET_ELEM_LIST_SET])
	if table != "csm\x00" || (set != "blocked_ips\x00" && set != "blocked_ips6\x00") {
		return nil
	}
	items, err := netlink.UnmarshalAttributes(attrs[unix.NFTA_SET_ELEM_LIST_ELEMENTS])
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]time.Duration{}
	for _, item := range items {
		el := killAttrs(t, item.Data)
		key := killAttrs(t, el[unix.NFTA_SET_ELEM_KEY])[unix.NFTA_DATA_VALUE]
		wantLen := net.IPv4len
		if set == "blocked_ips6\x00" {
			wantLen = net.IPv6len
		}
		if len(key) != wantLen {
			t.Fatalf("set %q received a key of length %d; want %d", set, len(key), wantLen)
		}
		var ttl time.Duration
		if data := el[unix.NFTA_SET_ELEM_TIMEOUT]; data != nil {
			if len(data) != 8 {
				t.Fatalf("invalid timeout: %v", data)
			}
			ttl = time.Duration(binary.BigEndian.Uint64(data)) * time.Millisecond
		}
		out[net.IP(key).String()] = ttl
	}
	return out
}

// Apply must delete the old table and install hooked base chains with
// rules, not merely create a table. Only its emitted transaction seeds
// elements; a successful mock ACK alone proves none of these effects.
func applyKillKernel(t *testing.T, e *Engine, kernel map[string]time.Duration) {
	t.Helper()
	conn, captured := nftConnCapturingRules(t)
	e.conn = conn
	e.listTables = func() ([]*nftables.Table, error) {
		if len(kernel) == 0 {
			return nil, nil
		}
		return []*nftables.Table{{Name: "csm", Family: nftables.TableFamilyINet}}, nil
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	next := maps.Clone(kernel)
	created := 0
	chains, rules := map[string]bool{}, map[string]int{}
	sets := map[string]bool{}
	for _, msg := range *captured {
		switch msg.Header.Type {
		case netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELTABLE), netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWTABLE):
			attrs := killAttrs(t, msg.Data[4:])
			if msg.Data[0] != byte(nftables.TableFamilyINet) || string(attrs[unix.NFTA_TABLE_NAME]) != "csm\x00" {
				continue
			}
			if msg.Header.Type == netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_DELTABLE) {
				clear(next)
				clear(chains)
				clear(rules)
				clear(sets)
			} else {
				created++
			}
		case netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSET):
			attrs := killAttrs(t, msg.Data[4:])
			name := string(attrs[unix.NFTA_SET_NAME])
			if msg.Data[0] != byte(nftables.TableFamilyINet) || string(attrs[unix.NFTA_SET_TABLE]) != "csm\x00" || (name != "blocked_ips\x00" && name != "blocked_ips6\x00") {
				continue
			}
			keyLen, flags := attrs[unix.NFTA_SET_KEY_LEN], attrs[unix.NFTA_SET_FLAGS]
			wantLen := uint32(net.IPv4len)
			if name == "blocked_ips6\x00" {
				wantLen = net.IPv6len
			}
			if len(keyLen) != 4 || binary.BigEndian.Uint32(keyLen) != wantLen || len(flags) != 4 || binary.BigEndian.Uint32(flags)&unix.NFT_SET_TIMEOUT == 0 {
				t.Fatalf("Apply installed an invalid blocked set %q: %v", name, attrs)
			}
			sets[name] = true
		case netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWCHAIN):
			attrs := killAttrs(t, msg.Data[4:])
			if msg.Data[0] == byte(nftables.TableFamilyINet) && string(attrs[unix.NFTA_CHAIN_TABLE]) == "csm\x00" {
				hook := killAttrs(t, attrs[unix.NFTA_CHAIN_HOOK])[unix.NFTA_HOOK_HOOKNUM]
				name := string(attrs[unix.NFTA_CHAIN_NAME])
				if len(hook) == 4 {
					n := binary.BigEndian.Uint32(hook)
					chains[name] = (name == "input\x00" && n == unix.NF_INET_LOCAL_IN) || (name == "output\x00" && n == unix.NF_INET_LOCAL_OUT)
				}
			}
		case netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE):
			attrs := killAttrs(t, msg.Data[4:])
			if msg.Data[0] == byte(nftables.TableFamilyINet) && string(attrs[unix.NFTA_RULE_TABLE]) == "csm\x00" {
				rules[string(attrs[unix.NFTA_RULE_CHAIN])]++
			}
		case netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSETELEM):
			elements := killElements(t, msg)
			if len(elements) > 0 {
				name := string(killAttrs(t, msg.Data[4:])[unix.NFTA_SET_ELEM_LIST_SET])
				if !sets[name] {
					t.Fatalf("Apply seeded undeclared blocked set %q", name)
				}
			}
			maps.Copy(next, elements)
		}
	}
	if created != 1 || capturedTypes(*captured, unix.NFNL_MSG_BATCH_BEGIN) != 1 || capturedTypes(*captured, unix.NFNL_MSG_BATCH_END) != 1 {
		t.Fatal("Apply did not install one atomic base ruleset")
	}
	if !sets["blocked_ips\x00"] || !sets["blocked_ips6\x00"] {
		t.Fatal("Apply omitted a blocked set")
	}
	for _, name := range []string{"input\x00", "output\x00"} {
		// This fixture has no outbound restrictions: its hooked output
		// chain accepts by policy and legitimately has no rules.
		if !chains[name] || (name == "input\x00" && rules[name] == 0) {
			t.Fatalf("Apply omitted the hooked base chain or rules for %q", name)
		}
	}
	clear(kernel)
	maps.Copy(kernel, next)
}
