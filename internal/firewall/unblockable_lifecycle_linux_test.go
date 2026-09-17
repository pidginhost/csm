//go:build linux

package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

var protectedAddressCases = []string{
	"127.0.0.1", "::ffff:127.0.0.53", "::1", "0.0.0.0", "::ffff:0.0.0.0", "::",
	"169.254.1.1", "::ffff:169.254.1.1", "fe80::1", "224.0.0.1", "ff02::1", "ff12::1",
}

func newProtectedAddressEngine(t *testing.T, conn *nftables.Conn) *Engine {
	t.Helper()
	e := newBlockedSetWireTestEngine(t, conn)
	e.cfg.IPv6 = true
	e.setBlocked6 = &nftables.Set{Table: e.table, Name: "blocked_ips6", KeyType: nftables.TypeIP6Addr, HasTimeout: true}
	e.setBlockedNet = &nftables.Set{Table: e.table, Name: "blocked_nets", KeyType: nftables.TypeIPAddr, Interval: true}
	e.setBlockedNet6 = &nftables.Set{Table: e.table, Name: "blocked_nets6", KeyType: nftables.TypeIP6Addr, Interval: true}
	e.localAddrsLookup = func() ([]string, error) { return nil, errors.New("interface lookup failed") }
	return e
}

func TestProtectedAddressBlockAndPromotionRefused(t *testing.T) {
	for _, ip := range protectedAddressCases {
		for _, operation := range []string{"auto", "force", "promote"} {
			t.Run(ip+"/"+operation, func(t *testing.T) {
				conn, captured := nftConnCapturingRules(t)
				e := newProtectedAddressEngine(t, conn)
				e.SetDryRunEnabledFunc(func() bool { return true })
				e.SetDryRunRecorder(func(string, string, time.Duration) { t.Error("protected block recorded as dry-run") })
				e.SetVerdictAsker(func(_ context.Context, _, _ string) (string, string, string, error) {
					t.Error("protected block reached verdict callback")
					return "block", "", "", nil
				})
				prior := FirewallState{Blocked: []BlockedEntry{{
					IP: net.ParseIP(ip).String(), Reason: "legacy block", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
				}}}
				writeRawFirewallState(t, e, prior)
				prior = readRawFirewallState(t, e)
				var err error
				switch operation {
				case "auto":
					var outcome BlockOutcome
					outcome, err = e.BlockIPOutcome(ip, "new block", time.Hour)
					if outcome != BlockOutcomeNoop {
						t.Errorf("outcome = %v, want no-op", outcome)
					}
				case "force":
					err = e.BlockIPForce(ip, "new block", 0)
				case "promote":
					err = e.PromoteToPermanentBlock(ip, "escalated")
				}
				if !errors.Is(err, ErrIPProtected) {
					t.Errorf("error = %v, want ErrIPProtected", err)
				}
				if len(*captured) != 0 {
					t.Error("refused block sent a kernel transaction")
				}
				if got := readRawFirewallState(t, e); !reflect.DeepEqual(got, prior) {
					t.Errorf("refused block changed state: %+v", got)
				}
			})
		}
	}
}

func TestProtectedAddressLegacyBlockRecovery(t *testing.T) {
	for _, ip := range protectedAddressCases {
		t.Run(ip, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := newProtectedAddressEngine(t, conn)
			canonical := net.ParseIP(ip).String()
			writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{{IP: canonical, Reason: "legacy block"}}})
			if !e.IsBlocked(ip) {
				t.Fatal("legacy block disappeared from membership")
			}
			initial := e.computeInitialBlockStateLocked()
			elems := slices.Concat(initial.blocked4, initial.blocked6)
			if len(elems) != 1 {
				t.Fatalf("restored elements = %+v, want one legacy block", elems)
			}
			requireElemKey(t, elems[0], canonical)
			if err := e.UnblockIP(ip); err != nil {
				t.Fatalf("UnblockIP: %v", err)
			}
			setName := "blocked_ips"
			if net.ParseIP(ip).To4() == nil {
				setName += "6"
			}
			if got := delSetElemCount(t, *captured, setName); got != 1 {
				t.Errorf("kernel deletes = %d, want 1", got)
			}
			if e.IsBlocked(ip) || len(readRawFirewallState(t, e).Blocked) != 0 {
				t.Fatal("unblocked entry survived in state")
			}
			initial = e.computeInitialBlockStateLocked()
			if len(initial.blocked4)+len(initial.blocked6) != 0 {
				t.Fatal("removed entry would be restored on restart")
			}
		})
	}
}

func TestProtectedAddressUnblockFailureKeepsLegacyState(t *testing.T) {
	for _, nftErr := range []syscall.Errno{unix.ENOENT, unix.EPERM} {
		t.Run(nftErr.Error(), func(t *testing.T) {
			conn, _ := nftConnReturningErrsThenOK(t, nftErr)
			e := newProtectedAddressEngine(t, conn)
			writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{{IP: "::", Reason: "legacy block"}}})
			err := e.UnblockIP("::")
			if nftErr == unix.ENOENT {
				if err != nil || e.IsBlocked("::") {
					t.Fatalf("absent element did not reconcile: err=%v, blocked=%v", err, e.IsBlocked("::"))
				}
			} else if err == nil || !e.IsBlocked("::") {
				t.Fatalf("failed delete lost retryable state: err=%v, blocked=%v", err, e.IsBlocked("::"))
			}
		})
	}
}

func TestSubnetBlockRefusesProtectedAddresses(t *testing.T) {
	cidrs := []string{
		"127.0.0.1/32", "126.0.0.0/7", "::ffff:127.0.0.1/128", "::1/128", "0.0.0.0/32", "::/128",
		"169.254.1.1/32", "168.0.0.0/7", "fe80::1/128", "fe00::/8", "224.0.0.1/32", "224.0.0.0/3",
	}
	for flags := 0; flags < 16; flags++ {
		cidrs = append(cidrs, fmt.Sprintf("ff%x2::1/128", flags), fmt.Sprintf("ff%x0::/12", flags))
	}
	for _, cidr := range cidrs {
		t.Run(cidr, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := newProtectedAddressEngine(t, conn)
			if err := e.ValidateSubnetBlock(cidr); !errors.Is(err, ErrIPProtected) {
				t.Errorf("ValidateSubnetBlock error = %v, want ErrIPProtected", err)
			}
			if err := e.BlockSubnet(cidr, "new block", 0); !errors.Is(err, ErrIPProtected) {
				t.Errorf("BlockSubnet error = %v, want ErrIPProtected", err)
			}
			if len(*captured) != 0 || len(e.loadStateFile().BlockedNet) != 0 {
				t.Fatal("refused subnet changed kernel or persisted state")
			}
		})
	}
}

func TestSubnetBlockKeepsOtherAddressRanges(t *testing.T) {
	for _, cidr := range []string{
		"192.0.2.0/24", "2001:db8::/32", "10.0.0.0/8", "fc00::/7",
		"126.0.0.0/8", "128.0.0.0/8", "169.253.0.0/16", "169.255.0.0/16",
		"224.0.1.0/24", "fe40::/10", "fec0::/10", "ff01::/16", "ff03::/16",
	} {
		t.Run(cidr, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := newProtectedAddressEngine(t, conn)
			if err := e.ValidateSubnetBlock(cidr); err != nil {
				t.Fatalf("ValidateSubnetBlock: %v", err)
			}
			if err := e.BlockSubnet(cidr, "attacker subnet", 0); err != nil {
				t.Fatalf("BlockSubnet: %v", err)
			}
			if len(*captured) == 0 || !e.IsSubnetBlocked(cidr) {
				t.Fatal("accepted subnet was not applied")
			}
		})
	}
}

func TestProtectedSubnetLegacyBlockRecovery(t *testing.T) {
	for _, cidr := range []string{"127.0.0.1/32", "0.0.0.0/32", "::/128", "fe80::/64"} {
		t.Run(cidr, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := newProtectedAddressEngine(t, conn)
			writeRawFirewallState(t, e, FirewallState{BlockedNet: []SubnetEntry{{CIDR: cidr, Reason: "legacy subnet"}}})
			initial := e.computeInitialBlockStateLocked()
			elems := slices.Concat(initial.blockedNet4, initial.blockedNet6)
			if len(elems) != 2 || !e.IsSubnetBlocked(cidr) {
				t.Fatalf("legacy subnet disappeared: %+v", elems)
			}
			requireIntervalElems(t, elems, cidr)
			if err := e.UnblockSubnet(cidr); err != nil {
				t.Fatalf("UnblockSubnet: %v", err)
			}
			if len(*captured) == 0 || e.IsSubnetBlocked(cidr) || len(readRawFirewallState(t, e).BlockedNet) != 0 {
				t.Fatal("legacy subnet removal was not applied")
			}
		})
	}
}
