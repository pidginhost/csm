//go:build linux && nftkernel

package firewall

import (
	"errors"
	"net"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
)

func TestKernelAllowRemovalPersistenceAndRecovery(t *testing.T) {
	for _, sourceOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "all sources", true: "one source"}[sourceOnly], func(t *testing.T) {
			isolatedFirewallNamespace(t)
			e, err := NewEngine(&FirewallConfig{Enabled: true, IPv6: true}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			seed := FirewallState{Allowed: []AllowedEntry{{IP: "192.0.2.10", Source: SourceCLI}, {IP: "2001:db8::10", Source: SourceCLI}}}
			if sourceOnly {
				seed.Allowed = append(seed.Allowed, AllowedEntry{IP: "192.0.2.10", Source: SourceDynDNS})
			}
			if err := e.saveState(&seed); err != nil {
				t.Fatal(err)
			}
			if err := e.Apply(); err != nil {
				t.Fatal(err)
			}
			remove := func() error { return e.RemoveAllowIP("192.0.2.10") }
			if sourceOnly {
				remove = func() error { return e.RemoveAllowIPBySource("192.0.2.10", SourceDynDNS) }
			}
			previous := writeFirewallStateJSON
			t.Cleanup(func() { writeFirewallStateJSON = previous })
			for _, failure := range []error{syscall.ENOSPC, syscall.EACCES, syscall.EIO} {
				writeFirewallStateJSON = func(string, os.FileMode, any) error { return failure }
				if err := remove(); !errors.Is(err, failure) {
					t.Fatalf("removal error=%v, want %v", err, failure)
				}
				if got := readRawFirewallState(t, e); !reflect.DeepEqual(got, seed) {
					t.Fatalf("failed write changed disk: %+v", got)
				}
				assertKernelIntervalSet(t, e, e.setAllowed, map[string]bool{"192.0.2.10": false})
				assertKernelIntervalSet(t, e, e.setAllowed6, map[string]bool{"2001:db8::10": false})
				assertNoMutationAudit(t, e.statePath)
			}
			writeFirewallStateJSON = previous
			if !sourceOnly {
				e.setAllowed.Name = "missing_allowed_set"
				if err := remove(); err == nil {
					t.Fatal("missing kernel set reported successful removal")
				}
				e.setAllowed.Name = "allowed_ips"
				if got := readRawFirewallState(t, e); !reflect.DeepEqual(got, seed) {
					t.Fatalf("kernel failure lost state: %+v", got)
				}
				assertKernelIntervalSet(t, e, e.setAllowed, map[string]bool{"192.0.2.10": false})
				assertNoMutationAudit(t, e.statePath)
			}
			if err := remove(); err != nil {
				t.Fatal(err)
			}
			want4 := map[string]bool{}
			if sourceOnly {
				want4["192.0.2.10"] = false
			}
			assertKernelIntervalSet(t, e, e.setAllowed, want4)
			if got := readRawFirewallState(t, e); len(got.Allowed) != 1+len(want4) {
				t.Fatalf("remaining state: %+v", got)
			}
			if err := e.Apply(); err != nil {
				t.Fatal(err)
			}
			assertKernelIntervalSet(t, e, e.setAllowed, want4)
			assertKernelIntervalSet(t, e, e.setAllowed6, map[string]bool{"2001:db8::10": false})
		})
	}
}

func TestKernelAllowExpiryMissingElementDoesNotWedge(t *testing.T) {
	isolatedFirewallNamespace(t)
	e, err := NewEngine(&FirewallConfig{Enabled: true, IPv6: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed := FirewallState{Allowed: []AllowedEntry{{IP: "192.0.2.10", Source: SourceCLI}, {IP: "192.0.2.11", Source: SourceCLI}, {IP: "192.0.2.12", Source: SourceCLI}, {IP: "2001:db8::10", Source: SourceCLI}, {IP: "2001:db8::11", Source: SourceCLI}}}
	if err := e.saveState(&seed); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 1, 3} {
		seed.Allowed[i].ExpiresAt = time.Now().Add(-time.Minute).UTC()
	}
	if err := e.saveState(&seed); err != nil {
		t.Fatal(err)
	}
	if err := e.conn.SetDeleteElements(e.setAllowed, []nftables.SetElement{{Key: net.ParseIP("192.0.2.10").To4()}}); err != nil {
		t.Fatal(err)
	}
	if err := e.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	// The first family's deletes must not commit if the other family fails.
	e.setAllowed6.Name = "missing_allowed_v6"
	if count := e.CleanExpiredAllows(); count != 0 {
		t.Fatalf("failed transaction reported %d removals", count)
	}
	e.setAllowed6.Name = "allowed_ips6"
	assertKernelIntervalSet(t, e, e.setAllowed, map[string]bool{"192.0.2.11": false, "192.0.2.12": false})
	if got := readRawFirewallState(t, e); !reflect.DeepEqual(got, seed) {
		t.Fatalf("failed expiry lost retry state: %+v", got)
	}
	assertNoMutationAudit(t, e.statePath)
	if count := e.CleanExpiredAllows(); count != 3 {
		t.Fatalf("removed %d, want 3 expired source entries", count)
	}
	assertKernelIntervalSet(t, e, e.setAllowed, map[string]bool{"192.0.2.12": false})
	assertKernelIntervalSet(t, e, e.setAllowed6, map[string]bool{"2001:db8::11": false})
	if got := readRawFirewallState(t, e); len(got.Allowed) != 2 {
		t.Fatalf("remaining state: %+v", got)
	}
}

func TestKernelAllowRetryWithAbsentBlock(t *testing.T) {
	isolatedFirewallNamespace(t)
	e, err := NewEngine(&FirewallConfig{Enabled: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := e.AllowIP("192.0.2.10", "via CLI"); err != nil {
		t.Fatal(err)
	}
	assertKernelIntervalSet(t, e, e.setAllowed, map[string]bool{"192.0.2.10": false})
	assertKernelIntervalSet(t, e, e.setBlocked, map[string]bool{})
	if got := readRawFirewallState(t, e); len(got.Allowed) != 1 || len(got.Blocked) != 0 {
		t.Fatalf("state after allow retry: %+v", got)
	}
}

func TestKernelSubnetRetryAfterUncertainPersistence(t *testing.T) {
	isolatedFirewallNamespace(t)
	e, err := NewEngine(&FirewallConfig{Enabled: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	previous := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = previous })
	writes := 0
	writeFirewallStateJSON = func(path string, perm os.FileMode, state any) error {
		writes++
		if writes == 2 {
			return syscall.EACCES
		}
		if err := previous(path, perm, state); err != nil {
			return err
		}
		return syscall.EIO
	}
	if err := e.BlockSubnet("192.0.2.0/24", "via CLI", 0); !errors.Is(err, syscall.EIO) {
		t.Fatalf("sync error=%v", err)
	}
	assertKernelIntervalSet(t, e, e.setBlockedNet, map[string]bool{})
	assertNoMutationAudit(t, e.statePath)
	if got := readRawFirewallState(t, e); len(got.BlockedNet) != 1 {
		t.Fatalf("expected visible partial state after failed rollback: %+v", got)
	}
	writeFirewallStateJSON = previous
	if err := e.BlockSubnet("192.0.2.0/24", "via CLI", 0); err != nil {
		t.Fatal(err)
	}
	assertKernelIntervalSet(t, e, e.setBlockedNet, map[string]bool{"192.0.2.0": false, "192.0.3.0": true})
}
