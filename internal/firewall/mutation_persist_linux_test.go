//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/atomicio"
)

func TestFirewallMutationsReportPersistenceFailures(t *testing.T) {
	for _, operation := range []struct {
		name string
		seed FirewallState
		call func(*Engine) error
	}{
		{"allow port", FirewallState{}, func(e *Engine) error { return e.AllowIPPort("192.0.2.10", 443, "tcp", "via CLI") }},
		{"remove port", FirewallState{PortAllowed: []PortAllowEntry{{IP: "192.0.2.10", Port: 443, Proto: "tcp"}}}, func(e *Engine) error { return e.RemoveAllowIPPort("192.0.2.10", 443, "tcp") }},
		{"remove allow", FirewallState{Allowed: []AllowedEntry{{IP: "192.0.2.10", Source: SourceCLI}}}, func(e *Engine) error { return e.RemoveAllowIP("192.0.2.10") }},
		{"remove source", FirewallState{Allowed: []AllowedEntry{{IP: "192.0.2.10", Source: SourceDynDNS}}}, func(e *Engine) error { return e.RemoveAllowIPBySource("192.0.2.10", SourceDynDNS) }},
	} {
		for _, failure := range []struct {
			phase string
			cause error
		}{{"write", syscall.ENOSPC}, {"open", syscall.EACCES}, {"rename", syscall.EIO}, {"fsync tmp", syscall.EIO}} {
			t.Run(operation.name+"/"+failure.phase, func(t *testing.T) {
				conn, sends := nftConnReturningErrsThenOK(t)
				e := &Engine{conn: conn, statePath: t.TempDir(), cfg: &FirewallConfig{Enabled: true}, setAllowed: namedIPv4Set("allowed_ips")}
				if err := e.saveState(&operation.seed); err != nil {
					t.Fatal(err)
				}
				statePath := filepath.Join(e.statePath, "state.json")
				before, err := os.ReadFile(statePath)
				if err != nil {
					t.Fatal(err)
				}
				previous := writeFirewallStateJSON
				t.Cleanup(func() { writeFirewallStateJSON = previous })
				writeFirewallStateJSON = func(string, os.FileMode, any) error {
					return fmt.Errorf("%s: %w", failure.phase, failure.cause)
				}
				if callErr := operation.call(e); !errors.Is(callErr, failure.cause) {
					t.Errorf("mutation error = %v, want %v", callErr, failure.cause)
				}
				if sends() != 0 {
					t.Errorf("changed kernel before persistence succeeded: %d sends", sends())
				}
				after, err := os.ReadFile(statePath)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("failed mutation changed persisted state: error=%v, before=%s, after=%s", err, before, after)
				}
				assertNoMutationAudit(t, e.statePath)
			})
		}
	}
}

func assertNoMutationAudit(t *testing.T, dir string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("failed mutation emitted a success audit record: %s", data)
	}
}

func TestFirewallSyncFailureReportsUncertainCommit(t *testing.T) {
	e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}}
	previous := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = previous })
	writeFirewallStateJSON = func(path string, perm os.FileMode, state any) error {
		if err := atomicio.AtomicWriteJSON(path, perm, state); err != nil {
			return err
		}
		return fmt.Errorf("fsync dir: %w", syscall.EIO)
	}
	err := e.AllowIPPort("192.0.2.10", 443, "tcp", "via CLI")
	if !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), "durability") {
		t.Errorf("post-rename failure = %v, want explicit durability uncertainty", err)
	}
	state := readRawFirewallState(t, e)
	if len(state.PortAllowed) != 1 || state.PortAllowed[0].IP != "192.0.2.10" {
		t.Fatalf("visible post-rename state differs from the reported partial commit: %+v", state)
	}
	assertNoMutationAudit(t, e.statePath)
}

func TestExpiredAllowsReportPersistenceFailure(t *testing.T) {
	conn, sends := nftConnReturningErrsThenOK(t)
	e := &Engine{conn: conn, statePath: t.TempDir(), cfg: &FirewallConfig{}, setAllowed: namedIPv4Set("allowed_ips")}
	seed := FirewallState{Allowed: []AllowedEntry{{IP: "192.0.2.10", Source: SourceCLI, ExpiresAt: time.Now().Add(-time.Hour)}}}
	writeRawFirewallState(t, e, seed)
	previous := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = previous })
	writeFirewallStateJSON = func(string, os.FileMode, any) error { return syscall.ENOSPC }
	if count := e.CleanExpiredAllows(); count != 0 {
		t.Errorf("reported %d expired entries after persistence failure", count)
	}
	if sends() != 0 {
		t.Errorf("changed kernel before persistence: %d sends", sends())
	}
	if got := readRawFirewallState(t, e); len(got.Allowed) != 1 {
		t.Errorf("lost expired entry: %+v", got)
	}
	assertNoMutationAudit(t, e.statePath)
}

func TestAllowRemovalRollsBackKernelFailures(t *testing.T) {
	for _, rollbackFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("rollback fails %v", rollbackFails), func(t *testing.T) {
			conn, _ := nftConnReturningErrsThenOK(t, syscall.EPERM)
			e := &Engine{conn: conn, statePath: t.TempDir(), cfg: &FirewallConfig{}, setAllowed: namedIPv4Set("allowed_ips")}
			seed := FirewallState{Allowed: []AllowedEntry{{IP: "192.0.2.10", Source: SourceDynDNS}}}
			if err := e.saveState(&seed); err != nil {
				t.Fatal(err)
			}
			previous := writeFirewallStateJSON
			t.Cleanup(func() { writeFirewallStateJSON = previous })
			writes := 0
			writeFirewallStateJSON = func(path string, perm os.FileMode, state any) error {
				writes++
				if rollbackFails && writes == 2 {
					return syscall.ENOSPC
				}
				return atomicio.AtomicWriteJSON(path, perm, state)
			}
			err := e.RemoveAllowIPBySource("192.0.2.10", SourceDynDNS)
			if !errors.Is(err, syscall.EPERM) {
				t.Fatalf("error = %v, want kernel failure", err)
			}
			if writes != 2 {
				t.Fatalf("writes = %d, want intent and rollback", writes)
			}
			got := readRawFirewallState(t, e)
			if rollbackFails {
				if !strings.Contains(err.Error(), "partial failure") || !strings.Contains(err.Error(), "state restore failed") {
					t.Errorf("missing partial outcome: %v", err)
				}
				if len(got.Allowed) != 0 {
					t.Errorf("failed rollback unexpectedly restored state: %+v", got)
				}
			} else if len(got.Allowed) != 1 || got.Allowed[0] != seed.Allowed[0] {
				t.Errorf("rollback changed original entry: %+v", got)
			}
			assertNoMutationAudit(t, e.statePath)
		})
	}
}

func TestAllowQueueFailureDiscardsEarlierDeletes(t *testing.T) {
	conn, sends := nftConnReturningErrsThenOK(t)
	e := &Engine{conn: conn, statePath: t.TempDir(), cfg: &FirewallConfig{}, setBlocked: namedIPv4Set("blocked_ips"), setAllowed: anonymousIPv4Set("allowed_ips")}
	if err := e.AllowIP("192.0.2.10", "via CLI"); err == nil {
		t.Fatal("expected allowed-set queue failure")
	}
	if err := e.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if sends() != 0 {
		t.Errorf("failed allow leaked %d queued kernel batches", sends())
	}
	assertNoMutationAudit(t, e.statePath)
}

func TestExpiredAllowSyncFailureKeepsRetryState(t *testing.T) {
	conn, sends := nftConnReturningErrsThenOK(t)
	e := &Engine{conn: conn, statePath: t.TempDir(), cfg: &FirewallConfig{}, setAllowed: namedIPv4Set("allowed_ips")}
	writeRawFirewallState(t, e, FirewallState{Allowed: []AllowedEntry{{IP: "192.0.2.10", Source: SourceCLI, ExpiresAt: time.Now().Add(-time.Hour)}}})
	previous := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = previous })
	writes := 0
	writeFirewallStateJSON = func(path string, perm os.FileMode, state any) error {
		writes++
		if err := previous(path, perm, state); err != nil {
			return err
		}
		if writes == 1 {
			return syscall.EIO
		}
		return nil
	}
	if count := e.CleanExpiredAllows(); count != 0 {
		t.Errorf("failed cleanup reported %d removals", count)
	}
	if sends() != 0 {
		t.Errorf("kernel changed after sync failure: %d sends", sends())
	}
	if got := readRawFirewallState(t, e); len(got.Allowed) != 1 {
		t.Fatalf("lost expiry retry state: %+v", got)
	}
	assertNoMutationAudit(t, e.statePath)
	if count := e.CleanExpiredAllows(); count != 1 {
		t.Fatalf("cleanup did not retry: count=%d", count)
	}
	if sends() != 1 {
		t.Errorf("retry committed %d kernel batches, want 1", sends())
	}
}
