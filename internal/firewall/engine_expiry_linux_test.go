//go:build linux

package firewall

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

func readRawFirewallState(t *testing.T, e *Engine) FirewallState {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.statePath, "state.json"))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	var state FirewallState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("decode state.json: %v", err)
	}
	return state
}

func anonymousIPv4Set(name string) *nftables.Set {
	return &nftables.Set{
		Table:     &nftables.Table{Name: "csm", Family: nftables.TableFamilyINet},
		Name:      name,
		KeyType:   nftables.TypeIPAddr,
		Anonymous: true,
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stderr = w
	defer func() {
		os.Stderr = old
		_ = r.Close()
	}()

	fn()
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close stderr writer: %v", closeErr)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(out)
}

func TestCleanExpiredAllowsUsesRawStateForMixedSourceExpiry(t *testing.T) {
	e := &Engine{
		conn:      &nftables.Conn{},
		statePath: t.TempDir(),
		cfg:       &FirewallConfig{},
	}
	e.saveAllowedEntry(AllowedEntry{
		IP:        "10.0.0.42",
		Reason:    "expired cli",
		Source:    SourceCLI,
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	e.saveAllowedEntry(AllowedEntry{
		IP:        "10.0.0.42",
		Reason:    "active dyndns",
		Source:    SourceDynDNS,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	if removed := e.CleanExpiredAllows(); removed != 1 {
		t.Fatalf("CleanExpiredAllows removed %d, want 1", removed)
	}

	state := readRawFirewallState(t, e)
	if len(state.Allowed) != 1 {
		t.Fatalf("allowed entries = %d, want 1: %+v", len(state.Allowed), state.Allowed)
	}
	if state.Allowed[0].Source != SourceDynDNS {
		t.Fatalf("remaining source = %q, want %q", state.Allowed[0].Source, SourceDynDNS)
	}
}

func TestCleanExpiredAllowsQueueErrorKeepsState(t *testing.T) {
	e := &Engine{
		conn:       &nftables.Conn{},
		statePath:  t.TempDir(),
		cfg:        &FirewallConfig{},
		setAllowed: anonymousIPv4Set("allowed_ips"),
	}
	e.saveAllowedEntry(AllowedEntry{
		IP:        "10.0.0.43",
		Reason:    "expired cli",
		Source:    SourceCLI,
		ExpiresAt: time.Now().Add(-time.Hour),
	})

	var removed int
	stderr := captureStderr(t, func() {
		removed = e.CleanExpiredAllows()
	})
	if removed != 0 {
		t.Fatalf("CleanExpiredAllows removed %d after queue error, want 0", removed)
	}
	if !strings.Contains(stderr, "firewall: nft CleanExpiredAllows remove for 10.0.0.43 failed") {
		t.Fatalf("stderr missing nft cleanup error, got %q", stderr)
	}

	state := readRawFirewallState(t, e)
	if len(state.Allowed) != 1 {
		t.Fatalf("allowed entries after queue error = %d, want 1", len(state.Allowed))
	}
}

func TestCleanExpiredSubnetsUsesRawState(t *testing.T) {
	e := &Engine{
		conn:      &nftables.Conn{},
		statePath: t.TempDir(),
		cfg:       &FirewallConfig{},
	}
	future := time.Now().Add(time.Hour)
	e.saveState(&FirewallState{
		BlockedNet: []SubnetEntry{
			{CIDR: "192.0.2.0/24", Reason: "expired", ExpiresAt: time.Now().Add(-time.Hour)},
			{CIDR: "198.51.100.0/24", Reason: "active", ExpiresAt: future},
		},
	})

	if removed := e.CleanExpiredSubnets(); removed != 1 {
		t.Fatalf("CleanExpiredSubnets removed %d, want 1", removed)
	}

	state := readRawFirewallState(t, e)
	if len(state.BlockedNet) != 1 {
		t.Fatalf("blocked subnets = %d, want 1: %+v", len(state.BlockedNet), state.BlockedNet)
	}
	if state.BlockedNet[0].CIDR != "198.51.100.0/24" {
		t.Fatalf("remaining CIDR = %q, want 198.51.100.0/24", state.BlockedNet[0].CIDR)
	}
}

func TestAllowMethodsReturnBlockedDeleteQueueError(t *testing.T) {
	tests := []struct {
		name string
		call func(*Engine) error
	}{
		{
			name: "AllowIP",
			call: func(e *Engine) error {
				return e.AllowIP("10.0.0.44", "manual")
			},
		},
		{
			name: "TempAllowIP",
			call: func(e *Engine) error {
				return e.TempAllowIP("10.0.0.44", "manual", time.Minute)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &Engine{
				conn:       &nftables.Conn{},
				statePath:  t.TempDir(),
				cfg:        &FirewallConfig{},
				setBlocked: anonymousIPv4Set("blocked_ips"),
			}
			e.saveBlockedEntry(BlockedEntry{
				IP:        "10.0.0.44",
				Reason:    "test block",
				BlockedAt: time.Now(),
			})

			err := tc.call(e)
			if err == nil || !strings.Contains(err.Error(), "removing from blocked set") {
				t.Fatalf("%s error = %v, want blocked-delete error", tc.name, err)
			}

			state := readRawFirewallState(t, e)
			if len(state.Blocked) != 1 {
				t.Fatalf("blocked entries after failed %s = %d, want 1", tc.name, len(state.Blocked))
			}
			if len(state.Allowed) != 0 {
				t.Fatalf("allowed entries after failed %s = %d, want 0", tc.name, len(state.Allowed))
			}
		})
	}
}

func TestAddElementsChunkedReturnsQueueError(t *testing.T) {
	e := &Engine{conn: &nftables.Conn{}}
	err := e.addElementsChunked(anonymousIPv4Set("blocked_ips"), []nftables.SetElement{
		{Key: []byte{10, 0, 0, 45}},
	})
	if err == nil || !strings.Contains(err.Error(), "adding initial elements") {
		t.Fatalf("addElementsChunked error = %v, want queue error", err)
	}
}
