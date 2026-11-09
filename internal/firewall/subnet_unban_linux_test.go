//go:build linux

package firewall

import (
	"errors"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestSubnetSourceUsesAutomaticIntent(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		for _, reason := range []string{"manual response to auto-netblock", "subnet abuse"} {
			t.Run(reason+"/"+map[bool]string{false: "operator", true: "automatic"}[automatic], func(t *testing.T) {
				conn, _ := nftConnCapturingRules(t)
				e := newProtectedAddressEngine(t, conn)
				e.SetDryRunEnabledFunc(func() bool { return false })
				if err := e.BlockSubnetRequest(ActionRequest{Target: "192.0.2.0/24", Reason: reason, Automatic: automatic}, nil); err != nil {
					t.Fatal(err)
				}
				entries := readRawFirewallState(t, e).BlockedNet
				if len(entries) != 1 || (entries[0].Source == SourceAutoResponse) != automatic || entries[0].Automatic != automatic {
					t.Fatalf("automatic=%v: subnet provenance = %+v", automatic, entries)
				}
			})
		}
	}
}

func TestSubnetConditionalUnblock(t *testing.T) {
	for _, mode := range []string{"unchanged", "operator replacement", "ownership changed", "renewed", "removed", "kernel failure"} {
		t.Run(mode, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			if mode == "kernel failure" {
				conn = nftConnReturningErr(t, syscall.EPERM)
			}
			e := newProtectedAddressEngine(t, conn)
			expected := SubnetEntry{CIDR: "192.0.2.0/24", Reason: "auto-netblock", Source: SourceAutoResponse, Automatic: true, BlockedAt: time.Now()}
			current := expected
			switch mode {
			case "operator replacement":
				current.Source = SourceCLI
			case "ownership changed":
				current.Automatic = false
			case "renewed":
				current.ExpiresAt = time.Now().Add(time.Hour)
			}
			other := SubnetEntry{CIDR: "192.0.2.0/25", Source: SourceWebUI}
			entries := []SubnetEntry{current, other}
			if mode == "removed" {
				entries = []SubnetEntry{other}
			}
			writeRawFirewallState(t, e, FirewallState{BlockedNet: entries})
			prior := readRawFirewallState(t, e)
			err := e.UnblockSubnetIfUnchanged(expected)
			if mode == "unchanged" {
				if err != nil {
					t.Fatal(err)
				}
				if got := e.BlockedSubnets(); !reflect.DeepEqual(got, []SubnetEntry{other}) {
					t.Fatalf("surviving subnets = %+v", got)
				}
				if len(*captured) == 0 {
					t.Fatal("successful removal did not update the kernel")
				}
				return
			}
			want := ErrBlockChanged
			if mode == "kernel failure" {
				want = syscall.EPERM
			}
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
			if got := readRawFirewallState(t, e); !reflect.DeepEqual(got, prior) {
				t.Fatalf("failed removal changed persisted state: %+v", got)
			}
			if mode != "kernel failure" && len(*captured) != 0 {
				t.Fatal("stale removal reached the kernel")
			}
		})
	}
}
