//go:build linux

package firewall

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"

	"github.com/pidginhost/csm/internal/actionlog"
)

func TestRulesetApplyRecordsSuccessAndFailures(t *testing.T) {
	for _, phase := range []string{"success", "list", "flush"} {
		t.Run(phase, func(t *testing.T) {
			sink := withActionSink(t)
			conn, _ := nftConnReturningErrsThenOK(t)
			e := newBlockedSetWireTestEngine(t, conn)
			e.listTables = func() ([]*nftables.Table, error) {
				if phase == "list" {
					return nil, errors.New("listing failed")
				}
				return nil, nil
			}
			if phase == "flush" {
				e.conn = nftConnReturningErr(t, syscall.EPERM)
			}
			err := e.Apply()
			want := actionlog.Applied
			if phase != "success" {
				want = actionlog.Failed
			}
			if (err != nil) != (phase != "success") {
				t.Fatalf("error=%v phase=%s", err, phase)
			}
			if len(sink.records) != 1 || sink.records[0].Op != "integrate.firewall_ruleset" || sink.records[0].Result != want {
				t.Fatalf("records=%+v", sink.records)
			}
		})
	}
}

func TestBlockActionsCoverLiveDryRunAndFailure(t *testing.T) {
	for _, phase := range []string{"live", "manual", "dry-run", "refused", "failed", "already-blocked"} {
		t.Run(phase, func(t *testing.T) {
			sink := withActionSink(t)
			conn, _ := nftConnReturningErrsThenOK(t)
			e := newBlockedSetWireTestEngine(t, conn)
			e.dryRunEnabled = func() bool { return phase == "dry-run" }
			if phase == "refused" {
				e.cfg.InfraIPs = []string{"192.0.2.10"}
			}
			if phase == "failed" {
				e.conn = nftConnReturningErr(t, syscall.EPERM)
			}
			if phase == "already-blocked" {
				writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.10"}}})
				e.liveBlockLookup = func(*nftables.Set, []byte) (bool, error) { return true, nil }
			}
			var err error
			if phase == "manual" {
				err = e.BlockIPForce("192.0.2.10", "operator reason", time.Minute)
			} else {
				_, err = e.BlockIPOutcome("192.0.2.10", "auto-block test", time.Minute)
			}
			want := actionlog.Applied
			op := "respond.block_ip"
			switch phase {
			case "manual":
				op = "operate.manual_firewall"
			case "dry-run":
				want = actionlog.DryRun
			case "refused":
				want = actionlog.Refused
			case "failed":
				want = actionlog.Failed
			case "already-blocked":
				if len(sink.records) != 0 {
					t.Fatalf("no-op recorded: %+v", sink.records)
				}
				return
			}
			if len(sink.records) != 1 || sink.records[0].Op != op || sink.records[0].Result != want {
				t.Fatalf("records=%+v error=%v", sink.records, err)
			}
		})
	}
}

func TestManualFirewallFailureRecords(t *testing.T) {
	for _, method := range []string{"unblock", "allow", "remove-allow", "allow-port", "remove-port", "flush", "subnet", "unblock-subnet", "promote"} {
		t.Run(method, func(t *testing.T) {
			sink := withActionSink(t)
			e := newBlockedSetWireTestEngine(t, nftConnReturningErr(t, syscall.EPERM))
			e.setAllowed = namedIPv4Set("allowed_ips")
			var err error
			switch method {
			case "unblock":
				err = e.UnblockIP("192.0.2.10")
			case "allow":
				err = e.AllowIP("192.0.2.10", "via CLI")
			case "remove-allow":
				err = e.RemoveAllowIP("192.0.2.10")
			case "allow-port":
				err = e.AllowIPPort("192.0.2.10", 0, "tcp", "via CLI")
			case "remove-port":
				err = e.RemoveAllowIPPort("192.0.2.10", 80, "tcp")
			case "flush":
				err = e.FlushBlocked()
			case "subnet":
				err = e.BlockSubnet("bad", "via CLI", 0)
			case "unblock-subnet":
				err = e.UnblockSubnet("bad")
			case "promote":
				err = e.PromoteToPermanentBlock("192.0.2.10", "permblock")
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if len(sink.records) != 1 || sink.records[0].Result == actionlog.Applied || sink.records[0].Error == "" {
				t.Fatalf("records=%+v", sink.records)
			}
		})
	}
}

func TestSubnetSafetyRefusalsRecordRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cidr  string
		infra []string
		want  string
	}{
		{"IPv4 default route", "0.0.0.0/0", nil, "default route"},
		{"IPv6 default route", "::/0", nil, "default route"},
		{"unspecified", "::/128", nil, "non-routable range"},
		{"loopback", "127.0.0.0/8", nil, "protected range"},
		{"link-local", "fe80::/64", nil, "protected range"},
		{"infra IP", "192.0.2.0/24", []string{"192.0.2.1"}, "infra IP"},
		{"IPv6 infra IP", "2001:db8:1::/64", []string{"2001:db8:1::1"}, "infra IP"},
		{"contains infra range", "192.0.2.0/24", []string{"192.0.2.128/25"}, "infra range"},
		{"inside infra range", "192.0.2.128/26", []string{"192.0.2.128/25"}, "infra range"},
		{"resolved infra", "198.51.100.0/25", nil, "resolved from panel.example"},
		{"local address", "203.0.113.0/24", nil, "local host IP"},
		{"allowed address", "198.51.100.128/26", nil, "contains allowed IP"},
		{"port-allowed address", "198.51.100.192/26", nil, "contains port-allowed IP"},
	} {
		for _, automatic := range []bool{false, true} {
			source := "manual"
			if automatic {
				source = "automatic"
			}
			t.Run(tc.name+"/"+source, func(t *testing.T) {
				sink := withActionSink(t)
				conn, captured := nftConnCapturingRules(t)
				e := newBlockedSetWireTestEngine(t, conn)
				e.cfg.InfraIPs = tc.infra
				e.infraResolved = map[string]map[string]struct{}{"panel.example": {"198.51.100.7": {}}}
				e.localAddrsLookup = func() ([]string, error) { return []string{"203.0.113.5"}, nil }
				prior := FirewallState{
					Allowed:     []AllowedEntry{{IP: "198.51.100.129"}},
					PortAllowed: []PortAllowEntry{{IP: "198.51.100.193", Port: 25, Proto: "tcp"}},
					BlockedNet:  []SubnetEntry{{CIDR: "2001:db8:2::/64", Reason: "existing block"}},
				}
				writeRawFirewallState(t, e, prior)
				prior = readRawFirewallState(t, e)
				if err := e.ValidateSubnetBlock(tc.cidr); !errors.Is(err, ErrIPProtected) {
					t.Errorf("preflight error = %v, want ErrIPProtected", err)
				}
				if len(sink.records) != 0 {
					t.Fatalf("preflight recorded an action: %+v", sink.records)
				}
				reason, findingID := "via CLI", ""
				wantOp, wantActor := "operate.manual_firewall", actionlog.CLI
				if automatic {
					reason, findingID = "CSM auto-block: subnet attack", "subnet-finding"
					wantOp, wantActor = "respond.block_ip", actionlog.Daemon
				}
				err := e.BlockSubnetWithFindingID(tc.cidr, reason, time.Hour, findingID)
				if !errors.Is(err, ErrIPProtected) {
					t.Errorf("block error = %v, want ErrIPProtected", err)
				}
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("block error = %v, want reason containing %q", err, tc.want)
				}
				if len(sink.records) != 1 {
					t.Fatalf("records = %+v, want one refusal", sink.records)
				}
				rec := sink.records[0]
				if rec.Result != actionlog.Refused || rec.Action != "block_subnet" || rec.Target != tc.cidr || rec.Error != err.Error() || rec.FindingID != findingID || rec.Op != wantOp || rec.Actor != wantActor {
					t.Errorf("unexpected refusal record: %+v", rec)
				}
				if len(*captured) != 0 {
					t.Error("refused subnet sent a kernel transaction")
				}
				if got := readRawFirewallState(t, e); !reflect.DeepEqual(got, prior) {
					t.Errorf("refused subnet changed state: %+v", got)
				}
			})
		}
	}
}

func TestSubnetOperationalErrorsRecordFailed(t *testing.T) {
	for _, tc := range []struct {
		name string
		cidr string
		want string
	}{
		{"invalid CIDR", "invalid", "invalid CIDR"},
		{"IPv6 disabled", "2001:db8::/64", "no matching set"},
		{"kernel failure", "192.0.2.0/24", "operation not permitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := withActionSink(t)
			e := newBlockedSetWireTestEngine(t, nftConnReturningErr(t, syscall.EPERM))
			e.setBlockedNet = &nftables.Set{Table: e.table, Name: "blocked_nets", KeyType: nftables.TypeIPAddr, Interval: true}
			e.localAddrsLookup = func() ([]string, error) { return nil, nil }
			writeRawFirewallState(t, e, FirewallState{})
			prior := readRawFirewallState(t, e)
			err := e.BlockSubnet(tc.cidr, "via CLI", time.Hour)
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.Is(err, ErrIPProtected) {
				t.Fatalf("error = %v, want operational failure containing %q", err, tc.want)
			}
			if len(sink.records) != 1 {
				t.Fatalf("records = %+v, want one failure", sink.records)
			}
			rec := sink.records[0]
			if rec.Result != actionlog.Failed || rec.Action != "block_subnet" || rec.Target != tc.cidr || rec.Error != err.Error() {
				t.Errorf("unexpected failure record: %+v", rec)
			}
			if got := readRawFirewallState(t, e); !reflect.DeepEqual(got, prior) {
				t.Errorf("failed subnet changed state: %+v", got)
			}
		})
	}
}

func TestConcurrentAutomaticBlocksRecordOneMutation(t *testing.T) {
	sink := withActionSink(t)
	conn, _ := nftConnReturningErrsThenOK(t)
	e := newBlockedSetWireTestEngine(t, conn)
	e.liveBlockLookup = func(*nftables.Set, []byte) (bool, error) {
		return firewallStateHasBlocked(e.loadStateFile(), "192.0.2.10"), nil
	}
	var arrived sync.WaitGroup
	arrived.Add(2)
	e.SetVerdictAsker(func(context.Context, string, string) (string, string, string, error) {
		arrived.Done()
		arrived.Wait()
		return "block", "", "", nil
	})
	var done sync.WaitGroup
	done.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer done.Done()
			if _, err := e.BlockIPOutcome("192.0.2.10", "auto-block test", 0); err != nil {
				t.Error(err)
			}
		}()
	}
	done.Wait()
	if len(sink.records) != 1 {
		t.Fatalf("records=%d want one kernel mutation", len(sink.records))
	}
}
