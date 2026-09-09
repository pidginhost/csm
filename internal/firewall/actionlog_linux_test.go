//go:build linux

package firewall

import (
	"context"
	"errors"
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
