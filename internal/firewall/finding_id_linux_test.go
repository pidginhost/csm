package firewall

import (
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/actionlog"
)

func TestFirewallBlockActionRetainsFindingIDAndOutcome(t *testing.T) {
	for _, phase := range []string{"live", "dry-run", "refused", "failed"} {
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
			const id = "0123456789abcdef"
			_, _ = e.BlockIPOutcomeWithFindingID("192.0.2.10", "CSM auto-block: evidence", time.Minute, id)
			want := map[string]actionlog.Result{"live": actionlog.Applied, "dry-run": actionlog.DryRun, "refused": actionlog.Refused, "failed": actionlog.Failed}[phase]
			if len(sink.records) != 1 || sink.records[0].FindingID != id || sink.records[0].Result != want {
				t.Fatalf("action lost cause or outcome: %+v", sink.records)
			}
		})
	}
}

func TestFirewallSubnetAndPromotionRetainFindingID(t *testing.T) {
	for _, kind := range []string{"subnet", "promotion"} {
		for _, failed := range []bool{false, true} {
			t.Run(kind+"/"+map[bool]string{false: "live", true: "failed"}[failed], func(t *testing.T) {
				sink := withActionSink(t)
				conn, _ := nftConnReturningErrsThenOK(t)
				e := newBlockedSetWireTestEngine(t, conn)
				e.setBlockedNet = &nftables.Set{Table: e.table, Name: "blocked_nets", KeyType: nftables.TypeIPAddr, Interval: true}
				writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.10", ExpiresAt: time.Now().Add(time.Hour)}}})
				if failed {
					e.conn = nftConnReturningErr(t, syscall.EPERM)
				}
				const id = "0123456789abcdef"
				var err error
				if kind == "subnet" {
					err = e.BlockSubnetWithFindingID("192.0.2.0/24", "CSM auto-block: subnet", time.Minute, id)
				} else {
					err = e.PromoteToPermanentBlockWithFindingID("192.0.2.10", "PERMBLOCK: evidence", id)
				}
				want := actionlog.Applied
				if failed {
					want = actionlog.Failed
				}
				if (err != nil) != failed || len(sink.records) != 1 || sink.records[0].FindingID != id || sink.records[0].Result != want {
					t.Fatalf("action lost cause or outcome: records=%+v err=%v", sink.records, err)
				}
			})
		}
	}
}

func TestFirewallFindingIDsStayLocalToEachOperation(t *testing.T) {
	sink := withActionSink(t)
	conn, _ := nftConnReturningErrsThenOK(t)
	e := newBlockedSetWireTestEngine(t, conn)
	var wg sync.WaitGroup
	expected := map[string]string{"192.0.2.10": "1111111111111111", "192.0.2.11": "2222222222222222"}
	for ip, id := range expected {
		wg.Go(func() {
			if _, err := e.BlockIPOutcomeWithFindingID(ip, "CSM auto-block: test", time.Minute, id); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if err := e.BlockIPForce("192.0.2.12", "operator decision", time.Minute); err != nil {
		t.Fatal(err)
	}
	expected["192.0.2.12"] = ""
	if len(sink.records) != 3 {
		t.Fatalf("records=%d, want three separate operations", len(sink.records))
	}
	for _, rec := range sink.records {
		id, ok := expected[rec.Target]
		if !ok || rec.FindingID != id {
			t.Errorf("operation inherited another cause: %+v", rec)
		}
	}
}
