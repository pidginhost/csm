//go:build linux && nftkernel

package store

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/firewall"
)

func kernelSetElements(t *testing.T, name string) []nftables.SetElement {
	t.Helper()
	conn := &nftables.Conn{}
	set, err := conn.GetSetByName(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}, name)
	if err != nil {
		t.Fatal(err)
	}
	elems, err := conn.GetSetElements(set)
	if err != nil {
		t.Fatal(err)
	}
	return elems
}

func kernelBatchMember(id, target string) firewall.ActionRequest {
	return firewall.ActionRequest{ID: id, Operation: "block", Target: target, Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}
}

// Invalid members before, between and after valid IPv4 and IPv6 members are
// left out: only the valid ones are charged, written in one kernel
// transaction and verified together, and a full set evicts nothing.
func TestKernelDurableBlockBatchRunsOnlyValidMembers(t *testing.T) {
	var delivered []firewall.FirewallAction
	db, e, _ := durableKernelEngine(t, func(a firewall.FirewallAction) error { delivered = append(delivered, a); return nil })
	header := firewall.ActionRequest{ID: "batch-kernel", Operation: "block", Actor: "auto", Source: "scan", Automatic: true}
	badTTL := kernelBatchMember("member-ttl", "203.0.113.52")
	badTTL.TTL = 0
	members := []firewall.ActionRequest{
		kernelBatchMember("member-range", "203.0.113.0/24"),
		kernelBatchMember("member-a", "203.0.113.50"),
		badTTL,
		kernelBatchMember("member-b", "2001:db8::50"),
		kernelBatchMember("member-full", "203.0.113.51"),
		kernelBatchMember("member-again", "203.0.113.50"),
	}
	budget := &firewall.ScanAdmission{Window: time.Now().UTC().Format("2006-01-02T15"), Limit: 10}
	result, err := e.BlockBatchRequest(header, members, budget)
	if err != nil || result.Action.Phase != "verified" || len(result.Action.Members) != 2 {
		t.Fatalf("batch = %#v, %v", result, err)
	}
	want := []firewall.BlockRefusal{firewall.BlockRefusedInvalid, "", firewall.BlockRefusedInvalid, "", firewall.BlockRefusedFull, firewall.BlockRefusedDuplicate}
	if fmt.Sprint(result.Refusals) != fmt.Sprint(want) {
		t.Fatalf("refusals = %q, want %q", result.Refusals, want)
	}
	if count, err := db.ReadFirewallScanBudget(budget.Window); err != nil || count != 2 {
		t.Fatalf("charged %d, %v; want the two valid members", count, err)
	}
	stored, err := db.ReadFirewallAction(header.ID)
	if err != nil || stored.Phase != "verified" || len(stored.Members) != 2 {
		t.Fatalf("stored batch = %#v, %v", stored, err)
	}
	for _, check := range []struct{ set, ip string }{{"blocked_ips", "203.0.113.50"}, {"blocked_ips6", "2001:db8::50"}} {
		key := net.ParseIP(check.ip).To4()
		if key == nil {
			key = net.ParseIP(check.ip).To16()
		}
		var evidence []firewall.ActionElement
		for _, s := range stored.KernelAfter {
			if s.Name == check.set {
				evidence = s.Elements
			}
		}
		live := kernelSetElements(t, check.set)
		if len(live) != 1 || !bytes.Equal(live[0].Key, key) || live[0].Timeout <= 0 || len(evidence) != 1 || live[0].Comment != evidence[0].Comment {
			t.Fatalf("%s = %#v, evidence %#v", check.set, live, evidence)
		}
	}
	var batchAudits []firewall.FirewallAction
	for _, a := range delivered {
		if a.Request.ID == header.ID {
			batchAudits = append(batchAudits, a)
		}
	}
	if len(batchAudits) != 1 || len(batchAudits[0].Members) != 2 || batchAudits[0].Phase != "verified" {
		t.Fatalf("batch audit = %#v", batchAudits)
	}
	again, err := e.BlockBatchRequest(header, members, budget)
	if err != nil || again.Action.Phase != "verified" || again.Refusals != nil {
		t.Fatalf("replayed batch = %#v, %v", again, err)
	}
	if count, _ := db.ReadFirewallScanBudget(budget.Window); count != 2 || len(kernelSetElements(t, "blocked_ips")) != 1 {
		t.Fatalf("replay charged or wrote again: %d charges", count)
	}
}

// A full set refuses every new member; nothing is evicted for a batch.
func TestKernelDurableBlockBatchNeverEvicts(t *testing.T) {
	db, e, d := durableKernelEngine(t)
	for _, ip := range []string{"203.0.113.60", "203.0.113.61"} {
		if _, err := d.BlockIPRequest(firewall.ActionRequest{ID: "single-" + ip[len(ip)-2:], Operation: "block", Target: ip, Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}, nil); err != nil {
			t.Fatal(err)
		}
	}
	before, _, err := db.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	header := firewall.ActionRequest{ID: "batch-full", Operation: "block", Actor: "auto", Source: "scan", Automatic: true}
	result, err := e.BlockBatchRequest(header, []firewall.ActionRequest{kernelBatchMember("member-c", "203.0.113.62"), kernelBatchMember("member-d", "203.0.113.63")}, nil)
	if err != nil || result.Action.Request.ID != "" || fmt.Sprint(result.Refusals) != fmt.Sprint([]firewall.BlockRefusal{firewall.BlockRefusedFull, firewall.BlockRefusedFull}) {
		t.Fatalf("batch over a full set = %#v, %v", result, err)
	}
	after, _, err := db.ReadFirewallState()
	if err != nil || !reflect.DeepEqual(after, before) || len(kernelSetElements(t, "blocked_ips")) != 2 {
		t.Fatalf("a batch evicted: %#v, %v", after.Blocked, err)
	}
}

func TestKernelDurableBlockBatchLeaseClock(t *testing.T) {
	db, e, _ := durableKernelEngine(t)
	at := time.Now().Round(0)
	prior := firewall.FirewallState{Blocked: []firewall.BlockedEntry{{IP: "203.0.113.70", Reason: "earlier", BlockedAt: at, ExpiresAt: at.Add(time.Hour)}}}
	_, revision, err := db.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReplaceFirewallState(revision, prior); err != nil {
		t.Fatal(err)
	}
	// The row has expired on the lease clock, although wall time says otherwise.
	e.SetLeaseFloor(at.Add(2 * time.Hour))
	header := firewall.ActionRequest{ID: "batch-clock", Operation: "block", Actor: "auto", Source: "scan", Automatic: true}
	result, err := e.BlockBatchRequest(header, []firewall.ActionRequest{kernelBatchMember("member-clock-a", "203.0.113.70"), kernelBatchMember("member-clock-b", "203.0.113.71")}, nil)
	if err != nil || result.Action.Phase != "verified" || len(result.Action.Members) != 2 {
		t.Fatalf("lease-clock batch = %#v, %v", result, err)
	}
	if !result.Action.CreatedAt.Equal(result.Action.After.Blocked[1].BlockedAt) || len(kernelSetElements(t, "blocked_ips")) != 2 {
		t.Fatal("batch lost its common lease instant or member effects")
	}
}
