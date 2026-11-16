package daemon

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/stalwartapi"
)

// unbanDaemon returns a daemon whose host runs mta and whose Stalwart API is
// f, with nothing else running. It also returns how many clients were asked
// for.
func unbanDaemon(t *testing.T, mta platform.MTAKind, f *fakeStalwart) (*Daemon, *int) {
	t.Helper()
	useHost(t, platform.PanelNone, mta)
	clients := new(int)
	prevClient := stalwartClient
	stalwartClient = func(*config.Config) (stalwartAPI, error) {
		*clients++
		return f, nil
	}
	d := &Daemon{cfg: &config.Config{}, stopCh: make(chan struct{})}
	d.stalwartUnban = newStalwartUnban(d)
	t.Cleanup(func() {
		if d.stalwartUnban != nil {
			d.stalwartUnban.stop()
		}
		stalwartClient = prevClient
	})
	return d, clients
}

// waitDrain returns once the last drain started on d has ended.
func waitDrain(d *Daemon) {
	u := d.stalwartUnban
	if u == nil {
		return
	}
	u.mu.Lock()
	done := u.done
	u.mu.Unlock()
	if done != nil {
		<-done
	}
}

// heldLookup returns the address of the lookup f is holding. The bound only
// keeps a broken drain from hanging the run.
func heldLookup(t *testing.T, f *fakeStalwart) string {
	t.Helper()
	select {
	case ip := <-f.held:
		return ip
	case <-time.After(stalwartCallTimeout):
		close(f.hold)
		t.Fatal("no drain asked Stalwart for its bans")
		return ""
	}
}

func autoBan(id, ip string) stalwartapi.BlockedIP {
	return stalwartapi.BlockedIP{ID: id, Address: ip, Reason: "authFailure"}
}

func manualBlock(id, ip string) stalwartapi.BlockedIP {
	return stalwartapi.BlockedIP{ID: id, Address: ip, Reason: "manual"}
}

func TestUnblockClearsAutomaticStalwartBan(t *testing.T) {
	sink := captureActionRecords(t)
	const ip = "203.0.113.9"
	f := &fakeStalwart{bans: map[string][]stalwartapi.BlockedIP{ip: {autoBan("b1", ip)}}}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)

	d.stalwartUnban.add(ip)
	waitDrain(d)

	if !slices.Equal(f.lookups, []string{ip}) {
		t.Fatalf("lookups = %v, want one for %s", f.lookups, ip)
	}
	if !reflect.DeepEqual(f.deletes, [][]string{{"b1"}}) {
		t.Fatalf("deletes = %v, want b1", f.deletes)
	}
	if f.unbounded != 0 {
		t.Fatalf("%d Stalwart calls ran without a 10 second deadline", f.unbounded)
	}
	if len(sink.records) != 1 {
		t.Fatalf("action records = %+v, want one", sink.records)
	}
	r := sink.records[0]
	if r.Op != "operate.clear_stalwart_ban" || r.Target != ip || r.Reason != "authFailure" || r.Result != actionlog.Applied || r.Error != "" {
		t.Fatalf("action record = %+v, want an applied operate.clear_stalwart_ban for %s", r, ip)
	}
}

func TestUnblockLeavesManualStalwartBlock(t *testing.T) {
	const ip = "203.0.113.10"
	for _, tc := range []struct {
		name string
		bans []stalwartapi.BlockedIP
		want [][]string
	}{
		{"manual and automatic", []stalwartapi.BlockedIP{manualBlock("m1", ip), autoBan("b2", ip), manualBlock("m2", ip)}, [][]string{{"b2"}}},
		{"manual only", []stalwartapi.BlockedIP{manualBlock("m1", ip)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := captureActionRecords(t)
			f := &fakeStalwart{bans: map[string][]stalwartapi.BlockedIP{ip: tc.bans}}
			d, _ := unbanDaemon(t, platform.MTAStalwart, f)

			out := captureAppliedBlockStderr(t, func() {
				d.stalwartUnban.add(ip)
				waitDrain(d)
			})

			if !reflect.DeepEqual(f.deletes, tc.want) {
				t.Fatalf("deletes = %v, want %v", f.deletes, tc.want)
			}
			if len(sink.records) != len(tc.want) {
				t.Fatalf("action records = %+v, want one per lifted ban", sink.records)
			}
			if n := strings.Count(out, "manual block of "+ip); n != 1 {
				t.Fatalf("log = %q, want one line about the manual block of %s", out, ip)
			}
		})
	}
}

func TestFlushClearsNoStalwartBans(t *testing.T) {
	f := &fakeStalwart{}
	d, clients := unbanDaemon(t, platform.MTAStalwart, f)

	d.firewallReleased("", firewall.ReleaseOperator)
	d.firewallReleased("203.0.113.0/24", firewall.ReleaseOperator)
	d.firewallReleased("2001:db8::/64", firewall.ReleaseOperator)
	waitDrain(d)

	if *clients != 0 || len(f.lookups) != 0 {
		t.Fatalf("clients=%d lookups=%v, want no Stalwart call for a flush or a network", *clients, f.lookups)
	}
}

func TestUnbanAlsoClears(t *testing.T) {
	const ip = "198.51.100.4"
	f := &fakeStalwart{bans: map[string][]stalwartapi.BlockedIP{ip: {autoBan("b3", ip)}}}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)

	d.firewallReleased(ip, firewall.ReleaseUnban)
	waitDrain(d)

	if !slices.Equal(f.lookups, []string{ip}) || !reflect.DeepEqual(f.deletes, [][]string{{"b3"}}) {
		t.Fatalf("lookups=%v deletes=%v, want the unbanned address cleared", f.lookups, f.deletes)
	}
}

// An IPv4-mapped spelling is looked up as the IPv4 address Stalwart stores.
func TestUnblockLooksUpTheIPv4Spelling(t *testing.T) {
	f := &fakeStalwart{}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)

	d.firewallReleased("::ffff:192.0.2.7", firewall.ReleaseOperator)
	waitDrain(d)

	if !slices.Equal(f.lookups, []string{"192.0.2.7"}) {
		t.Fatalf("lookups = %v, want 192.0.2.7", f.lookups)
	}
}

func TestUnblockNeverBlocksTheCaller(t *testing.T) {
	const first = "203.0.113.9"
	f := &fakeStalwart{hold: make(chan struct{}), held: make(chan string, 16), bans: map[string][]stalwartapi.BlockedIP{first: {autoBan("b0", first)}}}
	var more []string
	for i := 1; i <= 10; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		more = append(more, ip)
		f.bans[ip] = []stalwartapi.BlockedIP{autoBan(fmt.Sprintf("b%d", i), ip)}
	}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)

	returned := make(chan struct{})
	go func() {
		d.firewallReleased(first, firewall.ReleaseOperator)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		close(f.hold)
		t.Fatal("firewallReleased waited on Stalwart")
	}
	if got := heldLookup(t, f); got != first {
		t.Fatalf("first lookup = %s, want %s", got, first)
	}
	// The drain is inside Stalwart; these wait for it.
	for _, ip := range more {
		d.firewallReleased(ip, firewall.ReleaseOperator)
	}
	d.stalwartUnban.mu.Lock()
	pending := len(d.stalwartUnban.pending)
	d.stalwartUnban.mu.Unlock()
	if pending != len(more) {
		t.Fatalf("pending = %d, want all %d waiting for the one drain", pending, len(more))
	}
	close(f.hold)
	waitDrain(d)

	wantLookups := append([]string{first}, more...)
	slices.Sort(wantLookups)
	gotLookups := slices.Sorted(slices.Values(f.lookups))
	if !slices.Equal(gotLookups, wantLookups) {
		t.Fatalf("lookups = %v, want each address once", f.lookups)
	}
	var deleted []string
	for _, ids := range f.deletes {
		deleted = append(deleted, ids...)
	}
	if len(f.deletes) != 11 || len(deleted) != 11 {
		t.Fatalf("deletes = %v, want one per address", f.deletes)
	}
	if f.maxInFlight != 1 {
		t.Fatalf("%d Stalwart lookups ran at once, want one goroutine", f.maxInFlight)
	}
}

func TestUnblockWithoutKeyLogsAndReturns(t *testing.T) {
	const ip = "203.0.113.11"
	f := &fakeStalwart{}
	d, clients := unbanDaemon(t, platform.MTAStalwart, f)
	stalwartClient = func(*config.Config) (stalwartAPI, error) {
		*clients++
		return nil, fmt.Errorf("/etc/csm/stalwart-api.key: %w", stalwartapi.ErrNoKeyFile)
	}

	out := captureAppliedBlockStderr(t, func() {
		d.stalwartUnban.add(ip)
		waitDrain(d)
		d.stalwartUnban.add(ip)
		waitDrain(d)
	})

	if len(f.lookups) != 0 || len(f.deletes) != 0 {
		t.Fatalf("lookups=%v deletes=%v, want no Stalwart call without a key", f.lookups, f.deletes)
	}
	if n := strings.Count(out, "Stalwart may still refuse "+ip); n != 2 {
		t.Fatalf("log = %q, want one line per unblock of %s", out, ip)
	}
}

// One address that fails does not stop the others, and is not retried.
func TestUnblockErrorKeepsDraining(t *testing.T) {
	sink := captureActionRecords(t)
	const bad, good = "203.0.113.12", "203.0.113.13"
	f := &fakeStalwart{
		bans:   map[string][]stalwartapi.BlockedIP{good: {autoBan("b5", good)}},
		banErr: map[string]error{bad: errors.New("stalwart: HTTP 500")},
	}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)

	out := captureAppliedBlockStderr(t, func() {
		d.stalwartUnban.add(bad)
		d.stalwartUnban.add(good)
		waitDrain(d)
	})

	if got := slices.Sorted(slices.Values(f.lookups)); !slices.Equal(got, []string{bad, good}) {
		t.Fatalf("lookups = %v, want each address once", f.lookups)
	}
	if !reflect.DeepEqual(f.deletes, [][]string{{"b5"}}) {
		t.Fatalf("deletes = %v, want b5", f.deletes)
	}
	if n := strings.Count(out, bad); n != 1 || !strings.Contains(out, "HTTP 500") {
		t.Fatalf("log = %q, want one line naming %s and the error", out, bad)
	}
	if len(sink.records) != 1 || sink.records[0].Target != good {
		t.Fatalf("action records = %+v, want one for %s", sink.records, good)
	}
}

func TestUnblockFailedDeleteIsRecorded(t *testing.T) {
	sink := captureActionRecords(t)
	const ip = "203.0.113.14"
	f := &fakeStalwart{
		bans:      map[string][]stalwartapi.BlockedIP{ip: {autoBan("b6", ip)}},
		deleteErr: errors.New("stalwart: b6 not destroyed"),
	}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)

	out := captureAppliedBlockStderr(t, func() {
		d.stalwartUnban.add(ip)
		waitDrain(d)
	})

	if len(sink.records) != 1 {
		t.Fatalf("action records = %+v, want one", sink.records)
	}
	r := sink.records[0]
	if r.Op != "operate.clear_stalwart_ban" || r.Result != actionlog.Failed || r.Error != "stalwart: b6 not destroyed" || r.Target != ip {
		t.Fatalf("action record = %+v, want a failed record with the client error", r)
	}
	if strings.Count(out, ip) != 1 {
		t.Fatalf("log = %q, want one line naming %s", out, ip)
	}
}

// Stopping ends the call in flight, quietly, and starts no new drain.
func TestUnblockDrainEndsWithTheDaemon(t *testing.T) {
	const ip = "203.0.113.15"
	f := &fakeStalwart{hold: make(chan struct{}), held: make(chan string, 4)}
	d, clients := unbanDaemon(t, platform.MTAStalwart, f)

	out := captureAppliedBlockStderr(t, func() {
		d.stalwartUnban.add(ip)
		heldLookup(t, f)
		d.stalwartUnban.stop()
	})
	if !errors.Is(f.holdEnd, context.Canceled) {
		t.Fatalf("call in flight ended with %v, want it canceled by the stop", f.holdEnd)
	}
	if out != "" {
		t.Fatalf("log = %q, want nothing for a stop", out)
	}

	d.stalwartUnban.add("203.0.113.16")
	waitDrain(d)
	if *clients != 1 || len(f.lookups) != 1 {
		t.Fatalf("clients=%d lookups=%v, want nothing after the stop", *clients, f.lookups)
	}
}

// Adds racing a stop: stop returns only once the call in flight has ended,
// and no add after it reaches Stalwart or starts a drain.
func TestUnblockStopRacesAdds(t *testing.T) {
	f := &fakeStalwart{hold: make(chan struct{}), held: make(chan string, 1024)}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)
	u := d.stalwartUnban

	u.add("203.0.113.1")
	heldLookup(t, f)
	stopped := make(chan struct{})
	var adders sync.WaitGroup
	for g := range 4 {
		adders.Add(1)
		go func() {
			defer adders.Done()
			for i := 0; ; i++ {
				u.add(fmt.Sprintf("198.51.100.%d", (g*50+i)%250+1))
				select {
				case <-stopped:
					// Keep adding after stop returned.
					for j := range 20 {
						u.add(fmt.Sprintf("192.0.2.%d", g*20+j+1))
					}
					return
				default:
				}
			}
		}()
	}
	u.stop()

	f.mu.Lock()
	ended, inFlight, lookups := f.holdEnd, f.inFlight, len(f.lookups)
	f.mu.Unlock()
	u.mu.Lock()
	done := u.done
	u.mu.Unlock()
	if !errors.Is(ended, context.Canceled) || inFlight != 0 {
		t.Fatalf("stop returned with the call in flight: end=%v in flight=%d", ended, inFlight)
	}
	close(stopped)
	adders.Wait()

	f.mu.Lock()
	after := len(f.lookups)
	f.mu.Unlock()
	u.mu.Lock()
	running, sameDone := u.running, u.done == done
	u.mu.Unlock()
	if after != lookups || running || !sameDone {
		t.Fatalf("after stop: lookups %d -> %d, running=%v, new drain=%v; want nothing", lookups, after, running, !sameDone)
	}
}

func TestUnblockStopTwiceAndUnused(t *testing.T) {
	d, clients := unbanDaemon(t, platform.MTAStalwart, &fakeStalwart{})
	d.stalwartUnban.stop()
	d.stalwartUnban.stop()
	d.stalwartUnban.add("203.0.113.17")
	waitDrain(d)
	if *clients != 0 {
		t.Fatalf("clients = %d, want none after stop", *clients)
	}
}

func TestNotStalwartHostDoesNothing(t *testing.T) {
	for _, mta := range []platform.MTAKind{platform.MTAPostfix, platform.MTAExim} {
		f := &fakeStalwart{}
		d, clients := unbanDaemon(t, mta, f)

		d.firewallReleased("203.0.113.9", firewall.ReleaseOperator)
		d.firewallReleased("203.0.113.9", firewall.ReleaseUnban)
		waitDrain(d)

		if d.stalwartUnban != nil || *clients != 0 {
			t.Fatalf("%v host: unban=%v clients=%d, want nothing", mta, d.stalwartUnban, *clients)
		}
	}
}
