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
			if n := strings.Count(out, "block of "+ip+" (reason manual)"); n != 1 {
				t.Fatalf("log = %q, want one line about the manual block of %s", out, ip)
			}
		})
	}
}

func TestUnblockClearsEachAutomaticReason(t *testing.T) {
	const ip = "203.0.113.18"
	for _, reason := range []string{"rcptToFailure", "authFailure", "loitering", "portScanning"} {
		t.Run(reason, func(t *testing.T) {
			sink := captureActionRecords(t)
			f := &fakeStalwart{bans: map[string][]stalwartapi.BlockedIP{ip: {{ID: "a1", Address: ip, Reason: reason}}}}
			d, _ := unbanDaemon(t, platform.MTAStalwart, f)

			d.stalwartUnban.add(ip)
			waitDrain(d)

			if !reflect.DeepEqual(f.deletes, [][]string{{"a1"}}) {
				t.Fatalf("deletes = %v, want a1", f.deletes)
			}
			if len(sink.records) != 1 || sink.records[0].Reason != reason {
				t.Fatalf("action records = %+v, want one with reason %s", sink.records, reason)
			}
		})
	}
}

// Only Stalwart's automatic reasons are lifted. Anything else, including a
// reason a later Stalwart adds, is left for the Stalwart admin.
func TestUnblockLeavesNonAutomaticReasons(t *testing.T) {
	const ip = "203.0.113.19"
	for _, tc := range []struct{ reason, log string }{
		{"other", "(reason other)"},
		{"", "(an unknown reason)"},
		{"spamTrap", "(reason spamTrap)"},
		{"bad\nreason", "(an unknown reason)"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			sink := captureActionRecords(t)
			f := &fakeStalwart{bans: map[string][]stalwartapi.BlockedIP{ip: {{ID: "k1", Address: ip, Reason: tc.reason}}}}
			d, _ := unbanDaemon(t, platform.MTAStalwart, f)

			out := captureAppliedBlockStderr(t, func() {
				d.stalwartUnban.add(ip)
				waitDrain(d)
			})

			if len(f.deletes) != 0 || len(sink.records) != 0 {
				t.Fatalf("deletes=%v records=%+v, want the entry left", f.deletes, sink.records)
			}
			if n := strings.Count(out, "block of "+ip+" "+tc.log); n != 1 {
				t.Fatalf("log = %q, want one line saying the block of %s stays %s", out, ip, tc.log)
			}
		})
	}
}

// A lookup answer naming another address is never acted on, whatever its
// reason or spelling.
func TestUnblockSkipsForeignEntries(t *testing.T) {
	sink := captureActionRecords(t)
	const ip = "203.0.113.20"
	f := &fakeStalwart{bans: map[string][]stalwartapi.BlockedIP{ip: {
		autoBan("x1", "203.0.113.21"),
		autoBan("x2", "203.0.113.0/24"),
		autoBan("x3", ""),
		autoBan("own", "::ffff:203.0.113.20"),
		autoBan("x4", "2001:db8::14"),
	}}}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)

	out := captureAppliedBlockStderr(t, func() {
		d.stalwartUnban.add(ip)
		waitDrain(d)
	})

	if !reflect.DeepEqual(f.deletes, [][]string{{"own"}}) {
		t.Fatalf("deletes = %v, want only the entry for %s", f.deletes, ip)
	}
	if len(sink.records) != 1 || sink.records[0].Target != ip {
		t.Fatalf("action records = %+v, want one for %s", sink.records, ip)
	}
	if n := strings.Count(out, "other addresses"); n != 1 {
		t.Fatalf("log = %q, want one line about the foreign entries", out)
	}
}

func TestUnblockClearsTwoAutomaticBansInOneCall(t *testing.T) {
	sink := captureActionRecords(t)
	const ip = "203.0.113.22"
	f := &fakeStalwart{bans: map[string][]stalwartapi.BlockedIP{ip: {
		autoBan("a1", ip),
		{ID: "a2", Address: ip, Reason: "loitering"},
	}}}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)

	d.stalwartUnban.add(ip)
	waitDrain(d)

	if !reflect.DeepEqual(f.deletes, [][]string{{"a1", "a2"}}) {
		t.Fatalf("deletes = %v, want a1 and a2 in one call", f.deletes)
	}
	if len(sink.records) != 2 || sink.records[0].Reason != "authFailure" || sink.records[1].Reason != "loitering" {
		t.Fatalf("action records = %+v, want one per ban", sink.records)
	}
	for _, r := range sink.records {
		if r.Target != ip || r.Result != actionlog.Applied {
			t.Fatalf("action record = %+v, want applied for %s", r, ip)
		}
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
	// The bound only keeps a caller stuck on Stalwart from hanging the run.
	select {
	case <-returned:
	case <-time.After(stalwartCallTimeout):
		close(f.hold)
		t.Fatal("firewallReleased waited on Stalwart")
	}
	if got := heldLookup(t, f); got != first {
		t.Fatalf("first lookup = %s, want %s", got, first)
	}
	// The proof: the caller returned while the lookup it queued is still
	// held. A caller that waited on Stalwart returns only after it ended.
	f.mu.Lock()
	inFlight, ended := f.inFlight, f.holdEnd
	f.mu.Unlock()
	if inFlight != 1 || ended != nil {
		close(f.hold)
		t.Fatalf("lookup in flight=%d ended=%v after the caller returned; want it still held", inFlight, ended)
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

	if len(f.lookups) != 0 || len(f.deletes) != 0 || f.reloads != 0 {
		t.Fatalf("lookups=%v deletes=%v reloads=%d, want no Stalwart call without a key", f.lookups, f.deletes, f.reloads)
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

// A lift whose reload was lost leaves a ban Stalwart enforces but no longer
// lists. An unblock that lifts nothing must still reload, so unblocking the
// address again finishes it.
func TestUnblockReloadsWhenNothingIsLifted(t *testing.T) {
	const ip = "203.0.113.30"
	for _, tc := range []struct {
		name string
		bans []stalwartapi.BlockedIP
	}{
		{"no ban listed", nil},
		{"manual only", []stalwartapi.BlockedIP{manualBlock("m1", ip)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := captureActionRecords(t)
			f := &fakeStalwart{bans: map[string][]stalwartapi.BlockedIP{ip: tc.bans}}
			d, _ := unbanDaemon(t, platform.MTAStalwart, f)

			d.stalwartUnban.add(ip)
			waitDrain(d)

			if f.reloads != 1 {
				t.Fatalf("reloads = %d, want one", f.reloads)
			}
			if len(f.deletes) != 0 {
				t.Fatalf("deletes = %v, want none", f.deletes)
			}
			if len(sink.records) != 0 {
				t.Fatalf("action records = %+v, want none for a reload", sink.records)
			}
			if f.unbounded != 0 {
				t.Fatalf("%d Stalwart calls ran without a 10 second deadline", f.unbounded)
			}
		})
	}
}

// The delete call reloads the list itself; a second reload would be waste.
func TestUnblockLiftSendsNoExtraReload(t *testing.T) {
	const ip = "203.0.113.31"
	f := &fakeStalwart{bans: map[string][]stalwartapi.BlockedIP{ip: {autoBan("b1", ip)}}}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)

	d.stalwartUnban.add(ip)
	waitDrain(d)

	if !reflect.DeepEqual(f.deletes, [][]string{{"b1"}}) || f.reloads != 0 {
		t.Fatalf("deletes = %v, reloads = %d, want one delete and no separate reload", f.deletes, f.reloads)
	}
}

func TestUnblockFailedReloadIsLoggedAndKeepsDraining(t *testing.T) {
	const bad, good = "203.0.113.32", "203.0.113.33"
	f := &fakeStalwart{
		bans:      map[string][]stalwartapi.BlockedIP{good: {autoBan("b6", good)}},
		reloadErr: errors.New("stalwart: HTTP 500"),
		hold:      make(chan struct{}),
		held:      make(chan string, 2),
	}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)

	out := captureAppliedBlockStderr(t, func() {
		d.stalwartUnban.add(bad)
		if got := heldLookup(t, f); got != bad {
			t.Fatalf("first lookup = %s, want %s", got, bad)
		}
		d.stalwartUnban.add(good)
		close(f.hold)
		waitDrain(d)
	})

	if n := strings.Count(out, "Stalwart may still refuse "+bad); n != 1 || strings.Count(out, "\n") != 1 || !strings.Contains(out, "reloading Stalwart's ban list") {
		t.Fatalf("log = %q, want one line saying the reload for %s failed", out, bad)
	}
	if !slices.Equal(f.lookups, []string{bad, good}) || f.reloads != 1 {
		t.Fatalf("lookups=%v reloads=%d, want bad then good and one failed reload", f.lookups, f.reloads)
	}
	if !reflect.DeepEqual(f.deletes, [][]string{{"b6"}}) {
		t.Fatalf("deletes = %v, want b6 lifted after the failed reload", f.deletes)
	}
}

func heldReload(t *testing.T, f *fakeStalwart) {
	t.Helper()
	select {
	case <-f.reloadHeld:
	case <-time.After(stalwartCallTimeout):
		t.Fatal("no drain asked Stalwart to reload its bans")
	}
}

func TestUnblockStopCancelsReload(t *testing.T) {
	const ip = "203.0.113.34"
	f := &fakeStalwart{reloadHold: make(chan struct{}), reloadHeld: make(chan struct{}, 2)}
	d, clients := unbanDaemon(t, platform.MTAStalwart, f)

	out := captureAppliedBlockStderr(t, func() {
		d.stalwartUnban.add(ip)
		heldReload(t, f)
		d.stalwartUnban.add("203.0.113.35")
		d.stalwartUnban.stop()
	})
	if !errors.Is(f.reloadEnd, context.Canceled) {
		t.Fatalf("reload ended with %v, want cancellation by stop", f.reloadEnd)
	}
	if out != "" {
		t.Fatalf("log = %q, want nothing for a stopped reload", out)
	}
	d.stalwartUnban.add("203.0.113.36")
	waitDrain(d)
	if *clients != 1 || !slices.Equal(f.lookups, []string{ip}) || f.reloads != 1 {
		t.Fatalf("clients=%d lookups=%v reloads=%d, want only the canceled call", *clients, f.lookups, f.reloads)
	}
}

// Requests arriving during a reload still use the one drain and coalesce
// by address, including another unblock of the address being reloaded.
func TestUnblockReloadCoalescesPendingRequests(t *testing.T) {
	const ip = "203.0.113.37"
	f := &fakeStalwart{reloadHold: make(chan struct{}), reloadHeld: make(chan struct{}, 2)}
	d, _ := unbanDaemon(t, platform.MTAStalwart, f)
	d.firewallReleased(ip, firewall.ReleaseUnban)
	heldReload(t, f)

	var adders sync.WaitGroup
	for _, kind := range []firewall.ReleaseKind{firewall.ReleaseUnban, firewall.ReleaseOperator} {
		adders.Go(func() {
			for range 100 {
				d.firewallReleased(ip, kind)
			}
		})
	}
	adders.Wait()
	d.stalwartUnban.mu.Lock()
	pending := len(d.stalwartUnban.pending)
	d.stalwartUnban.mu.Unlock()
	f.mu.Lock()
	lookups, reloads := len(f.lookups), f.reloads
	f.mu.Unlock()
	if pending != 1 || lookups != 1 || reloads != 1 {
		t.Fatalf("pending=%d lookups=%d reloads=%d, want one pending behind the held reload", pending, lookups, reloads)
	}
	close(f.reloadHold)
	waitDrain(d)
	if !slices.Equal(f.lookups, []string{ip, ip}) || f.reloads != 2 || f.reloadEnd != nil || f.unbounded != 0 {
		t.Fatalf("lookups=%v reloads=%d ended=%v unbounded=%d, want two bounded calls without retries", f.lookups, f.reloads, f.reloadEnd, f.unbounded)
	}
}
