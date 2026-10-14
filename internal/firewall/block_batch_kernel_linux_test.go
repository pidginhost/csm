//go:build linux && nftkernel

package firewall

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
)

func newKernelBatchEngine(t *testing.T) *Engine {
	t.Helper()
	isolatedFirewallNamespace(t)
	e, err := NewEngine(&FirewallConfig{Enabled: true, IPv6: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	return e
}

func kernelBlockMember(action, ip string, ttl time.Duration) BlockMember {
	return BlockMember{Action: action, IP: ip, Reason: "lane general", ExpiresAt: time.Now().Add(ttl)}
}

func kernelBlockElements(t *testing.T, e *Engine, set *nftables.Set) map[string]nftables.SetElement {
	t.Helper()
	elements, err := e.conn.GetSetElements(set)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]nftables.SetElement{}
	for _, el := range elements {
		out[net.IP(el.Key).String()] = el
	}
	return out
}

func TestKernelBlockBatchAppliesOnlyValidMembers(t *testing.T) {
	e := newKernelBatchEngine(t)
	members := []BlockMember{
		kernelBlockMember("act bad", "192.0.2.1", time.Hour),
		kernelBlockMember("act_v4", "203.0.113.20", time.Hour),
		kernelBlockMember("act_mapped", "::ffff:203.0.113.21", time.Hour),
		kernelBlockMember("act_v6", "2001:db8::20", 90*time.Minute),
		kernelBlockMember("act_loop", "127.0.0.1", time.Hour),
		kernelBlockMember("act_short", "203.0.113.22", 5*time.Second),
		kernelBlockMember("act_dup", "203.0.113.20", time.Hour),
	}

	results, err := e.ApplyBlockBatch(members)
	if err != nil {
		t.Fatal(err)
	}
	if got := effects(results); got != "failed/invalid applied/ failed/invalid applied/ failed/protected applied/ failed/duplicate" {
		t.Fatalf("effects = %s (%+v)", got, results)
	}
	v4, v6 := kernelBlockElements(t, e, e.setBlocked), kernelBlockElements(t, e, e.setBlocked6)
	if len(v4) != 2 || len(v6) != 1 {
		t.Fatalf("kernel holds %v and %v", v4, v6)
	}
	for ip, ttl := range map[string]time.Duration{"203.0.113.20": time.Hour, "203.0.113.22": 5 * time.Second, "2001:db8::20": 90 * time.Minute} {
		el, ok := v4[ip]
		if !ok {
			el = v6[ip]
		}
		if el.Timeout <= 0 || el.Timeout > ttl || el.Expires <= 0 || el.Expires > el.Timeout {
			t.Fatalf("%s timeout %v, %v left; want at most %v", ip, el.Timeout, el.Expires, ttl)
		}
	}
}

func TestKernelBlockBatchRejectionAppliesNothing(t *testing.T) {
	e := newKernelBatchEngine(t)
	name := e.setBlocked6.Name
	e.setBlocked6.Name = "missing_blocked_set"
	e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
		if set == e.setBlocked6 {
			return nil, nil
		}
		return e.conn.GetSetElements(set)
	}
	members := []BlockMember{kernelBlockMember("act_v4", "203.0.113.20", time.Hour), kernelBlockMember("act_v6", "2001:db8::20", time.Hour)}

	results, err := e.ApplyBlockBatch(members)
	if err != nil {
		t.Fatal(err)
	}
	if got := effects(results); got != "failed/ failed/" || !errors.Is(results[0].Err, syscall.ENOENT) {
		t.Fatalf("effects = %s, error %v", got, results[0].Err)
	}
	if v4 := kernelBlockElements(t, e, e.setBlocked); len(v4) != 0 {
		t.Fatalf("a rejected transaction left %v in the kernel", v4)
	}
	if rows := e.loadStateFile().Blocked; len(rows) != 0 {
		t.Fatalf("a rejected batch left rows %+v", rows)
	}

	e.setBlocked6.Name, e.liveBlockedDump = name, nil
	if results, err := e.ApplyBlockBatch(members); err != nil || effects(results) != "applied/ applied/" {
		t.Fatalf("retry = %s, %v", effects(results), err)
	}
}

func TestKernelBlockBatchUnverifiedRowsStayOutOfTheKernel(t *testing.T) {
	e := newKernelBatchEngine(t)
	members := []BlockMember{kernelBlockMember("act_a", "203.0.113.20", time.Hour), kernelBlockMember("act_b", "203.0.113.21", time.Hour)}
	if results, err := e.ApplyBlockBatch(members); err != nil || effects(results) != "applied/ applied/" {
		t.Fatalf("apply = %s, %v", effects(results), err)
	}
	if marked, err := e.MarkBlockActionsUnverified([]string{"act_a"}); err != nil || marked != 1 {
		t.Fatalf("mark = %d, %v", marked, err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	v4 := kernelBlockElements(t, e, e.setBlocked)
	if _, ok := v4["203.0.113.20"]; ok || len(v4) != 1 {
		t.Fatalf("after restoring, the kernel holds %v; want only the verified row", v4)
	}
	if e.IsBlocked("203.0.113.20") || !e.IsBlocked("203.0.113.21") {
		t.Fatal("IsBlocked disagrees with the rows")
	}

	again := []BlockMember{kernelBlockMember("act_c", "203.0.113.21", time.Hour), kernelBlockMember("act_d", "203.0.113.22", time.Hour)}
	if results, err := e.ApplyBlockBatch(again); err != nil || effects(results) != "failed/existing_effect applied/" {
		t.Fatalf("second batch = %s, %v", effects(results), err)
	}
}

// Apply saves the lease clock with the boot it was read in, so the next
// engine on the same boot resumes from it.
func TestKernelApplySavesTheLeaseCheckpoint(t *testing.T) {
	isolatedFirewallNamespace(t)
	dir := t.TempDir()
	e, err := NewEngine(&FirewallConfig{Enabled: true, IPv6: true}, dir)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	clock := &leaseSteps{wall: at, elapsed: at}
	boot := &bootReading{id: leaseBootA, since: time.Hour}
	e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
	e.SetBootClock(boot.read)
	writeEngineStateFile(t, filepath.Join(dir, "firewall"), FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.2", ExpiresAt: at.Add(time.Hour)},
	}})
	for i := range 2 {
		if err := e.Apply(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "firewall", leaseCheckpointFile)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var ck leaseCheckpoint
		want := at.Add(time.Duration(i) * time.Minute)
		if err := json.Unmarshal(data, &ck); err != nil || !ck.Lease.Equal(want) || ck.BootID != leaseBootA || ck.SinceBoot != boot.since {
			t.Fatalf("apply %d checkpoint %s, %v", i, data, err)
		}
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("checkpoint permissions: %v, %v", info, err)
		}
		got := kernelBlockElements(t, e, e.setBlocked)
		if len(got) != 1 || got["203.0.113.2"].Timeout != time.Hour-time.Duration(i)*time.Minute {
			t.Fatalf("apply %d restored the wrong lifetime: %+v", i, got)
		}
		clock.advance(time.Minute)
		clock.step(-time.Hour)
		boot.since += time.Minute
	}
}
