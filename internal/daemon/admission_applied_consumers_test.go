package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// An applied admission block reaches the legacy consumers after its threat
// row: the tracker row and the Critical auto_block finding in history,
// which the block digest and alerts read. The owner never waits for them:
// the tracker's lock can be held for a whole scan.
func TestAdmissionHandsAppliedBlocksToLegacyConsumers(t *testing.T) {
	dir := t.TempDir()
	_, cleanup := openTestBoltStore(t, t.TempDir())
	t.Cleanup(cleanup)
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	blockedAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	expires := blockedAt.Add(24 * time.Hour)
	row := appliedRow(t, "7", "203.0.113.47", expires)
	row.FindingID = "0123456789abcdef"
	data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{
		{IP: "203.0.113.47", Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse, ActionID: string(row.Attempt.ID), BlockedAt: blockedAt, ExpiresAt: expires},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "firewall", "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checks.SetGlobalThreatDBForTest(dir))
	previous := attackdb.Global()
	attackdb.SetGlobal(attackdb.NewForTest(map[string]*attackdb.IPRecord{"203.0.113.47": {IP: "203.0.113.47"}}))
	t.Cleanup(func() { attackdb.SetGlobal(previous) })
	cfg := &config.Config{StatePath: dir}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs = true, true
	d := New(cfg, st, nil, "")
	opts := d.admissionOptions(nil)
	stop, served := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(served)
		d.appliedBlocks.serve(d, stop)
	}()
	t.Cleanup(func() {
		close(stop)
		<-served
	})

	held, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseTracker := func() { releaseOnce.Do(func() { close(release) }) }
	flushed := make(chan struct{})
	defer func() { releaseTracker(); <-flushed }()
	go func() {
		defer close(flushed)
		_, _ = checks.FlushAutoBlockState(dir, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	done := make(chan error, 1)
	go func() { done <- opts.Applied([]admission.AuditRow{row}) }()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		releaseTracker()
		t.Fatal("the applied block waited for the tracker lock")
	}
	releaseTracker()

	deadline := time.Now().Add(5 * time.Second)
	for {
		tracked := trackedAddresses(t, dir)
		notice := false
		history, _ := st.ReadHistory(10, 0)
		for _, f := range history {
			notice = notice || f.Check == "auto_block" && f.Severity == alert.Critical && f.SourceIP == "203.0.113.47"
		}
		if len(tracked) == 1 && tracked[0] == "203.0.113.47" && notice {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tracker %v, notice %v: the legacy consumers never recorded the block", tracked, notice)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// trackedAddresses reads the addresses the legacy tracker holds in dir.
func trackedAddresses(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "blocked_ips.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		IPs []struct {
			IP string `json:"ip"`
		} `json:"ips"`
	}
	if err = json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, b := range s.IPs {
		out = append(out, b.IP)
	}
	return out
}

// A slow tracker cannot grow the best-effort backlog beyond the durable
// delivery bound. Refusing a batch keeps it in the audit outbox for retry.
func TestAppliedBlockQueueBacklogBound(t *testing.T) {
	q := &appliedBlockQueue{}
	full := make([]checks.AdmissionBlock, int(admission.MaxAuditSlots))
	if !q.add(full) {
		t.Fatal("empty consumer refused one full audit delivery")
	}
	if q.add([]checks.AdmissionBlock{{IP: "203.0.113.48"}}) {
		t.Fatal("full consumer accepted another record")
	}
}

// consumerFixture is a daemon whose verified firewall state names rows,
// with the threat, attack and history stores open and permanent-block
// strikes counted.
type consumerFixture struct {
	dir  string
	d    *Daemon
	st   *state.Store
	rows []admission.AuditRow
}

func newConsumerFixture(t *testing.T, addrs ...string) *consumerFixture {
	t.Helper()
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	blockedAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	fx := &consumerFixture{dir: dir, st: st}
	var blocked []firewall.BlockedEntry
	records := map[string]*attackdb.IPRecord{}
	for i, addr := range addrs {
		row := appliedRow(t, fmt.Sprint(i+1), addr, blockedAt.Add(time.Duration(i+1)*time.Hour))
		fx.rows = append(fx.rows, row)
		blocked = append(blocked, firewall.BlockedEntry{IP: addr, Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse, ActionID: string(row.Attempt.ID), BlockedAt: blockedAt, ExpiresAt: row.ExpiresAt})
		records[addr] = &attackdb.IPRecord{IP: addr}
	}
	data, err := json.Marshal(firewall.FirewallState{Blocked: blocked})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "firewall", "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checks.SetGlobalThreatDBForTest(dir))
	previous := attackdb.Global()
	attackdb.SetGlobal(attackdb.NewForTest(records))
	t.Cleanup(func() { attackdb.SetGlobal(previous) })
	cfg := &config.Config{StatePath: dir}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs, cfg.AutoResponse.PermBlock = true, true, true
	fx.d = New(cfg, st, nil, "")
	return fx
}

// serve runs the consumer until the test ends.
func (fx *consumerFixture) serve(t *testing.T) {
	t.Helper()
	stop, served := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(served)
		fx.d.appliedBlocks.serve(fx.d, stop)
	}()
	t.Cleanup(func() {
		close(stop)
		<-served
	})
}

func (fx *consumerFixture) pending() int {
	fx.d.appliedBlocks.mu.Lock()
	defer fx.d.appliedBlocks.mu.Unlock()
	return len(fx.d.appliedBlocks.pending)
}

// recorded waits for the consumers to record want tracker rows and returns
// the tracked addresses in order, the strikes per address and the notices.
func (fx *consumerFixture) recorded(t *testing.T, want int) ([]string, map[string]int, int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		tracked := trackedAddresses(t, fx.dir)
		if len(tracked) >= want || time.Now().After(deadline) {
			// Let a wrongly repeated batch land before counting.
			time.Sleep(100 * time.Millisecond)
			tracked = trackedAddresses(t, fx.dir)
			strikes := map[string]int{}
			var tracker struct {
				IPs map[string][]time.Time `json:"ips"`
			}
			if data, err := os.ReadFile(filepath.Join(fx.dir, "permblock_tracker.json")); err == nil {
				if err = json.Unmarshal(data, &tracker); err != nil {
					t.Fatal(err)
				}
			}
			for ip, times := range tracker.IPs {
				strikes[ip] = len(times)
			}
			history, _ := fx.st.ReadHistory(100, 0)
			notices := 0
			for _, f := range history {
				if f.Check == "auto_block" && f.Severity == alert.Critical {
					notices++
				}
			}
			return tracked, strikes, notices
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Shutdown never waits for a consumer stuck behind a scan's tracker lock
// longer than the scan holds it: the owner's hand-off returns while the
// lock is held, and after the stop signal the scan, the consumer and the
// daemon's wait group all finish.
func TestAppliedConsumerShutdownReleasesTracker(t *testing.T) {
	_, cleanup := openTestBoltStore(t, t.TempDir())
	t.Cleanup(cleanup)
	fx := newConsumerFixture(t, "203.0.113.51")
	held, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseScan := func() { releaseOnce.Do(func() { close(release) }) }
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		_, _ = checks.FlushAutoBlockState(fx.dir, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	defer func() { releaseScan(); <-scanned }()
	<-held
	fx.d.wg.Add(1)
	go func() {
		defer fx.d.wg.Done()
		fx.d.appliedBlocks.serve(fx.d, fx.d.stopCh)
	}()
	done := make(chan error, 1)
	go func() { done <- fx.d.consumeAppliedBlocks(fx.rows) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hand-off waited for the tracker lock")
	}
	close(fx.d.stopCh)
	releaseScan()
	waited := make(chan struct{})
	go func() { fx.d.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("the consumer did not stop after the scan released the tracker")
	}
	<-scanned
	// A delivery after the consumer stopped is refused and keeps nothing in
	// memory, so the audit outbox redelivers it at the next start.
	if err := fx.d.consumeAppliedBlocks(fx.rows); err == nil || fx.pending() != 0 {
		t.Fatalf("late delivery: %v, %d pending; want a refusal with nothing kept", err, fx.pending())
	}
}

// A block the owner applies while the daemon stops, after the consumer has
// exited, is not lost: the delivery is refused, so the audit row stays
// pending, and the next process records it once.
func TestAppliedBlockDeliveredDuringShutdownIsRecordedNextStart(t *testing.T) {
	_, cleanup := openTestBoltStore(t, t.TempDir())
	t.Cleanup(cleanup)
	fx := newConsumerFixture(t, "203.0.113.55")
	stop := make(chan struct{})
	close(stop)
	fx.d.appliedBlocks.serve(fx.d, stop)
	if err := fx.d.consumeAppliedBlocks(fx.rows); err == nil {
		t.Fatal("a stopped consumer accepted a delivery it will never record")
	}
	next := &consumerFixture{dir: fx.dir, st: fx.st, rows: fx.rows, d: New(fx.d.cfg, fx.st, nil, "")}
	next.serve(t)
	if err := next.d.consumeAppliedBlocks(next.rows); err != nil {
		t.Fatal(err)
	}
	tracked, strikes, notices := next.recorded(t, 1)
	if len(tracked) != 1 || tracked[0] != "203.0.113.55" || strikes["203.0.113.55"] != 1 || notices != 1 {
		t.Fatalf("tracker %v, strikes %v, notices %d; want the block recorded once", tracked, strikes, notices)
	}
}

// The consumers run only after the durable threat write: a failed write
// queues nothing for them, and its retry records each block once. Rows
// whose firewall row was removed, names another action or another expiry
// queue nothing. A full consumer refuses the delivery so the audit outbox
// retries it, and the retry after a drain records it once.
func TestAppliedConsumersFollowDurableThreatWrite(t *testing.T) {
	storeDir := t.TempDir()
	sdb, cleanup := openTestBoltStore(t, storeDir)
	fx := newConsumerFixture(t, "203.0.113.52")
	if err := sdb.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fx.d.consumeAppliedBlocks(fx.rows); err == nil {
		t.Fatal("a failed threat write reported consumption")
	}
	if fx.pending() != 0 {
		t.Fatalf("a failed threat write queued %d blocks for the consumers", fx.pending())
	}
	cleanup()
	_, cleanup = openTestBoltStore(t, storeDir)
	t.Cleanup(cleanup)
	t.Cleanup(checks.SetGlobalThreatDBForTest(fx.dir))
	removed, other, expiry := appliedRow(t, "7", "203.0.113.57", fx.rows[0].ExpiresAt), fx.rows[0], fx.rows[0]
	other.Attempt.ID = admission.ActionID("act_" + strings.Repeat("8", 32))
	expiry.ExpiresAt = expiry.ExpiresAt.Add(time.Minute)
	if err := fx.d.consumeAppliedBlocks([]admission.AuditRow{removed, other, expiry}); err != nil {
		t.Fatal(err)
	}
	if fx.pending() != 0 {
		t.Fatalf("rows without a standing firewall row queued %d blocks", fx.pending())
	}
	full := make([]checks.AdmissionBlock, int(admission.MaxAuditSlots))
	fx.d.appliedBlocks.mu.Lock()
	fx.d.appliedBlocks.pending = full
	fx.d.appliedBlocks.mu.Unlock()
	if err := fx.d.consumeAppliedBlocks(fx.rows); err == nil {
		t.Fatal("a full consumer accepted the delivery")
	}
	if fx.pending() != len(full) {
		t.Fatalf("a refused delivery changed the backlog to %d", fx.pending())
	}
	fx.d.appliedBlocks.mu.Lock()
	fx.d.appliedBlocks.pending = nil
	fx.d.appliedBlocks.mu.Unlock()
	if err := fx.d.consumeAppliedBlocks(fx.rows); err != nil {
		t.Fatal(err)
	}
	fx.serve(t)
	tracked, strikes, notices := fx.recorded(t, 1)
	if len(tracked) != 1 || tracked[0] != "203.0.113.52" || strikes["203.0.113.52"] != 1 || notices != 1 {
		t.Fatalf("tracker %v, strikes %v, notices %d; want one of each", tracked, strikes, notices)
	}
}

// Blocks are recorded in delivery order, and a repeated delivery adds no
// row, strike or notice.
func TestAdmissionAppliedConsumerBatchOrder(t *testing.T) {
	_, cleanup := openTestBoltStore(t, t.TempDir())
	t.Cleanup(cleanup)
	fx := newConsumerFixture(t, "203.0.113.53", "203.0.113.54")
	for range 2 {
		if err := fx.d.consumeAppliedBlocks(fx.rows); err != nil {
			t.Fatal(err)
		}
	}
	fx.serve(t)
	tracked, strikes, notices := fx.recorded(t, 2)
	if !slices.Equal(tracked, []string{"203.0.113.53", "203.0.113.54"}) || strikes["203.0.113.53"] != 1 || strikes["203.0.113.54"] != 1 || notices != 2 {
		t.Fatalf("tracker %v, strikes %v, notices %d; want both once, in order", tracked, strikes, notices)
	}
}
