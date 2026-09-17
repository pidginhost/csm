//go:build linux && nftkernel

package store

import (
	"errors"
	"github.com/pidginhost/csm/internal/actionlog"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

type durableEngine interface {
	AttachLifecycle(*firewall.Lifecycle) error
	BlockIPRequest(firewall.ActionRequest, *firewall.ScanAdmission) (firewall.BlockOutcome, error)
	RecoverActions() error
	UndoAction(firewall.ActionRequest) (firewall.FirewallAction, error)
}

func lifecycleNamespace(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(fd)
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := unix.Setns(fd, unix.CLONE_NEWNET)
		_ = unix.Close(fd)
		runtime.UnlockOSThread()
		if err != nil {
			t.Error(err)
		}
	})
}
func durableKernelEngine(t *testing.T, audit ...func(firewall.FirewallAction) error) (*DB, *firewall.Engine, durableEngine) {
	t.Helper()
	lifecycleNamespace(t)
	db := openSnapshotDB(t)
	if _, err := db.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
		t.Fatal(err)
	}
	e, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true, IPv6: true, DenyTempIPLimit: 2}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d, ok := any(e).(durableEngine)
	if !ok {
		t.Fatal("engine has no durable action boundary")
	}
	writer := func(firewall.FirewallAction) error { return nil }
	if len(audit) > 0 {
		writer = audit[0]
	}
	if err := d.AttachLifecycle(&firewall.Lifecycle{Store: db, Audit: writer}); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	return db, e, d
}
func TestKernelDurableBlockReplaceUndo(t *testing.T) {
	db, e, d := durableKernelEngine(t)
	req := firewall.ActionRequest{ID: "temporary", Operation: "block", Target: "192.0.2.19", Actor: "cli", Source: "cli", TTL: time.Hour}
	if out, err := d.BlockIPRequest(req, nil); err != nil || out != firewall.BlockOutcomeLive {
		t.Fatalf("block=%s,%v", out, err)
	}
	first, err := db.ReadFirewallAction(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	req.ID = "replacement"
	req.TTL = 0
	if _, err := d.BlockIPRequest(req, nil); err != nil {
		t.Fatal(err)
	}
	second, err := db.ReadFirewallAction(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !second.After.Blocked[0].ExpiresAt.IsZero() {
		t.Fatal("replacement retained timeout")
	}
	undo := firewall.ActionRequest{ID: "undo", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: req.ID}
	if _, err := d.UndoAction(undo); err != nil {
		t.Fatal(err)
	}
	state, _, err := db.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	if !state.Blocked[0].ExpiresAt.Equal(first.After.Blocked[0].ExpiresAt) {
		t.Fatal("undo renewed expiry")
	}
	if err := e.UnblockIP(req.Target); err != nil {
		t.Fatal(err)
	}
	if blocked, err := e.IsBlockedLive(req.Target); err != nil || blocked {
		t.Fatalf("unblock=%v,%v", blocked, err)
	}
}
func TestKernelDurableUnknownPreventsOtherMutations(t *testing.T) {
	db, e, d := durableKernelEngine(t)
	req := firewall.ActionRequest{ID: "block", Operation: "block", Target: "192.0.2.29", Actor: "cli", Source: "cli", TTL: time.Hour}
	if _, err := d.BlockIPRequest(req, nil); err != nil {
		t.Fatal(err)
	}
	a, err := db.ReadFirewallAction(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Change only provenance: membership and timeout still look correct.
	conn := &nftables.Conn{}
	table := &nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}
	set, err := conn.GetSetByName(table, "blocked_ips")
	if err != nil {
		t.Fatal(err)
	}
	elems, err := conn.GetSetElements(set)
	if err != nil {
		t.Fatal(err)
	}
	elems[0].Comment = "changed externally"
	elems[0].Timeout = time.Hour
	conn.FlushSet(set)
	if err := conn.SetAddElements(set, elems); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	undo := firewall.ActionRequest{ID: "undo-changed", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: a.Request.ID}
	if _, err := d.UndoAction(undo); err == nil {
		t.Fatal("undo accepted changed provenance")
	}
	// Inject an unfinished intent to prove every block-affecting entry point gates it.
	state, revision, err := db.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	a.Request.ID = "pending"
	a.Before = state
	a.After = firewall.FirewallState{}
	a.Revision = revision
	if _, _, err := db.AdmitFirewallAction(a); err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{e.Apply, e.FlushBlocked, func() error { return e.UpdateCloudflareSet(nil, nil) }, func() error { return e.RefreshDOSExemptSets(nil) }, func() error { return e.AllowIP(req.Target, "operator") }, func() error { return e.UnblockIP(req.Target) }, func() error { return e.PromoteToPermanentBlock(req.Target, "promote") }} {
		if err := call(); err == nil {
			t.Fatal("mutation bypassed pending recovery")
		}
	}
	if err := d.RecoverActions(); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("changed kernel recovered as success: %v", err)
	}
}

func TestKernelDurableRestartRecoversWithoutReplay(t *testing.T) {
	db, e, d := durableKernelEngine(t)
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	calls := 0
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		calls++
		if calls == 3 {
			return errors.New("crash before applied outcome")
		}
		return previous(b, fn)
	}
	req := firewall.ActionRequest{ID: "interrupted", Operation: "block", Target: "192.0.2.39", Actor: "cli", Source: "cli", TTL: time.Hour}
	if _, err := d.BlockIPRequest(req, nil); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("interrupted outcome=%v", err)
	}
	if blocked, err := e.IsBlockedLive(req.Target); err != nil || !blocked {
		t.Fatalf("kernel mutation missing: %v,%v", blocked, err)
	}
	boltUpdate = previous
	restarted, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true, IPv6: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	next := any(restarted).(durableEngine)
	if err := next.AttachLifecycle(&firewall.Lifecycle{Store: db, Audit: func(firewall.FirewallAction) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	if err := next.RecoverActions(); err != nil {
		t.Fatalf("restart recovery: %v", err)
	}
	a, err := db.ReadFirewallAction(req.ID)
	if err != nil || a.Phase != "verified" {
		t.Fatalf("recovered=%#v,%v", a, err)
	}
	if outcome, err := next.BlockIPRequest(req, nil); err != nil || outcome != firewall.BlockOutcomeNoop {
		t.Fatalf("replay outcome=%s,%v", outcome, err)
	}
	again, err := db.ReadFirewallAction(req.ID)
	if err != nil || !again.After.Blocked[0].ExpiresAt.Equal(a.After.Blocked[0].ExpiresAt) {
		t.Fatalf("retry renewed expiry: %#v,%v", again, err)
	}
}

func TestKernelDurableBlockRefusesUntrackedLiveEntry(t *testing.T) {
	_, _, d := durableKernelEngine(t)
	conn := &nftables.Conn{}
	set, err := conn.GetSetByName(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}, "blocked_ips")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetAddElements(set, []nftables.SetElement{{Key: []byte{192, 0, 2, 79}, Comment: "untracked"}}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.BlockIPRequest(firewall.ActionRequest{ID: "different-target", Operation: "block", Target: "192.0.2.80", Actor: "cli", Source: "cli"}, nil); err == nil {
		t.Fatal("mutation overwrote untracked live state")
	}
	elems, err := conn.GetSetElements(set)
	if err != nil || len(elems) != 1 || elems[0].Comment != "untracked" {
		t.Fatalf("untracked entry changed: %#v,%v", elems, err)
	}
}
func TestKernelDurableApplyHasRecoverableAdmission(t *testing.T) {
	db, e, _ := durableKernelEngine(t)
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	calls := 0
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		calls++
		if calls == 3 {
			return errors.New("crash before apply outcome")
		}
		return previous(b, fn)
	}
	if err := e.Apply(); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("apply lacked recoverable admission: %v", err)
	}
	pending, err := db.PendingFirewallActions()
	if err != nil || len(pending) != 1 || pending[0].Request.Operation != "apply" {
		t.Fatalf("apply intent=%#v,%v", pending, err)
	}
}

func TestKernelDurableUndoRefusesWholeRulesetApply(t *testing.T) {
	var apply firewall.FirewallAction
	_, e, d := durableKernelEngine(t, func(a firewall.FirewallAction) error {
		if a.Request.Operation == "apply" {
			apply = a
		}
		return nil
	})
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}

	if _, err := d.UndoAction(firewall.ActionRequest{ID: "undo-apply", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: apply.Request.ID}); err == nil {
		t.Fatal("block undo claimed to reverse complete ruleset configuration")
	}
}

type lifecycleAuditSink struct {
	mu      sync.Mutex
	records []actionlog.Record
}

func (s *lifecycleAuditSink) Write(r actionlog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
	return nil
}
func (s *lifecycleAuditSink) WriteDurable(r actionlog.Record) error { return s.Write(r) }
func TestKernelDurableAuditHasOneLinkedOutcome(t *testing.T) {
	sink := &lifecycleAuditSink{}
	actionlog.SetSink(sink, "")
	t.Cleanup(func() { actionlog.SetSink(nil, "") })
	_, e, _ := durableKernelEngine(t, nil)
	if err := e.BlockIPForce("192.0.2.91", "via CLI", time.Hour); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var blocks []actionlog.Record
	for _, r := range sink.records {
		if r.Action == "block" {
			blocks = append(blocks, r)
		}
	}
	if len(blocks) != 1 || blocks[0].ActionID == "" || blocks[0].Actor != actionlog.CLI || blocks[0].Result != "verified" {
		t.Fatalf("durable block audit=%#v", blocks)
	}
}

func TestKernelDurableRequestDefaultsReplay(t *testing.T) {
	db, _, d := durableKernelEngine(t)
	req := firewall.ActionRequest{ID: "default-identity", Target: "192.0.2.101", TTL: time.Hour}
	if _, err := d.BlockIPRequest(req, nil); err != nil {
		t.Fatal(err)
	}
	first, err := db.ReadFirewallAction(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := d.BlockIPRequest(req, nil); err != nil || out != firewall.BlockOutcomeNoop {
		t.Fatalf("retry=%s,%v", out, err)
	}
	last, err := db.ReadFirewallAction(req.ID)
	if err != nil || !last.After.Blocked[0].ExpiresAt.Equal(first.After.Blocked[0].ExpiresAt) {
		t.Fatal("replay changed expiry", err)
	}
}
func TestKernelDurableSubnetRequestReplayAndDryRun(t *testing.T) {
	db, e, _ := durableKernelEngine(t)
	req := firewall.ActionRequest{ID: "subnet-request", Target: "192.0.2.0/28", TTL: time.Hour, Actor: "daemon", Source: "scan", Automatic: true}
	budget := &firewall.ScanAdmission{Window: time.Now().Format("2006-01-02T15"), Limit: 2}
	e.SetDryRunEnabledFunc(func() bool { return true })
	if err := e.BlockSubnetRequest(req, budget); !errors.Is(err, firewall.ErrActionDryRun) {
		t.Fatalf("subnet dry-run must return an explicit non-applied outcome: %v", err)
	}
	if _, err := db.ReadFirewallAction(req.ID); !errors.Is(err, firewall.ErrActionMissing) {
		t.Fatalf("dry-run admitted: %v", err)
	}
	e.SetDryRunEnabledFunc(func() bool { return false })
	if err := e.BlockSubnetRequest(req, budget); err != nil {
		a, _ := db.ReadFirewallAction(req.ID)
		t.Fatalf("%v detail=%s", err, a.Detail)
	}
	first, err := db.ReadFirewallAction(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.Request.Operation != "block_subnet" {
		t.Fatalf("operation=%s", first.Request.Operation)
	}
	e.SetDryRunEnabledFunc(func() bool { return true })

	if err := e.BlockSubnetRequest(req, budget); err != nil {
		a, _ := db.ReadFirewallAction(req.ID)
		t.Fatalf("%v detail=%s", err, a.Detail)
	}
	used, err := db.ReadFirewallScanBudget(budget.Window)
	if err != nil || used != 1 {
		t.Fatalf("budget=%d,%v", used, err)
	}
}
func TestKernelDurableReplacementRestoresEviction(t *testing.T) {
	db, e, d := durableKernelEngine(t)
	for i, req := range []firewall.ActionRequest{
		{ID: "victim", Target: "192.0.2.111", TTL: time.Hour},
		{ID: "survivor", Target: "192.0.2.112", TTL: 2 * time.Hour},
		{ID: "replace-me", Target: "192.0.2.113"},
	} {
		if _, err := d.BlockIPRequest(req, nil); err != nil {
			t.Fatalf("setup %d: %v", i, err)
		}
	}
	before, _, err := db.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.BlockIPRequest(firewall.ActionRequest{ID: "replacement-with-eviction", Target: "192.0.2.113", TTL: 3 * time.Hour}, nil); err != nil {
		t.Fatal(err)
	}
	a, err := db.ReadFirewallAction("replacement-with-eviction")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Before.Blocked) != 3 || len(a.After.Blocked) != 2 {
		t.Fatalf("missing eviction evidence: %#v", a)
	}
	if _, err := d.UndoAction(firewall.ActionRequest{ID: "undo-eviction", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: a.Request.ID}); err != nil {
		t.Fatal(err)
	}
	after, _, err := db.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("undo did not restore complete metadata: before=%#v after=%#v", before, after)
	}
	if live, err := e.IsBlockedLive("192.0.2.111"); err != nil || !live {
		t.Fatalf("eviction victim absent: %v,%v", live, err)
	}
}
func TestKernelDurableUndoRejectsChangedTimeout(t *testing.T) {
	_, _, d := durableKernelEngine(t)
	req := firewall.ActionRequest{ID: "timeout", Target: "192.0.2.121", TTL: time.Hour}
	if _, err := d.BlockIPRequest(req, nil); err != nil {
		t.Fatal(err)
	}
	conn := &nftables.Conn{}
	set, err := conn.GetSetByName(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}, "blocked_ips")
	if err != nil {
		t.Fatal(err)
	}
	elems, err := conn.GetSetElements(set)
	if err != nil {
		t.Fatal(err)
	}
	elems[0].Timeout = 2 * time.Hour
	conn.FlushSet(set)
	if err := conn.SetAddElements(set, elems); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UndoAction(firewall.ActionRequest{ID: "undo-timeout", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: req.ID}); !errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("changed expiry accepted: %v", err)
	}
}

func TestKernelDurableMaintenanceMetadataAndExpiredUndo(t *testing.T) {
	var actions []firewall.FirewallAction
	db, e, d := durableKernelEngine(t, func(a firewall.FirewallAction) error { actions = append(actions, a); return nil })
	if err := e.TempAllowIP("192.0.2.131", "temporary", 30*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	if count := e.CleanExpiredAllows(); count != 1 {
		t.Fatalf("cleaned=%d", count)
	}
	cleanup := actions[len(actions)-1]
	if cleanup.Request.Operation != "temp_allow_expired" || cleanup.Request.Actor != "daemon" {
		t.Fatalf("cleanup identity=%#v", cleanup.Request)
	}
	if _, err := d.UndoAction(firewall.ActionRequest{ID: "undo-expired-allow", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: cleanup.Request.ID}); err != nil {
		t.Fatal(err)
	}
	conn := &nftables.Conn{}
	set, err := conn.GetSetByName(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}, "allowed_ips")
	if err != nil {
		t.Fatal(err)
	}
	elems, err := conn.GetSetElements(set)
	if err != nil || len(elems) != 0 {
		t.Fatalf("expired allow rearmed: %#v,%v", elems, err)
	}
	state, _, err := db.ReadFirewallState()
	if err != nil || len(state.Allowed) != 1 || state.Allowed[0].ExpiresAt.After(time.Now()) {
		t.Fatalf("lost historical expiry: %#v,%v", state, err)
	}
	if err := e.AllowIPPort("192.0.2.132", 443, "tcp", "operator"); err != nil {
		t.Fatal(err)
	}
	port := actions[len(actions)-1]
	if port.Request.Operation != "configure_port_allow" || port.Request.Target != "192.0.2.132:443/tcp" {
		t.Fatalf("port identity=%#v", port.Request)
	}
}
func TestKernelDurableUndoReplayKeepsCurrentCache(t *testing.T) {
	_, e, d := durableKernelEngine(t)
	if _, err := d.BlockIPRequest(firewall.ActionRequest{ID: "original", Target: "192.0.2.141"}, nil); err != nil {
		t.Fatal(err)
	}
	undo := firewall.ActionRequest{ID: "inverse", Operation: "undo", UndoOf: "original", Actor: "cli", Source: "cli"}
	if _, err := d.UndoAction(undo); err != nil {
		t.Fatal(err)
	}
	if _, err := d.BlockIPRequest(firewall.ActionRequest{ID: "later", Target: "192.0.2.142"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UndoAction(undo); err != nil {
		t.Fatal(err)
	}
	if !e.IsBlocked("192.0.2.142") {
		t.Fatal("undo replay replaced current cache with historical state")
	}
}

func TestKernelDurableApplyRecoveryRejectsRulesOnlyDrift(t *testing.T) {
	db, e, d := durableKernelEngine(t)
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	calls := 0
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		calls++
		if calls == 4 {
			return errors.New("crash before verified apply")
		}
		return previous(b, fn)
	}
	if err := e.Apply(); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("interrupted apply=%v", err)
	}
	boltUpdate = previous
	conn := &nftables.Conn{}
	table := &nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}
	conn.AddChain(&nftables.Chain{Name: "external_drift", Table: table})
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := d.RecoverActions(); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("rules-only drift falsely verified: %v", err)
	}
	pending, err := db.PendingFirewallActions()
	if err != nil || len(pending) != 1 {
		t.Fatalf("recovery evidence lost: %#v,%v", pending, err)
	}
}
func TestKernelDurableApplyRecoveryProvesLostReply(t *testing.T) {
	_, e, d := durableKernelEngine(t)
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	calls := 0
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		calls++
		if calls == 3 {
			return errors.New("crash before applied phase")
		}
		return previous(b, fn)
	}
	if err := e.Apply(); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("interrupted apply=%v", err)
	}
	boltUpdate = previous
	if err := d.RecoverActions(); err != nil {
		t.Fatalf("cannot prove atomic apply: %v", err)
	}
}

func TestKernelDurableAuditFailureKeepsVerifiedOutcome(t *testing.T) {
	outage := false
	db, _, d := durableKernelEngine(t, func(firewall.FirewallAction) error {
		if outage {
			return errors.New("audit unavailable")
		}
		return nil
	})
	outage = true
	req := firewall.ActionRequest{ID: "verified-audit-pending", Target: "192.0.2.171", Automatic: true, Actor: "daemon", Source: "scan", TTL: time.Hour}
	out, err := d.BlockIPRequest(req, &firewall.ScanAdmission{Window: time.Now().Format("2006-01-02T15"), Limit: 2})
	if out != firewall.BlockOutcomeLive || !errors.Is(err, firewall.ErrActionAuditPending) {
		t.Fatalf("verified outcome hidden: %s,%v", out, err)
	}
	pending, err := db.FirewallAuditPending()
	if err != nil || len(pending) != 1 || pending[0].Phase != "verified" {
		t.Fatalf("audit retry lost: %#v,%v", pending, err)
	}
}
func TestKernelDurableProtectedRefusalIsAudited(t *testing.T) {
	sink := &lifecycleAuditSink{}
	actionlog.SetSink(sink, "")
	t.Cleanup(func() { actionlog.SetSink(nil, "") })
	_, e, _ := durableKernelEngine(t, nil)
	if err := e.BlockIPForce("127.0.0.1", "via CLI", time.Hour); !errors.Is(err, firewall.ErrIPProtected) {
		t.Fatalf("protected refusal=%v", err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, record := range sink.records {
		if record.Action == "block" && record.Result == actionlog.Refused && record.ActionID == "" {
			return
		}
	}
	t.Fatal("pre-admission refusal lost audit evidence")
}

func TestKernelDurableUndoAuditFailureReportsVerifiedEffect(t *testing.T) {
	outage := false
	_, e, d := durableKernelEngine(t, func(firewall.FirewallAction) error {
		if outage {
			return errors.New("audit unavailable")
		}
		return nil
	})
	if _, err := d.BlockIPRequest(firewall.ActionRequest{ID: "undo-audit-original", Target: "192.0.2.182"}, nil); err != nil {
		t.Fatal(err)
	}
	outage = true
	a, err := d.UndoAction(firewall.ActionRequest{ID: "undo-audit", Operation: "undo", UndoOf: "undo-audit-original", Actor: "cli", Source: "cli"})
	if a.Phase != "verified" || !errors.Is(err, firewall.ErrActionAuditPending) {
		t.Fatalf("verified undo effect hidden: phase=%s err=%v", a.Phase, err)
	}
	if e.IsBlocked("192.0.2.182") {
		t.Fatal("verified undo left stale cache")
	}
}
