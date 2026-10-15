//go:build linux && nftkernel

package admissionowner

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/verdict"
)

// kernelNamespace moves the test goroutine's thread into a new network
// namespace until the test ends and returns a handle on it.
func kernelNamespace(t *testing.T) int {
	t.Helper()
	runtime.LockOSThread()
	orig, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	if err = unix.Unshare(unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(orig)
		runtime.UnlockOSThread()
		t.Fatalf("kernel firewall tests require CAP_SYS_ADMIN and CAP_NET_ADMIN: %v", err)
	}
	ns, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Setns(orig, unix.CLONE_NEWNET)
		_ = unix.Close(orig)
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(ns)
		err := unix.Setns(orig, unix.CLONE_NEWNET)
		_ = unix.Close(orig)
		if err != nil {
			t.Fatalf("restore network namespace: %v", err)
		}
		runtime.UnlockOSThread()
	})
	return ns
}

// enterNamespace moves the owner goroutine into ns for the rest of its
// life: the engine dials netlink on the calling thread, and the owner
// makes every engine call. The goroutine stays locked to its thread, which
// the runtime discards once the owner stops.
func enterNamespace(t *testing.T, o *Owner, ns int) {
	t.Helper()
	if err := o.do(func() error {
		runtime.LockOSThread()
		return unix.Setns(ns, unix.CLONE_NEWNET)
	}); err != nil {
		t.Fatal(err)
	}
}

// kernelEngine is the real engine with each call the owner makes counted.
type kernelEngine struct {
	*firewall.Engine
	mu    sync.Mutex
	calls map[string]int
}

func (k *kernelEngine) count(name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls[name]++
}

func (k *kernelEngine) counted() map[string]int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return maps.Clone(k.calls)
}

func (k *kernelEngine) CheckBlockBatchEffects(m []firewall.BlockMember) ([]firewall.BlockCheck, error) {
	k.count("CheckBlockBatchEffects")
	return k.Engine.CheckBlockBatchEffects(m)
}

func (k *kernelEngine) RetireBlockActions(a []firewall.BlockAction) ([]bool, error) {
	k.count("RetireBlockActions")
	return k.Engine.RetireBlockActions(a)
}

func (k *kernelEngine) BlockAdmissionSnapshot(m []firewall.BlockMember, shadow []string) (firewall.BlockAdmission, error) {
	k.count("BlockAdmissionSnapshot")
	return k.Engine.BlockAdmissionSnapshot(m, shadow)
}

func (k *kernelEngine) ApplyBlockBatch(m []firewall.BlockMember) ([]firewall.BlockResult, error) {
	k.count("ApplyBlockBatch")
	return k.Engine.ApplyBlockBatch(m)
}

func (k *kernelEngine) LeaseNow() time.Time {
	k.count("LeaseNow")
	return k.Engine.LeaseNow()
}

func (k *kernelEngine) MarkBlockActionsUnverified(a []string) (int, error) {
	k.count("MarkBlockActionsUnverified")
	return k.Engine.MarkBlockActionsUnverified(a)
}

func (k *kernelEngine) ProbeBlockState() error {
	k.count("ProbeBlockState")
	return k.Engine.ProbeBlockState()
}

// kernelElement is one set element as read: its configured timeout and,
// when timed, its absolute expiry.
type kernelElement struct {
	timeout time.Duration
	expires time.Time
}

// firewallView is the firewall state file and the namespace's ruleset:
// tables, chains, sets and rules, and every set's elements by key.
type firewallView struct {
	state    []byte
	tables   []*nftables.Table
	chains   []*nftables.Chain
	sets     map[string]*nftables.Set
	rules    map[string][]*nftables.Rule
	elements map[string]map[string]kernelElement
}

// readFirewall reads the state file under dir and the ruleset of the test
// thread's namespace. Rule counters are traffic, not configuration, and
// are left out.
func readFirewall(t *testing.T, dir string) firewallView {
	t.Helper()
	v := firewallView{sets: map[string]*nftables.Set{}, rules: map[string][]*nftables.Rule{}, elements: map[string]map[string]kernelElement{}}
	var err error
	if v.state, err = os.ReadFile(filepath.Join(dir, "firewall", "state.json")); err != nil {
		t.Fatal(err)
	}
	conn, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	if v.tables, err = conn.ListTables(); err != nil {
		t.Fatal(err)
	}
	if v.chains, err = conn.ListChains(); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.chains {
		rules, err := conn.GetRules(c.Table, c)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			for i, e := range r.Exprs {
				if _, ok := e.(*expr.Counter); ok {
					r.Exprs[i] = &expr.Counter{}
				}
			}
		}
		v.rules[c.Table.Name+"/"+c.Name] = rules
	}
	for _, table := range v.tables {
		sets, err := conn.GetSets(table)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range sets {
			name := table.Name + "/" + s.Name
			v.sets[name] = s
			read := time.Now()
			elements, err := conn.GetSetElements(s)
			if err != nil {
				t.Fatal(err)
			}
			byKey := map[string]kernelElement{}
			for _, el := range elements {
				key := fmt.Sprintf("%s-%s-%t-%s-%v-%q", hex.EncodeToString(el.Key), hex.EncodeToString(el.KeyEnd), el.IntervalEnd, hex.EncodeToString(el.Val), el.VerdictData, el.Comment)
				e := kernelElement{timeout: el.Timeout}
				if el.Expires > 0 {
					e.expires = read.Add(el.Expires)
				}
				byKey[key] = e
			}
			v.elements[name] = byKey
		}
	}
	return v
}

// sameFirewall fails t unless after holds before's state file byte for
// byte, its ruleset, and every element with the same timeout and an
// absolute expiry within the engine's readback slack.
func sameFirewall(t *testing.T, before, after firewallView) {
	t.Helper()
	if !bytes.Equal(before.state, after.state) {
		t.Errorf("the state file changed:\n%s\n->\n%s", before.state, after.state)
	}
	if !reflect.DeepEqual(before.tables, after.tables) || !reflect.DeepEqual(before.chains, after.chains) ||
		!reflect.DeepEqual(before.sets, after.sets) || !reflect.DeepEqual(before.rules, after.rules) {
		t.Error("the ruleset changed")
	}
	for name, was := range before.elements {
		now := after.elements[name]
		if len(now) != len(was) {
			t.Errorf("set %s holds %d elements, held %d", name, len(now), len(was))
		}
		for key, e := range was {
			n, ok := now[key]
			switch {
			case !ok:
				t.Errorf("set %s lost %s", name, key)
			case n.timeout != e.timeout || n.expires.IsZero() != e.expires.IsZero() ||
				!firewall.CoversExpiry(n.expires, e.expires) || !firewall.CoversExpiry(e.expires, n.expires):
				t.Errorf("set %s element %s: timeout %v expiring %v, was %v expiring %v", name, key, n.timeout, n.expires, e.timeout, e.expires)
			}
		}
	}
}

// Spec 6.5: a dry run against a healthy engine in an isolated network
// namespace, with no pending recovery, asks the panel and forecasts, and
// changes nothing it enforces. Its selections cover both address
// families, a panel allow and a failed call, real covering blocks of both
// families, a promotion and repeats the forecast already holds. The owner
// only reads the engine's lease clock and admission snapshot; the firewall
// state file stays byte for byte, and the kernel keeps its rules and set
// elements, each with its timeout and absolute expiry.
func TestKernelDryRunLeavesTheFirewallUnchanged(t *testing.T) {
	ns := kernelNamespace(t)
	dir := t.TempDir()
	e, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true, IPv6: true}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Apply(); err != nil {
		t.Fatal(err)
	}
	for ip, ttl := range map[string]time.Duration{"198.51.100.9": 0, "2001:db8::99": 48 * time.Hour, "198.51.100.11": time.Hour} {
		if err = e.BlockIPForce(ip, "manual", ttl); err != nil {
			t.Fatal(err)
		}
	}
	if err = e.BlockSubnet("203.0.113.0/24", "manual", time.Hour); err != nil {
		t.Fatal(err)
	}
	engine := &kernelEngine{Engine: e, calls: map[string]int{}}
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	panel := newFakePanel("block")
	panel.answer = func(ip string) (verdict.Response, error) {
		switch ip {
		case "192.0.2.30":
			return verdict.Response{Verdict: "allow"}, nil
		case "192.0.2.31":
			return answerError(ip)
		}
		return verdict.Response{Verdict: "block"}, nil
	}
	opts := previewOptions(f)
	opts.Blocks = func() BlockEngine { return engine }
	opts.Policy = (&policyReader{p: dryVerdictPolicy(1, panel)}).read
	o := f.start(opts)
	enterNamespace(t, o, ns)
	heldMono(t, o)
	before := readFirewall(t, dir)

	ids := map[string]admission.CandidateID{}
	for _, addr := range []string{"192.0.2.10", "2001:db8::10", "192.0.2.30", "192.0.2.31", "198.51.100.9", "2001:db8::99"} {
		ids[addr] = observe(t, o, p, f, addr, "offset=1")
	}
	ids["promote"], _ = queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.40", admission.KindPromote)
	turn(t, o)
	readyAnswers(t, o, 4)
	turn(t, o)
	f.host.advance(time.Second)
	for _, addr := range []string{"192.0.2.10", "2001:db8::10"} {
		ids[addr+" repeat"] = observe(t, o, p, f, addr, "offset=2")
	}
	turn(t, o)
	after := readFirewall(t, dir)

	for name, id := range ids {
		c := candidate(t, o, id)
		want := admission.StateDryRun
		if name == "192.0.2.30" {
			want = admission.StateRefused
		}
		if c.State != want || c.Attempts != 0 {
			t.Errorf("%s pick = %+v", name, c)
		}
	}
	fc := forecastOf(t, o)
	var want [admission.PredictionSlots]uint64
	want[admission.PredictCapacityAdmit], want[admission.PredictExistingActual] = 3, 2
	want[admission.PredictExistingShadow], want[admission.PredictNotModelled] = 2, 1
	if fc == nil || fc.picks != want || len(fc.entries) != 3 {
		t.Fatalf("forecast = %+v, want picks %v", fc, want)
	}
	if asked, _, _, _ := panel.state(); len(asked) != 4 {
		t.Errorf("asked %v", asked)
	}
	if s := verdictState(t, o); s.AllowEndings != 1 || s.Failed != 1 {
		t.Errorf("verdict status = %+v", s)
	}
	calls := engine.counted()
	if calls["BlockAdmissionSnapshot"] == 0 || calls["LeaseNow"] == 0 {
		t.Errorf("the forecast did not read the engine: %v", calls)
	}
	delete(calls, "BlockAdmissionSnapshot")
	delete(calls, "LeaseNow")
	if len(calls) != 0 {
		t.Errorf("a dry run made engine calls %v", calls)
	}
	if used := liveUsed(t, o); used != 0 {
		t.Errorf("a dry run charged %d live units", used)
	}
	sameFirewall(t, before, after)
}
