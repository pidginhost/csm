//go:build integration

package learn

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/hostfacts"
	"github.com/pidginhost/csm/internal/store"
)

// Native tests run against real pinned containers (Plan B task 10 harness:
// docs/superpowers/e2e/antispam-learning/containers.sh). They fail, never
// skip, without their environment:
//
//	CSM_LEARN_CONTROLLER  rspamd's private controller socket
//	CSM_LEARN_RSPAMD_UID  the uid that serves it
//	CSM_LEARN_SCAN        rspamd's normal worker socket, for scores
//	CSM_LEARN_CONTROL     rspamd's control socket, for fuzzy_sync
//	CSM_LEARN_REDIS       the fuzzy storage's Redis, host:port
type nativeEnv struct {
	client        Client
	scan, control string
	redis         string
	uid           int
	ledger        *Ledger
	bodies        *Bodies
	publisher     *Publisher
	rng           *rand.Rand
	nextID        uint64
	words         []string
}

func native(t *testing.T) *nativeEnv {
	t.Helper()
	get := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("%s is not set; run docs/superpowers/e2e/antispam-learning/containers.sh", name)
		}
		return v
	}
	uid, err := strconv.Atoi(get("CSM_LEARN_RSPAMD_UID"))
	if err != nil {
		t.Fatal(err)
	}
	e := &nativeEnv{scan: get("CSM_LEARN_SCAN"), control: get("CSM_LEARN_CONTROL"), redis: get("CSM_LEARN_REDIS"), uid: uid,
		rng: rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 7))}
	e.client = Client{Controller: get("CSM_LEARN_CONTROLLER"), RspamdUID: uid,
		Run: func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
			// rspamadm control needs the shared control socket explicitly.
			if name == "rspamadm" && len(args) > 0 && args[0] == "control" {
				args = append([]string{"control", "-s", e.control}, args[1:]...)
			}
			return hostfacts.RunCommand(ctx, limit, name, args...)
		}}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.ledger = Open(db)
	e.bodies = &Bodies{Dir: t.TempDir() + "/anchors", owner: os.Getuid()}
	e.publisher = NewPublisher(e.client, e.ledger, e.bodies)
	for i := range 2000 {
		e.words = append(e.words, fmt.Sprintf("w%dx%s", i, strconv.FormatUint(e.rng.Uint64()%100000, 36)))
	}
	return e
}

// text returns n random words from the env's vocabulary.
func (e *nativeEnv) text(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = e.words[e.rng.IntN(len(e.words))]
	}
	return out
}

func message(words []string) []byte {
	return []byte("From: sender@example.com\r\nTo: user@example.net\r\nSubject: offer\r\nMessage-ID: <" +
		strconv.FormatInt(time.Now().UnixNano(), 36) + "@example.com>\r\nContent-Type: text/plain\r\n\r\n" + strings.Join(words, " ") + "\r\n")
}

// variant replaces k words.
func (e *nativeEnv) variant(words []string, k int) []string {
	out := append([]string(nil), words...)
	for range k {
		out[e.rng.IntN(len(out))] = e.words[e.rng.IntN(len(e.words))] + "v"
	}
	return out
}

func (e *nativeEnv) digest(t *testing.T, body []byte) Digest {
	t.Helper()
	insp, err := e.client.Inspect(context.Background(), body)
	if err != nil || insp.Distinct != 1 {
		t.Fatalf("inspect: %+v %v", insp, err)
	}
	return insp.Results[0].Queried
}

// anchor stores a cluster for body with target tv and publishes it.
func (e *nativeEnv) anchor(t *testing.T, body []byte, tv int32) Digest {
	t.Helper()
	d := e.digest(t, body)
	e.nextID++
	id := e.nextID
	s, err := e.bodies.Stage(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.bodies.Commit(s, id); err != nil {
		t.Fatal(err)
	}
	if err := e.ledger.Update(func(tx LedgerTx) error {
		now := time.Now().UTC()
		if err := tx.PutCluster(Cluster{ID: id, Anchor: d, BodyLen: s.Len, BodySHA: s.SHA, Revision: 1, Created: now, LastReport: now}); err != nil {
			return err
		}
		return tx.PutTarget(Target{Digest: d, ClusterID: id, T: tv, Revision: 1, Phase: PhaseRead})
	}); err != nil {
		t.Fatal(err)
	}
	e.settle(t, d)
	return d
}

// setT moves d's target and publishes it.
func (e *nativeEnv) setT(t *testing.T, d Digest, tv int32) {
	t.Helper()
	if err := e.ledger.Update(func(tx LedgerTx) error {
		cur, _, err := tx.Target(d)
		if err != nil {
			return err
		}
		cur.T, cur.Revision, cur.Phase = tv, cur.Revision+1, PhaseRead
		return tx.PutTarget(cur)
	}); err != nil {
		t.Fatal(err)
	}
	e.settle(t, d)
}

// settle runs turns until d is verified at its target.
func (e *nativeEnv) settle(t *testing.T, d Digest) {
	t.Helper()
	for range 6 {
		res, err := e.publisher.Turn(context.Background(), d)
		if err == nil && res.Done {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("target %s never settled", d[:8])
}

func (e *nativeEnv) value(t *testing.T, d Digest) (int64, bool) {
	t.Helper()
	insp, err := e.client.InspectDigests(context.Background(), []Digest{d})
	if err != nil {
		t.Fatal(err)
	}
	v, present, err := insp.ExactValue(d)
	if err != nil {
		t.Fatal(err)
	}
	return v, present
}

// score scans body through the normal worker and returns CSM_FUZZY_SPAM.
func (e *nativeEnv) score(t *testing.T, body []byte) float64 {
	t.Helper()
	status, reply, err := hostfacts.ControllerDo(context.Background(), e.scan, e.uid, http.MethodPost, "/checkv2", nil, body, 4<<20)
	if err != nil || status != http.StatusOK {
		t.Fatalf("scan: status %d err %v", status, err)
	}
	var r struct {
		Symbols map[string]struct {
			Score float64 `json:"score"`
		} `json:"symbols"`
	}
	if err := json.Unmarshal(reply, &r); err != nil {
		t.Fatal(err)
	}
	return r.Symbols["CSM_FUZZY_SPAM"].Score
}

// redisDo sends one command to the storage's Redis and returns its reply
// line.
func (e *nativeEnv) redisDo(t *testing.T, args ...string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", e.redis, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err = conn.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}

// audit runs one full audit rotation and the repairs it schedules.
func (e *nativeEnv) audit(t *testing.T) AuditProgress {
	t.Helper()
	var total AuditProgress
	for range 100 {
		prog, err := e.publisher.AuditTurn(context.Background(), AuditBatch, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		total.Checked += prog.Checked
		total.Repaired += prog.Repaired
		if prog.RotationDone {
			break
		}
	}
	for range 10 {
		n, err := e.publisher.RepairTurn(context.Background(), RepairBatch)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	return total
}

func TestNativeScoreTable(t *testing.T) {
	e := native(t)
	want := map[int32]float64{2: 2.93, 4: 5.40, 6: 7.19, 8: 8.36, 18: 9.91}
	for tv, score := range want {
		body := message(e.text(150))
		d := e.anchor(t, body, tv)
		if v, present := e.value(t, d); !present || v != int64(tv) {
			t.Fatalf("T=%d stored %d present %v", tv, v, present)
		}
		if got := e.score(t, body); math.Abs(got-score) > 0.01 {
			t.Errorf("T=%d scored %.2f, want %.2f", tv, got, score)
		}
	}
}

func TestNativePublishRaiseLowerZero(t *testing.T) {
	e := native(t)
	d := e.anchor(t, message(e.text(150)), 2)
	for _, tv := range []int32{6, 4, 22, 2} {
		e.setT(t, d, tv)
		if v, present := e.value(t, d); !present || v != int64(tv) {
			t.Fatalf("T=%d stored %d present %v", tv, v, present)
		}
	}
	e.setT(t, d, 0)
	if _, present := e.value(t, d); present {
		t.Fatal("zero target still stored")
	}
}

func TestNativeForgetRemovesShingles(t *testing.T) {
	e := native(t)
	words := e.text(150)
	d := e.anchor(t, message(words), 4)
	near := message(e.variant(words, 3))
	insp, err := e.client.Inspect(context.Background(), near)
	if err != nil || insp.Distinct != 1 || !insp.Results[0].Found || insp.Results[0].Stored != d || insp.Results[0].Prob < JoinBoundary {
		t.Fatalf("near variant before forget: %+v %v", insp, err)
	}
	e.setT(t, d, 0)
	insp, err = e.client.Inspect(context.Background(), near)
	if err != nil || insp.Distinct != 1 {
		t.Fatalf("inspect after forget: %+v %v", insp, err)
	}
	if r := insp.Results[0]; r.Found && r.Stored == d {
		t.Fatalf("near variant still matches the forgotten anchor: %+v", r)
	}
}

func TestNativeRebuildAfterFlush(t *testing.T) {
	e := native(t)
	d := e.anchor(t, message(e.text(150)), 6)
	if got := e.redisDo(t, "FLUSHALL"); got != "+OK" {
		t.Fatalf("FLUSHALL: %s", got)
	}
	if _, present := e.value(t, d); present {
		t.Fatal("flush left the anchor")
	}
	e.audit(t)
	if v, present := e.value(t, d); !present || v != 6 {
		t.Fatalf("rebuilt to %d present %v", v, present)
	}
}

func TestNativeExplicitInspectionExactOnly(t *testing.T) {
	e := native(t)
	words := e.text(150)
	d := e.anchor(t, message(words), 2)
	vd := e.digest(t, message(e.variant(words, 3)))
	if vd == d {
		t.Fatal("variant has the anchor's digest")
	}
	insp, err := e.client.InspectDigests(context.Background(), []Digest{vd, d})
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := insp.ExactValue(vd); err != nil || present {
		t.Fatalf("explicit check of a near variant hit: present %v err %v", present, err)
	}
	if v, present, err := insp.ExactValue(d); err != nil || !present || v != 2 {
		t.Fatalf("anchor %d present %v err %v", v, present, err)
	}
}

// killFuzzy kills rspamd's fuzzy storage worker; rspamd starts another.
func killFuzzy(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	killed := 0
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		cmd, err := os.ReadFile("/proc/" + ent.Name() + "/cmdline")
		if err == nil && strings.Contains(string(cmd), "fuzzy") && strings.Contains(string(cmd), "rspamd") {
			if syscall.Kill(pid, syscall.SIGKILL) == nil {
				killed++
			}
		}
	}
	if killed == 0 {
		t.Fatal("no fuzzy storage process found (is the PID namespace shared?)")
	}
}

// killingClient kills the fuzzy worker right after an add is acknowledged,
// before any flush.
type killingClient struct {
	Client
	t    *testing.T
	once sync.Once
}

func (k *killingClient) Add(ctx context.Context, body []byte, w int32) error {
	err := k.Client.Add(ctx, body, w)
	k.once.Do(func() { killFuzzy(k.t) })
	return err
}

func TestNativeAckedWriteLostOnWorkerKill(t *testing.T) {
	e := native(t)
	body := message(e.text(150))
	d := e.digest(t, body)
	e.nextID++
	s, err := e.bodies.Stage(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.bodies.Commit(s, e.nextID); err != nil {
		t.Fatal(err)
	}
	if err := e.ledger.Update(func(tx LedgerTx) error {
		now := time.Now().UTC()
		if err := tx.PutCluster(Cluster{ID: e.nextID, Anchor: d, BodyLen: s.Len, BodySHA: s.SHA, Revision: 1, Created: now, LastReport: now}); err != nil {
			return err
		}
		return tx.PutTarget(Target{Digest: d, ClusterID: e.nextID, T: 8, Revision: 1, Phase: PhaseRead})
	}); err != nil {
		t.Fatal(err)
	}
	k := &killingClient{Client: e.client, t: t}
	p := NewPublisher(k, e.ledger, e.bodies)
	_, _ = p.Turn(context.Background(), d)
	// Wait for rspamd to start a new fuzzy worker, then let the ordinary
	// publisher finish from whatever storage kept.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := e.client.InspectDigests(context.Background(), []Digest{d}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fuzzy storage did not come back")
		}
		time.Sleep(500 * time.Millisecond)
	}
	e.settle(t, d)
	if v, present := e.value(t, d); !present || v != 8 {
		t.Fatalf("restored %d present %v", v, present)
	}
}

func TestNativeReplayedAddRepairedByAudit(t *testing.T) {
	e := native(t)
	body := message(e.text(150))
	d := e.anchor(t, body, 4)
	// A replayed add outside the publisher.
	if err := e.client.Add(context.Background(), body, 2); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if v, _ := e.value(t, d); v != 6 {
		t.Fatalf("replayed add left %d", v)
	}
	if prog := e.audit(t); prog.Repaired == 0 {
		t.Fatalf("audit found no drift: %+v", prog)
	}
	if v, present := e.value(t, d); !present || v != 4 {
		t.Fatalf("audit left %d present %v", v, present)
	}
}

func TestNativeOOMKeepsTarget(t *testing.T) {
	e := native(t)
	for range 3 {
		e.anchor(t, message(e.text(150)), 2)
	}
	t.Cleanup(func() { e.redisDo(t, "CONFIG", "SET", "maxmemory", "256mb") })
	if got := e.redisDo(t, "CONFIG", "SET", "maxmemory", "1"); got != "+OK" {
		t.Fatalf("CONFIG SET: %s", got)
	}
	body := message(e.text(150))
	d := e.digest(t, body)
	e.nextID++
	s, err := e.bodies.Stage(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.bodies.Commit(s, e.nextID); err != nil {
		t.Fatal(err)
	}
	if err := e.ledger.Update(func(tx LedgerTx) error {
		now := time.Now().UTC()
		if err := tx.PutCluster(Cluster{ID: e.nextID, Anchor: d, BodyLen: s.Len, BodySHA: s.SHA, Revision: 1, Created: now, LastReport: now}); err != nil {
			return err
		}
		return tx.PutTarget(Target{Digest: d, ClusterID: e.nextID, T: 4, Revision: 1, Phase: PhaseRead})
	}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if res, err := e.publisher.Turn(context.Background(), d); err == nil && res.Done {
			t.Fatal("publication completed while Redis refused writes")
		}
	}
	var tgt Target
	if err := e.ledger.View(func(v LedgerView) error {
		var err error
		tgt, _, err = v.Target(d)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if tgt.T != 4 || tgt.Phase == PhaseIdle {
		t.Fatalf("target lost under OOM: %+v", tgt)
	}
	if _, err := e.bodies.Read(e.nextID, s.Len, s.SHA); err != nil {
		t.Fatalf("body lost under OOM: %v", err)
	}
	if got := e.redisDo(t, "CONFIG", "SET", "maxmemory", "256mb"); got != "+OK" {
		t.Fatalf("CONFIG SET: %s", got)
	}
	e.settle(t, d)
	if v, present := e.value(t, d); !present || v != 4 {
		t.Fatalf("after headroom returned %d present %v", v, present)
	}
}

// Scans during a delete and re-add see the old value, absence or the new
// value, never more than old plus new.
func TestNativeConcurrentScansDuringReset(t *testing.T) {
	e := native(t)
	d := e.anchor(t, message(e.text(150)), 8)
	ctx, cancel := context.WithCancel(context.Background())
	var seen sync.Map
	var bad atomic.Int64
	done := make(chan struct{})
	ready := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() {
		defer close(done)
		first := true
		for ctx.Err() == nil {
			insp, err := e.client.InspectDigests(ctx, []Digest{d})
			if err != nil {
				continue
			}
			v, present, err := insp.ExactValue(d)
			if err != nil {
				continue
			}
			if !present {
				v = 0
			}
			seen.Store(v, true)
			if first {
				close(ready)
				first = false
			}
			if v > 8+2 {
				bad.Store(v)
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent scanner never read the anchor")
	}
	e.setT(t, d, 2)
	cancel()
	<-done
	var values []int64
	seen.Range(func(k, _ any) bool { values = append(values, k.(int64)); return true })
	t.Logf("values seen during the reset: %v", values)
	if bad.Load() != 0 {
		t.Fatalf("a scan saw %d", bad.Load())
	}
	for _, v := range values {
		if v != 0 && v != 2 && v != 8 {
			t.Errorf("unexpected value %d during reset", v)
		}
	}
}

// Legitimate mail from one template with different content, and mail with
// a distinct vocabulary, against one anchor: record the probabilities;
// distinct vocabulary never reaches the join boundary.
func TestNativeTemplateOverlapFixtures(t *testing.T) {
	e := native(t)
	template := func(fill []string) []string {
		head := strings.Fields("Dear customer your monthly statement is ready please review the summary below and contact support with any questions about your account")
		tail := strings.Fields("Thank you for choosing our service this message was sent to the address on file you can change notification settings at any time")
		return append(append(append([]string(nil), head...), fill...), tail...)
	}
	anchorWords := template(e.text(60))
	d := e.anchor(t, message(anchorWords), 6)
	for i := range 5 {
		insp, err := e.client.Inspect(context.Background(), message(template(e.text(60))))
		if err != nil || insp.Distinct != 1 {
			t.Fatalf("inspect: %+v %v", insp, err)
		}
		r := insp.Results[0]
		t.Logf("same template, other content %d: found %v anchor %v prob %.2f", i, r.Found, r.Stored == d, r.Prob)
	}
	// Mostly boilerplate: a long fixed template with a short fill, the
	// shape of legitimate newsletters from one sender. Recorded, not
	// asserted: whether these join is the false-positive risk spec 14 asks
	// to measure.
	boiler := e.text(140)
	heavy := e.anchor(t, message(append(append([]string(nil), boiler...), e.text(10)...)), 2)
	for i := range 5 {
		insp, err := e.client.Inspect(context.Background(), message(append(append([]string(nil), boiler...), e.text(10)...)))
		if err != nil || insp.Distinct != 1 {
			t.Fatalf("inspect: %+v %v", insp, err)
		}
		r := insp.Results[0]
		t.Logf("boilerplate template, short fill %d: found %v anchor %v prob %.2f", i, r.Found, r.Stored == heavy, r.Prob)
	}
	for i := range 5 {
		insp, err := e.client.Inspect(context.Background(), message(e.text(150)))
		if err != nil || insp.Distinct != 1 {
			t.Fatalf("inspect: %+v %v", insp, err)
		}
		r := insp.Results[0]
		t.Logf("distinct vocabulary %d: found %v prob %.2f", i, r.Found, r.Prob)
		if r.Found && r.Stored == d && r.Prob >= JoinBoundary {
			t.Errorf("distinct vocabulary joined the anchor at %.2f", r.Prob)
		}
	}
}
