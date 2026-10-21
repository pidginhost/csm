package store

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Design C7 and admission-gates section 8, row 4: after the live start no
// observe preview from before it answers an episode. A target whose rows
// only a block preview anchored starts a new episode; one another kind's
// candidate keeps queues its block's next generation, whether the line
// still names the preview or only remembers its answer. A verified block's
// remembered answer keeps answering until its expiry, challenge previews
// keep answering their lines, and a preview after the live start answers
// as before.
func TestAdmissionLedgerLiveStartEndsPreviewAnswers(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first, _ := f.observedArrival("192.0.2.10", "offset=1")
	wantLedgerReason(t, "answered by a preview", f.arrive(f.arrival(evidenceSpec{target: "192.0.2.10", cursor: "offset=2"}))[0].Err, admission.ReasonExistingEffect)

	challengeAt := func(target, cursor string) admission.Arrival {
		a := f.arrival(evidenceSpec{target: target, cursor: cursor})
		a.Request.Kind = admission.KindChallenge
		return a
	}
	forget := func(target string, id admission.CandidateID) {
		t.Helper()
		key := f.candidateOf(id).Key.Target.Key()
		row, _ := f.episodeAt(target)
		row, _ = row.WithoutCandidate(id, true)
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisode(tx, key, row) }); err != nil {
			t.Fatal(err)
		}
	}
	// A queued challenge keeps the row while the block line only remembers
	// its preview's answer.
	if res := f.arrive(challengeAt("192.0.2.20", "challenge=1"))[0]; res.Err != nil || !res.Created {
		t.Fatalf("challenge = %+v", res)
	}
	remembered, _ := f.observedArrival("192.0.2.20", "offset=1")
	forget("192.0.2.20", remembered)
	// A verified block's remembered answer.
	if res := f.arrive(challengeAt("192.0.2.30", "challenge=1"))[0]; res.Err != nil || !res.Created {
		t.Fatalf("challenge = %+v", res)
	}
	verified := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.30", cursor: "offset=1"}))[0].Candidate
	f.finishArrival(verified, f.wall.Add(time.Hour), admission.DispositionApplied)
	forget("192.0.2.30", verified)
	// A previewed challenge, and a remembered one beside a queued block.
	previewChallenge := func(target string) admission.CandidateID {
		t.Helper()
		res := f.arrive(challengeAt(target, "challenge=1"))[0]
		if res.Err != nil || !res.Created {
			t.Fatalf("challenge = %+v", res)
		}
		if _, _, granted, err := f.l.Observe(res.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted {
			t.Fatalf("challenge preview: %v %v", granted, err)
		}
		return res.Candidate
	}
	previewChallenge("192.0.2.50")
	block := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.60", cursor: "offset=1"}))[0]
	if block.Err != nil || !block.Created {
		t.Fatalf("block beside remembered challenge = %+v", block)
	}
	forget("192.0.2.60", previewChallenge("192.0.2.60"))

	if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	if _, found := f.episodeAt("192.0.2.10"); found {
		t.Fatal("the live start kept an episode only a block preview anchored")
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopening after the live start: %v", err)
	}
	f.tickAt(f.wall.Add(time.Second))
	wantLedgerReason(t, "remembered challenge", f.arrive(challengeAt("192.0.2.60", "challenge=2"))[0].Err, admission.ReasonExistingEffect)
	wantLedgerReason(t, "previewed challenge", f.arrive(challengeAt("192.0.2.50", "challenge=2"))[0].Err, admission.ReasonExistingEffect)
	wantLedgerReason(t, "verified block", f.arrive(f.arrival(evidenceSpec{target: "192.0.2.30", cursor: "offset=3"}))[0].Err, admission.ReasonExistingEffect)
	if again := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.60", cursor: "offset=3"}))[0]; again.Err != nil || again.Created || again.Candidate != block.Candidate {
		t.Fatalf("observation beside a queued block = %+v", again)
	}
	next := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.10", cursor: "offset=3"}))[0]
	if c := f.candidateOf(next.Candidate); next.Err != nil || !next.Created || c.Key.Episode == f.candidateOf(first).Key.Episode || c.Key.Generation != 1 {
		t.Fatalf("after the only preview = %+v %+v", next, c.Key)
	}
	next = f.arrive(f.arrival(evidenceSpec{target: "192.0.2.20", cursor: "offset=3"}))[0]
	if c := f.candidateOf(next.Candidate); next.Err != nil || !next.Created || c.Key.Episode != f.candidateOf(remembered).Key.Episode || c.Key.Generation != 2 {
		t.Fatalf("after a remembered preview = %+v %+v", next, c.Key)
	}
	f.observedArrival("192.0.2.40", "offset=1")
	wantLedgerReason(t, "a preview after the live start", f.arrive(f.arrival(evidenceSpec{target: "192.0.2.40", cursor: "offset=2"}))[0].Err, admission.ReasonExistingEffect)
}

// 2a-2 plan ruling 7: notice records raised before the live start describe
// gaps legacy blocking covered. The live start clears them, delivered or
// not, so none is sent as a live alert and none delays the first live
// notice of its key; the fixed records stay, empty.
func TestAdmissionLedgerLiveStartClearsPreviewNotices(t *testing.T) {
	f := newLedgerFixture(t)
	if _, err := f.l.Terminate(f.criticalQueued(), admission.ReasonCollateral); err != nil {
		t.Fatal(err)
	}
	due, err := f.l.PendingNotices()
	if err != nil || len(due) == 0 {
		t.Fatalf("pending notices = %v, %v", due, err)
	}
	var acks []admission.NoticeAck
	for _, r := range due {
		acks = append(acks, admission.NoticeAck{Key: r.Key, First: r.First, Count: r.Count})
	}
	if err = f.l.AckNotices(acks); err != nil {
		t.Fatal(err)
	}
	if _, err = f.l.Terminate(f.criticalQueued(), admission.ReasonStale); err != nil {
		t.Fatal(err)
	}
	if n := f.storageState().NoticeRecords; n != admission.FixedNotices+2 {
		t.Fatalf("records before the live start = %d", n)
	}
	// Audit rows share the outbox and stay.
	f.begin()
	f.observedArrival("192.0.2.30", "offset=1")
	audit := f.pendingAudit()
	if err = f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	if got := f.pendingAudit(); len(audit) == 0 || !reflect.DeepEqual(got, audit) {
		t.Fatalf("audit rows after the live start = %+v, want %+v", got, audit)
	}
	want := map[admission.NoticeKey]admission.NoticeRecord{}
	for _, k := range admission.FixedNoticeKeys() {
		want[k] = admission.NewNoticeRecord(k)
	}
	if got := f.notices(); !reflect.DeepEqual(got, want) {
		t.Fatalf("notices after the live start = %+v", got)
	}
	if n := f.storageState().NoticeRecords; n != admission.FixedNotices {
		t.Fatalf("records after the live start = %d, want %d", n, admission.FixedNotices)
	}
	for k := range f.snapshot() {
		if strings.HasPrefix(k, admissionOutboxBucket+":q") {
			t.Fatalf("quiet index key %q outlived its record", k)
		}
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopening after the live start: %v", err)
	}
	if _, err = f.l.Terminate(f.criticalQueued(), admission.ReasonCollateral); err != nil {
		t.Fatal(err)
	}
	due, err = f.l.PendingNotices()
	if err != nil {
		t.Fatal(err)
	}
	keys := map[admission.NoticeKey]bool{}
	for _, r := range due {
		keys[r.Key] = true
	}
	if !reflect.DeepEqual(keys, map[admission.NoticeKey]bool{sshKey(admission.NoticeWithheld, admission.ReasonCollateral): true, criticalSummary: true}) {
		t.Fatalf("due after the live start = %+v", keys)
	}
}
