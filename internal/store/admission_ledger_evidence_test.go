package store

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func (f *ledgerFixture) storedEvidence(id admission.EvidenceID) []byte {
	var raw []byte
	_ = f.db.bolt.View(func(tx *bolt.Tx) error {
		raw = bytes.Clone(tx.Bucket([]byte(admissionEvidenceBucket)).Get([]byte(id)))
		return nil
	})
	return raw
}

// Evidence is immutable: the same record again changes nothing, and a
// re-mint of the same observation with a new finding is refused while the
// original bytes stay.
func TestAdmissionLedgerEvidenceIsImmutable(t *testing.T) {
	f := newLedgerFixture(t)
	e := f.mint(evidenceSpec{})
	if published, err := f.l.PublishEvidence(e); err != nil || !published {
		t.Fatalf("first publish: %v, %v", published, err)
	}
	original := f.storedEvidence(e.ID())
	if published, err := f.l.PublishEvidence(e); err != nil || published {
		t.Fatalf("same record again: %v, %v", published, err)
	}
	remint := f.mint(evidenceSpec{finding: "fedcba9876543210"})
	if remint.ID() != e.ID() {
		t.Fatal("precondition: a new finding for the same observation keeps the evidence ID")
	}
	_, err := f.l.PublishEvidence(remint)
	wantLedgerReason(t, "conflicting publish", err, admission.ReasonInvalid)
	if !bytes.Equal(f.storedEvidence(e.ID()), original) {
		t.Fatal("conflicting publish changed the stored record")
	}
	got, err := f.l.LoadEvidence(e.ID())
	if err != nil || !got.Equal(e) {
		t.Fatalf("load: %v", err)
	}
}

// The ledger revalidates evidence against its own sealed registry: a record
// minted by a producer it does not hold is refused on publish.
func TestAdmissionLedgerRefusesForeignEvidence(t *testing.T) {
	f := newLedgerFixture(t)
	other, err := admission.NewRegistry(ledgerLookup)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := other.Register(admission.ProducerSpec{ID: "stranger", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: []string{"ssh_brute"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.l.PublishEvidence(f.mint(evidenceSpec{producer: stranger, check: "ssh_brute"}))
	wantLedgerReason(t, "foreign producer", err, admission.ReasonPolicy)
	_, err = f.l.LoadEvidence("ev_00000000000000000000000000000001")
	wantLedgerReason(t, "unpublished", err, admission.ReasonInvalid)
	_, err = f.l.LoadEvidence("not-an-id")
	wantLedgerReason(t, "malformed", err, admission.ReasonInvalid)
}

func TestAdmissionLedgerRefusesCorruptEvidence(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.published(evidenceSpec{})
	other := f.mint(evidenceSpec{cursor: "offset=2"})
	otherBytes, _ := other.MarshalBinary()
	for name, raw := range map[string][]byte{
		"flipped byte": func() []byte { d := f.storedEvidence(id); d[5] ^= 1; return d }(),
		"wrong key":    otherBytes,
	} {
		_ = f.db.bolt.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionEvidenceBucket)).Put([]byte(id), raw)
		})
		if _, err := f.l.LoadEvidence(id); !isCorrupt(err) {
			t.Errorf("%s: err = %v, want a corrupt record", name, err)
		}
	}
}

func TestAdmissionLedgerReportLinksAreBounded(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.published(evidenceSpec{})
	for i := 1; i <= admission.MaxReportLinks+3; i++ {
		if err := f.l.LinkReport(id, fmt.Sprintf("%016x", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.l.LinkReport(id, fmt.Sprintf("%016x", 1)); err != nil {
		t.Fatal(err)
	}
	links, dropped, err := f.l.Reports(id)
	if err != nil || len(links) != admission.MaxReportLinks || dropped != 3 {
		t.Fatalf("links %d dropped %d: %v", len(links), dropped, err)
	}
	wantLedgerReason(t, "malformed finding", f.l.LinkReport(id, "xyz"), admission.ReasonInvalid)
	wantLedgerReason(t, "unpublished evidence", f.l.LinkReport("ev_00000000000000000000000000000001", "0000000000000001"), admission.ReasonInvalid)
	e, _ := f.l.LoadEvidence(id)
	if e.FindingID() != "0123456789abcdef" {
		t.Fatal("linking reports changed the evidence")
	}
}

// newFloorLedger reopens the fixture's database with a registry whose
// ssh_brute severity floor the returned function raises, so a test can
// change policy after evidence is published.
func newFloorLedger(t *testing.T) (*ledgerFixture, func(admission.Severity)) {
	t.Helper()
	var mu sync.Mutex
	floor := admission.Severity(0)
	lookup := func(check string) (string, admission.Policy, bool) {
		mu.Lock()
		defer mu.Unlock()
		if check != "ssh_brute" {
			return "", admission.Policy{}, false
		}
		return check, admission.Policy{Family: admission.FamilySSH, Basis: admission.BasisLocal, MinSeverity: floor}, true
	}
	reg, err := admission.NewRegistry(lookup)
	if err != nil {
		t.Fatal(err)
	}
	ssh, err := reg.Register(admission.ProducerSpec{ID: "sshd_log", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: []string{"ssh_brute"}, Claims: []admission.ClaimKind{admission.ClaimAccount}})
	if err != nil {
		t.Fatal(err)
	}
	reg.Seal()
	f := newLedgerFixture(t)
	if f.l, err = OpenAdmissionLedger(f.db, reg); err != nil {
		t.Fatal(err)
	}
	f.reg, f.ssh = reg, ssh
	f.tickAt(f.wall)
	return f, func(s admission.Severity) {
		mu.Lock()
		floor = s
		mu.Unlock()
	}
}

// Stored evidence is revalidated on every use: after its check's severity
// floor rises, evidence minted below it no longer loads.
func TestAdmissionLedgerRevalidatesEvidenceOnLoad(t *testing.T) {
	f, raise := newFloorLedger(t)
	id := f.published(evidenceSpec{})
	raise(admission.SeverityCritical)
	_, err := f.l.LoadEvidence(id)
	wantLedgerReason(t, "load below the new floor", err, admission.ReasonPolicy)
}

func TestAdmissionLedgerEvidenceWritesAreAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	e := f.mint(evidenceSpec{})
	before := f.snapshot()
	f.failNext("publish")
	if changed, err := f.l.PublishEvidence(e); err == nil || changed {
		t.Fatalf("failed publish: %v %v", changed, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed publish changed records")
	}
	if _, err := f.l.PublishEvidence(e); err != nil {
		t.Fatal(err)
	}
	before = f.snapshot()
	f.failNext("link")
	if err := f.l.LinkReport(e.ID(), "0000000000000001"); err == nil {
		t.Fatal("link did not fail")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed link changed records")
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionReportsBucket)).Put([]byte(e.ID()), []byte("damaged"))
	}); err != nil {
		t.Fatal(err)
	}
	before = f.snapshot()
	if _, _, err := f.l.Reports(e.ID()); !isCorrupt(err) {
		t.Fatalf("read damaged reports: %v", err)
	}
	if err := f.l.LinkReport(e.ID(), "0000000000000002"); !isCorrupt(err) {
		t.Fatalf("overwrite damaged reports: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("damaged reports changed")
	}
}

func TestAdmissionLedgerOriginalReportDoesNotConsumeLink(t *testing.T) {
	f := newLedgerFixture(t)
	e := f.mint(evidenceSpec{})
	if _, err := f.l.PublishEvidence(e); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if err := f.l.LinkReport(e.ID(), e.FindingID()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("original report allocated a later link")
	}
}

// Report links are bound to their evidence: a record copied under another
// evidence ID, or one listing the evidence's own original finding, which
// LinkReport never stores, is damaged storage.
func TestAdmissionLedgerRefusesMisplacedReportLinks(t *testing.T) {
	f := newLedgerFixture(t)
	a := f.published(evidenceSpec{cursor: "offset=1", finding: "00000000000000aa"})
	b := f.published(evidenceSpec{cursor: "offset=2", finding: "00000000000000bb"})
	if err := f.l.LinkReport(a, "00000000000000cc"); err != nil {
		t.Fatal(err)
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		reports := tx.Bucket([]byte(admissionReportsBucket))
		return reports.Put([]byte(b), bytes.Clone(reports.Get([]byte(a))))
	}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if links, _, err := f.l.Reports(b); !isCorrupt(err) {
		t.Fatalf("copied links read as b's: %v, %v", links, err)
	}
	if err := f.l.LinkReport(b, "00000000000000dd"); !isCorrupt(err) {
		t.Fatalf("copied links extended: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("misplaced links changed records")
	}
	own, err := admission.ReportLinks{Evidence: b, Links: []string{"00000000000000bb"}}.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionReportsBucket)).Put([]byte(b), own)
	}); err != nil {
		t.Fatal(err)
	}
	if links, _, err := f.l.Reports(b); !isCorrupt(err) {
		t.Fatalf("original finding read as a later report: %v, %v", links, err)
	}
}

// Evidence refusals name their cause: a reference to unpublished evidence
// and a conflicting record are distinct sentinels, both with reason invalid.
func TestAdmissionLedgerEvidenceRefusalSentinels(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.published(evidenceSpec{})
	_, err := f.l.PublishEvidence(f.mint(evidenceSpec{finding: "fedcba9876543210"}))
	wantLedgerErr(t, "conflicting publish", err, admission.ErrEvidenceConflict)
	wantLedgerReason(t, "conflicting publish", err, admission.ReasonInvalid)
	missing := admission.EvidenceID("ev_00000000000000000000000000000001")
	for name, call := range map[string]func() error{
		"load":   func() error { _, err := f.l.LoadEvidence(missing); return err },
		"link":   func() error { return f.l.LinkReport(missing, "fedcba9876543210") },
		"report": func() error { _, _, err := f.l.Reports(missing); return err },
		"enqueue": func() error {
			_, _, err := f.l.Enqueue(f.request("192.0.2.10", id, missing))
			return err
		},
	} {
		err := call()
		wantLedgerErr(t, name, err, admission.ErrEvidenceUnpublished)
		wantLedgerReason(t, name, err, admission.ReasonInvalid)
	}
	if errors.Is(admission.ErrEvidenceConflict, admission.ErrEvidenceUnpublished) {
		t.Fatal("the two refusals must be distinct")
	}
}
