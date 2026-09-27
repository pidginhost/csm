package store

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

var ledgerT0 = time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC)

const ledgerBoot = "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b"

// fixtureCeiling is the fixture's hourly ceiling: its first limit fills 266
// general and 66 reserved units, more than any single test spends.
const fixtureCeiling = 2000

func ledgerLookup(check string) (string, admission.Policy, bool) {
	switch check {
	case "ssh_brute":
		return check, admission.Policy{Family: admission.FamilySSH, Basis: admission.BasisLocal}, true
	case "reputation":
		return check, admission.Policy{Family: admission.FamilyReputation, Basis: admission.BasisIntel}, true
	case "mail_takeover":
		return check, admission.Policy{Family: admission.FamilyMail, Basis: admission.BasisCompromise, MinSeverity: admission.SeverityCritical}, true
	}
	return "", admission.Policy{}, false
}

// ledgerFixture is a ledger on a fresh database with three registered
// producers, a clock reading at ledgerT0 and accounts alice and bob.
type ledgerFixture struct {
	t              testing.TB
	db             *DB
	reg            *admission.Registry
	l              *AdmissionLedger
	ssh, rep, mail *admission.Producer
	wall           time.Time
	since          time.Duration
	generation     uint32
	fills          int
}

func newLedgerRegistry(t testing.TB) (*admission.Registry, *admission.Producer, *admission.Producer, *admission.Producer) {
	t.Helper()
	reg, err := admission.NewRegistry(ledgerLookup)
	if err != nil {
		t.Fatal(err)
	}
	register := func(id admission.ProducerID, obs admission.ObservationKind, check string) *admission.Producer {
		p, err := reg.Register(admission.ProducerSpec{ID: id, Entry: admission.EntryScan, Observation: obs, Checks: []string{check}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	ssh := register("sshd_log", admission.ObservationLogCursor, "ssh_brute")
	rep := register("reputation_scan", admission.ObservationScanPass, "reputation")
	mail := register("mail_log", admission.ObservationLogCursor, "mail_takeover")
	reg.Seal()
	return reg, ssh, rep, mail
}

func newLedgerFixture(t testing.TB) *ledgerFixture {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := &ledgerFixture{t: t, db: db, since: time.Hour}
	f.reg, f.ssh, f.rep, f.mail = newLedgerRegistry(t)
	if f.l, err = OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	if err = f.l.SetCeiling(fixtureCeiling); err != nil {
		t.Fatal(err)
	}
	f.tickAt(ledgerT0)
	f.refresh([]string{"alice", "bob"}, nil)
	return f
}

// tickAt records a reading on one boot whose elapsed time matches the wall.
func (f *ledgerFixture) tickAt(wall time.Time) admission.ClockTick {
	f.t.Helper()
	if !f.wall.IsZero() && wall.After(f.wall) {
		f.since += wall.Sub(f.wall)
	}
	f.wall = wall
	tick, err := f.l.Tick(admission.ClockReading{Wall: wall, BootID: ledgerBoot, SinceBoot: f.since})
	if err != nil {
		f.t.Fatal(err)
	}
	return tick
}

func (f *ledgerFixture) refresh(accounts []string, domains map[string]string) {
	f.t.Helper()
	if err := f.l.RefreshInventory(admission.InventoryObservation{Accounts: accounts, Domains: domains}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *ledgerFixture) owner(account string) admission.Owner {
	f.t.Helper()
	o := f.l.Inventory().Resolve(admission.Claim{Kind: admission.ClaimAccount, Value: account})
	if o.IsHost() {
		f.t.Fatalf("account %s is not in the inventory", account)
	}
	return o
}

func (f *ledgerFixture) target(raw string) admission.Target {
	f.t.Helper()
	tg, err := admission.CanonicalAddress(raw, admission.Caps{IPv6: true})
	if err != nil {
		f.t.Fatal(err)
	}
	return tg
}

func wantLedgerReason(t *testing.T, what string, err error, want admission.Reason) {
	t.Helper()
	if got, ok := admission.ReasonOf(err); !ok || got != want {
		t.Errorf("%s: err = %v, want reason %s", what, err, want)
	}
}

func wantLedgerErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: err = %v, want %v", what, err, want)
	}
}

// failNext makes the next write transaction fail after its writes.
func (f *ledgerFixture) failNext(op string) {
	f.l.failBeforeCommit = func(got string) error {
		f.l.failBeforeCommit = nil
		if got != op {
			return fmt.Errorf("unexpected transaction %s", got)
		}
		return errors.New("injected failure before commit")
	}
}

func isCorrupt(err error) bool { return errors.Is(err, admission.ErrCorruptRecord) }

// snapshot compares every ledger record before and after an aborted call.
func (f *ledgerFixture) snapshot() map[string]string {
	f.t.Helper()
	out := map[string]string{}
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		for _, name := range admissionBuckets {
			if err := tx.Bucket([]byte(name)).ForEach(func(k, v []byte) error {
				out[name+":"+string(k)] = string(v)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// evidenceSpec describes one observation; zero fields take defaults.
type evidenceSpec struct {
	producer *admission.Producer
	check    string
	target   string
	cursor   string
	age      time.Duration
	finding  string
	severity admission.Severity
	owner    admission.Owner
}

func (f *ledgerFixture) mint(s evidenceSpec) admission.Evidence {
	f.t.Helper()
	if s.producer == nil {
		s.producer, s.check = f.ssh, "ssh_brute"
	}
	if s.target == "" {
		s.target = "192.0.2.10"
	}
	if s.cursor == "" {
		s.cursor = "offset=1"
	}
	if s.finding == "" {
		s.finding = "0123456789abcdef"
	}
	if s.severity == 0 {
		s.severity = admission.SeverityHigh
	}
	in := admission.EvidenceInput{
		Check: s.check, FindingID: s.finding, Severity: s.severity,
		Observation: admission.ObservationRef{Stream: "log:" + string(s.producer.ID()), Cursor: s.cursor, Version: 1},
		ObservedAt:  f.wall.Add(-s.age), Parser: admission.ParserRef{Name: "fixture", Version: 1},
		Target: f.target(s.target), Owner: s.owner,
	}
	if s.producer == f.rep {
		in.Intel = &admission.IntelRef{Source: "feed", Expires: in.ObservedAt.Add(30 * time.Hour)}
	}
	e, err := s.producer.Mint(in)
	if err != nil {
		f.t.Fatal(err)
	}
	return e
}

// published mints and publishes evidence and returns its ID.
func (f *ledgerFixture) published(s evidenceSpec) admission.EvidenceID {
	f.t.Helper()
	e := f.mint(s)
	if _, err := f.l.PublishEvidence(e); err != nil {
		f.t.Fatal(err)
	}
	return e.ID()
}

func (f *ledgerFixture) request(target string, primary admission.EvidenceID, support ...admission.EvidenceID) admission.CandidateRequest {
	f.t.Helper()
	ep, err := admission.ParseEpisodeID("00000000000000000000000000000001")
	if err != nil {
		f.t.Fatal(err)
	}
	return admission.CandidateRequest{Kind: admission.KindBlockIP, Target: f.target(target), Episode: ep, Generation: f.generation + 1, Primary: primary, Support: support}
}

func (f *ledgerFixture) enqueue(req admission.CandidateRequest) (admission.Candidate, admission.CandidateID) {
	f.t.Helper()
	c, created, err := f.l.Enqueue(req)
	if err != nil || !created {
		f.t.Fatalf("enqueue: created %v, %v", created, err)
	}
	id, _ := c.ID()
	return c, id
}

// queued enqueues a candidate for the fixture's current generation, from a
// root observed now.
func (f *ledgerFixture) queued() admission.CandidateID {
	f.t.Helper()
	root := f.published(evidenceSpec{cursor: fmt.Sprintf("offset=%d", f.generation+1)})
	_, id := f.enqueue(f.request("192.0.2.10", root))
	return id
}

// nextGeneration moves the fixture's requests to a new candidate generation.
func (f *ledgerFixture) nextGeneration() { f.generation++ }
