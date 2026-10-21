package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// batchFixture is a two-member automatic batch whose first member records the
// row it evicts. The states only need to encode; planning is not tested here.
func batchFixture() firewall.FirewallAction {
	before := completeFirewallState()
	after := completeFirewallState()
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	after.Blocked = append(after.Blocked,
		firewall.BlockedEntry{IP: "203.0.113.10", Reason: "brute force", Source: "scan", BlockedAt: at, ExpiresAt: at.Add(time.Hour), ActionID: "member-one"},
		firewall.BlockedEntry{IP: "203.0.113.11", Reason: "brute force", Source: "scan", BlockedAt: at, ExpiresAt: at.Add(time.Hour), ActionID: "member-two"})
	member := func(id, target string) firewall.ActionMember {
		return firewall.ActionMember{
			Request: firewall.ActionRequest{ID: id, Operation: "block", Target: target, Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour},
			Budget:  &firewall.ScanAdmission{Window: "2026-01-02T03", Limit: 4},
		}
	}
	first, second := member("member-one", "203.0.113.10"), member("member-two", "203.0.113.11")
	first.Victims = []firewall.BlockedEntry{{IP: "203.0.113.90", Reason: "expired", Source: "explicit", BlockedAt: at.Add(-time.Hour), ExpiresAt: at.Add(30 * time.Minute), ActionID: "earlier-action"}}
	return firewall.FirewallAction{
		Request:   firewall.ActionRequest{ID: "batch-one", Operation: "block", Actor: "auto", Source: "scan", Automatic: true},
		Members:   []firewall.ActionMember{first, second},
		Before:    before,
		After:     after,
		Revision:  1,
		CreatedAt: at,
	}
}

func admitFixture(t *testing.T, db *DB, in firewall.FirewallAction) firewall.FirewallAction {
	t.Helper()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	a, fresh, err := db.AdmitFirewallAction(in)
	if err != nil || !fresh {
		t.Fatalf("admit = %v, %v", fresh, err)
	}
	return a
}

// storedEnvelope returns the version and payload keys of a raw journal value.
func storedEnvelope(t *testing.T, raw []byte) (uint64, map[string]json.RawMessage) {
	t.Helper()
	var envelope firewallJournalEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Payload, &fields); err != nil {
		t.Fatal(err)
	}
	return envelope.Version, fields
}

func storedAction(t *testing.T, db *DB, id string) (uint64, map[string]json.RawMessage) {
	t.Helper()
	var raw []byte
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		raw = append([]byte(nil), tx.Bucket([]byte(firewallActionsBucket)).Get([]byte(id))...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return storedEnvelope(t, raw)
}

func storedAuditAction(t *testing.T, db *DB, id string, version uint64) uint64 {
	t.Helper()
	var raw []byte
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		raw = append([]byte(nil), tx.Bucket([]byte(firewallAuditBucket)).Get(firewallAuditKey(id, version))...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, fields := storedEnvelope(t, raw)
	inner, _ := storedEnvelope(t, fields["action"])
	return inner
}

func TestFirewallBatchManifestRoundTrips(t *testing.T) {
	db := openSnapshotDB(t)
	in := batchFixture()
	a := admitFixture(t, db, in)
	if !a.SameManifest(in) || len(a.Members) != 2 || a.Members[1].Budget == nil {
		t.Fatalf("admitted manifest = %#v", a.Members)
	}
	victim := a.Members[0].Victims
	if len(victim) != 1 || victim[0].ActionID != "earlier-action" || !victim[0].ExpiresAt.Equal(in.Members[0].Victims[0].ExpiresAt) {
		t.Fatalf("victim = %#v", victim)
	}
	if version, fields := storedAction(t, db, in.Request.ID); version != 2 || fields["members"] == nil {
		t.Fatalf("stored batch version %d, members %s", version, fields["members"])
	}
	failed, err := db.TransitionFirewallAction(in.Request.ID, "failed", "not applied", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if version, _ := storedAction(t, db, in.Request.ID); version != 2 {
		t.Fatalf("transition rewrote the batch as version %d", version)
	}
	if version := storedAuditAction(t, db, in.Request.ID, failed.AuditVersion); version != 2 {
		t.Fatalf("audit event holds the batch as version %d", version)
	}
	pending, err := db.FirewallAuditPending()
	if err != nil || len(pending) != 1 || !pending[0].SameManifest(in) {
		t.Fatalf("audit pending = %#v, %v", pending, err)
	}
	if err = db.AcknowledgeFirewallAudit(in.Request.ID, failed.AuditVersion); err != nil {
		t.Fatal(err)
	}
	stored, err := db.ReadFirewallAction(in.Request.ID)
	if err != nil || !stored.SameManifest(in) || stored.AuditAck != failed.AuditVersion {
		t.Fatalf("stored = %#v, %v", stored, err)
	}
}

func TestFirewallEarlierRecordStaysVersionOne(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	a := admitFixture(t, db, in)
	if a.Members != nil || len(a.ActionMembers()) != 1 {
		t.Fatalf("one-request action gained a manifest: %#v", a.Members)
	}
	version, fields := storedAction(t, db, in.Request.ID)
	if version != 1 || fields["members"] != nil {
		t.Fatalf("one-request action stored as version %d with members %s", version, fields["members"])
	}
	unknown, err := db.TransitionFirewallAction(in.Request.ID, "unknown", "lost reply", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AcknowledgeFirewallAudit(in.Request.ID, unknown.AuditVersion); err != nil {
		t.Fatal(err)
	}
	version, fields = storedAction(t, db, in.Request.ID)
	if version != 1 || fields["members"] != nil {
		t.Fatalf("rewrite changed the record: version %d, members %s", version, fields["members"])
	}
	if version := storedAuditAction(t, db, in.Request.ID, unknown.AuditVersion); version != 1 {
		t.Fatalf("audit event holds the record as version %d", version)
	}
}

func TestFirewallManifestRejectsInvalidBatches(t *testing.T) {
	cases := map[string]func(*firewall.FirewallAction){
		"empty manifest":       func(a *firewall.FirewallAction) { a.Members = []firewall.ActionMember{} },
		"one member differs":   func(a *firewall.FirewallAction) { a.Members = a.Members[:1] },
		"header with a target": func(a *firewall.FirewallAction) { a.Request.Target = "203.0.113.12" },
		"header with a reason": func(a *firewall.FirewallAction) { a.Request.Reason = "batch" },
		"header with a TTL":    func(a *firewall.FirewallAction) { a.Request.TTL = time.Hour },
		"header with a link":   func(a *firewall.FirewallAction) { a.Request.FindingID = "finding" },
		"header not automatic": func(a *firewall.FirewallAction) { a.Request.Automatic = false },
		"header charge": func(a *firewall.FirewallAction) {
			a.Budget = &firewall.ScanAdmission{Window: "2026-01-02T03", Limit: 4}
		},
		"member unblocks":           func(a *firewall.FirewallAction) { a.Members[1].Request.Operation = "unblock" },
		"member not automatic":      func(a *firewall.FirewallAction) { a.Members[1].Request.Automatic = false },
		"member is permanent":       func(a *firewall.FirewallAction) { a.Members[1].Request.TTL = 0 },
		"member without a target":   func(a *firewall.FirewallAction) { a.Members[1].Request.Target = "" },
		"member undoes":             func(a *firewall.FirewallAction) { a.Members[1].Request.UndoOf = "batch-zero" },
		"member of another actor":   func(a *firewall.FirewallAction) { a.Members[1].Request.Actor = "cli" },
		"member of another source":  func(a *firewall.FirewallAction) { a.Members[1].Request.Source = "manual"; a.Members[1].Budget = nil },
		"member detail differs":     func(a *firewall.FirewallAction) { a.Members[1].Request.ActorDetail = "other" },
		"member repeats an ID":      func(a *firewall.FirewallAction) { a.Members[1].Request.ID = "member-one" },
		"member takes the batch ID": func(a *firewall.FirewallAction) { a.Members[1].Request.ID = "batch-one" },
		"member without an ID":      func(a *firewall.FirewallAction) { a.Members[1].Request.ID = "" },
		"member ID too long":        func(a *firewall.FirewallAction) { a.Members[1].Request.ID = strings.Repeat("m", 129) },
		"member repeats a target":   func(a *firewall.FirewallAction) { a.Members[1].Request.Target = "203.0.113.10" },
		"member aliases a target":   func(a *firewall.FirewallAction) { a.Members[1].Request.Target = "::ffff:203.0.113.10" },
		"member target not an IP":   func(a *firewall.FirewallAction) { a.Members[1].Request.Target = "203.0.113.0/24" },
		"victim aliases a target":   func(a *firewall.FirewallAction) { a.Members[0].Victims[0].IP = "::ffff:203.0.113.11" },
		"member text not UTF-8":     func(a *firewall.FirewallAction) { a.Members[1].Request.Reason = "bad\xff" },
		"member charge not scan":    func(a *firewall.FirewallAction) { a.Members[1].Budget.Limit = 0 },
		"member charge window":      func(a *firewall.FirewallAction) { a.Members[1].Budget.Window = "2026-01-02" },
		"charges disagree":          func(a *firewall.FirewallAction) { a.Members[1].Budget.Limit = 5 },
		"permanent victim":          func(a *firewall.FirewallAction) { a.Members[0].Victims[0].ExpiresAt = time.Time{} },
		"victim without an IP":      func(a *firewall.FirewallAction) { a.Members[0].Victims[0].IP = "" },
		"victim is a target":        func(a *firewall.FirewallAction) { a.Members[0].Victims[0].IP = "203.0.113.11" },
		"victim twice":              func(a *firewall.FirewallAction) { a.Members[1].Victims = a.Members[0].Victims },
		"victim action not UTF-8":   func(a *firewall.FirewallAction) { a.Members[0].Victims[0].ActionID = "bad\xff" },
		"too many members": func(a *firewall.FirewallAction) {
			for i := range a.Members {
				a.Members[i].Budget = &firewall.ScanAdmission{Window: "2026-01-02T03", Limit: firewall.MaxActionMembers + 1}
			}
			for i := len(a.Members); i <= firewall.MaxActionMembers; i++ {
				m := a.Members[1]
				m.Request.ID, m.Request.Target = fmt.Sprintf("member-%03d", i), fmt.Sprintf("198.51.100.%d", i)
				a.Members = append(a.Members, m)
			}
		},
		"victim of an unblock": func(a *firewall.FirewallAction) {
			*a = admissionFixture()
			victims := batchFixture().Members[0].Victims
			victims[0].IP = "198.51.100.77"
			a.Members = []firewall.ActionMember{{Request: a.Request, Budget: a.Budget, Victims: victims}}
		},
		"one member request differs": func(a *firewall.FirewallAction) {
			*a = admissionFixture()
			member := a.Request
			member.Reason = "other"
			a.Members = []firewall.ActionMember{{Request: member, Budget: a.Budget}}
		},
		"one member charge differs": func(a *firewall.FirewallAction) {
			*a = admissionFixture()
			a.Members = []firewall.ActionMember{{Request: a.Request}}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := batchFixture()
			change(&in)
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.AdmitFirewallAction(in); err == nil || errors.Is(err, firewall.ErrStateConflict) || errors.Is(err, firewall.ErrStateCorrupt) || errors.Is(err, firewall.ErrScanBudget) {
				t.Fatalf("invalid manifest admitted or refused for another reason: %v", err)
			}
			if _, err := db.ReadFirewallAction(in.Request.ID); !errors.Is(err, ErrFirewallActionMissing) {
				t.Fatalf("refused manifest left a record: %v", err)
			}
		})
	}
	t.Run("largest batch", func(t *testing.T) {
		db := openSnapshotDB(t)
		in := batchFixture()
		for i := len(in.Members); i < firewall.MaxActionMembers; i++ {
			m := in.Members[1]
			m.Request.ID, m.Request.Target = fmt.Sprintf("member-%03d", i), fmt.Sprintf("198.51.100.%d", i)
			in.Members = append(in.Members, m)
		}
		for i := range in.Members {
			in.Members[i].Budget = &firewall.ScanAdmission{Window: "2026-01-02T03", Limit: firewall.MaxActionMembers}
		}
		if a := admitFixture(t, db, in); len(a.Members) != firewall.MaxActionMembers {
			t.Fatalf("largest batch kept %d members", len(a.Members))
		}
	})
}

// rewriteStoredAction replaces a stored action with an envelope of the given
// version around fields, with a valid checksum.
func rewriteStoredAction(t *testing.T, db *DB, id string, version uint64, change func(map[string]json.RawMessage)) {
	t.Helper()
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(firewallActionsBucket))
		_, fields := storedEnvelope(t, b.Get([]byte(id)))
		change(fields)
		raw, err := encodeFirewallJournalVersion(fields, version)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), raw)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallManifestMustMatchItsVersion(t *testing.T) {
	cases := map[string]struct {
		batch   bool
		version uint64
		change  func(map[string]json.RawMessage)
	}{
		"version one with members": {batch: true, version: 1, change: func(map[string]json.RawMessage) {}},
		"version two without":      {version: 2, change: func(map[string]json.RawMessage) {}},
		"version two null members": {batch: true, version: 2, change: func(f map[string]json.RawMessage) { f["members"] = json.RawMessage("null") }},
		"version two no members":   {batch: true, version: 2, change: func(f map[string]json.RawMessage) { f["members"] = json.RawMessage("[]") }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := admissionFixture()
			if c.batch {
				in = batchFixture()
			}
			admitFixture(t, db, in)
			rewriteStoredAction(t, db, in.Request.ID, c.version, c.change)
			if _, err := db.ReadFirewallAction(in.Request.ID); !errors.Is(err, firewall.ErrStateCorrupt) || errors.Is(err, firewall.ErrStateUnsupported) {
				t.Fatalf("mismatched manifest version read as %v", err)
			}
		})
	}
}

func TestFirewallRecordsFromANewerBuildAreUnsupported(t *testing.T) {
	t.Run("action", func(t *testing.T) {
		db := openSnapshotDB(t)
		in := batchFixture()
		admitFixture(t, db, in)
		rewriteStoredAction(t, db, in.Request.ID, 3, func(map[string]json.RawMessage) {})
		if _, err := db.ReadFirewallAction(in.Request.ID); !errors.Is(err, firewall.ErrStateUnsupported) || !errors.Is(err, firewall.ErrStateCorrupt) {
			t.Fatalf("newer action read as %v", err)
		}
		if _, err := db.TransitionFirewallAction(in.Request.ID, "failed", "", in.CreatedAt); !errors.Is(err, firewall.ErrStateUnsupported) {
			t.Fatalf("newer action transitioned: %v", err)
		}
	})
	t.Run("index", func(t *testing.T) {
		db := openSnapshotDB(t)
		in := admissionFixture()
		admitFixture(t, db, in)
		if err := db.bolt.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(firewallActionIndexBucket))
			_, fields := storedEnvelope(t, b.Get([]byte("index")))
			raw, err := encodeFirewallJournalVersion(fields, 2)
			if err != nil {
				return err
			}
			return b.Put([]byte("index"), raw)
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.PendingFirewallActions(); !errors.Is(err, firewall.ErrStateUnsupported) {
			t.Fatalf("newer index read as %v", err)
		}
		other := admissionFixture()
		other.Request.ID, other.Budget = "another-request", nil
		if _, _, err := db.AdmitFirewallAction(other); !errors.Is(err, firewall.ErrStateUnsupported) {
			t.Fatalf("admission over a newer index = %v", err)
		}
	})
	t.Run("snapshot", func(t *testing.T) {
		db := openSnapshotDB(t)
		if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
			t.Fatal(err)
		}
		if err := db.bolt.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(firewallSnapshotBucket))
			var meta map[string]json.RawMessage
			if err := json.Unmarshal(b.Get([]byte(firewallSnapshotKey)), &meta); err != nil {
				return err
			}
			meta["version"] = json.RawMessage("2")
			raw, err := json.Marshal(meta)
			if err != nil {
				return err
			}
			return b.Put([]byte(firewallSnapshotKey), raw)
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := db.ReadFirewallState(); !errors.Is(err, firewall.ErrStateUnsupported) {
			t.Fatalf("newer snapshot read as %v", err)
		}
		if _, err := db.ReplaceFirewallState(1, completeFirewallState()); !errors.Is(err, firewall.ErrStateUnsupported) {
			t.Fatalf("newer snapshot replaced: %v", err)
		}
	})
}

func TestFirewallReplayComparesTheWholeManifest(t *testing.T) {
	db := openSnapshotDB(t)
	in := batchFixture()
	original := admitFixture(t, db, in)
	later := batchFixture()
	later.Members[0].Budget = &firewall.ScanAdmission{Window: "2026-01-02T05", Limit: 9}
	replay, fresh, err := db.AdmitFirewallAction(later)
	if err != nil || fresh || !replay.SameManifest(original) || replay.Members[0].Budget.Window != "2026-01-02T03" {
		t.Fatalf("replay in a later window = %#v, %v, %v", replay.Members, fresh, err)
	}
	changes := map[string]func(*firewall.FirewallAction){
		"order":  func(a *firewall.FirewallAction) { a.Members[0], a.Members[1] = a.Members[1], a.Members[0] },
		"victim": func(a *firewall.FirewallAction) { a.Members[0].Victims[0].Reason = "other" },
		"member": func(a *firewall.FirewallAction) { a.Members[1].Request.Reason = "other" },
	}
	for name, change := range changes {
		changed := batchFixture()
		change(&changed)
		if _, _, err := db.AdmitFirewallAction(changed); !errors.Is(err, firewall.ErrStateConflict) {
			t.Errorf("%s change under the batch ID = %v, want conflict", name, err)
		}
	}
}

func TestFirewallAuditRejectsAChangedManifest(t *testing.T) {
	db := openSnapshotDB(t)
	in := batchFixture()
	admitFixture(t, db, in)
	unknown, err := db.TransitionFirewallAction(in.Request.ID, "unknown", "lost reply", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	changed := unknown
	changed.Members = append([]firewall.ActionMember(nil), unknown.Members...)
	changed.Members[1].Request.Reason = "other"
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		action, err := encodeFirewallActionRecord(changed)
		if err != nil {
			return err
		}
		raw, err := encodeFirewallJournal(firewallAuditEvent{Action: action})
		if err != nil {
			return err
		}
		return tx.Bucket([]byte(firewallAuditBucket)).Put(firewallAuditKey(in.Request.ID, unknown.AuditVersion), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.FirewallAuditPending(); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("changed audit manifest delivered: %v", err)
	}
	if err := db.AcknowledgeFirewallAudit(in.Request.ID, unknown.AuditVersion); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("changed audit manifest acknowledged: %v", err)
	}
}

func TestFirewallSnapshotKeepsActionRows(t *testing.T) {
	db := openSnapshotDB(t)
	state := completeFirewallState()
	state.Blocked[0].ActionID, state.Blocked[0].Unverified = "act_one", true
	if _, err := db.ReplaceFirewallState(0, state); err != nil {
		t.Fatal(err)
	}
	assertFirewallSnapshot(t, db, state, 1)
	state.Blocked[1].ActionID = "bad\xff"
	if _, err := db.ReplaceFirewallState(1, state); err == nil {
		t.Fatal("an action ID that cannot round-trip was stored")
	}
}

func TestFirewallNewerBuildVersionPrecedesPayload(t *testing.T) {
	for _, raw := range []string{
		`{"version":3,"payload":"opaque","sha256":"invalid"}`,
		`{"version":3,"payload":{},"sha256":"invalid"}`,
	} {
		if _, _, err := decodeFirewallJournalVersion([]byte(raw), firewallManifestVersion); !errors.Is(err, firewall.ErrStateUnsupported) {
			t.Fatalf("newer envelope interpreted before version refusal: %v", err)
		}
	}
}

func TestFirewallRecordsFromANewerBuildKeepRecoveryErrors(t *testing.T) {
	t.Run("pending action", func(t *testing.T) {
		db := openSnapshotDB(t)
		in := batchFixture()
		admitFixture(t, db, in)
		rewriteStoredAction(t, db, in.Request.ID, 3, func(map[string]json.RawMessage) {})
		before := db.WriteTxID()
		if _, err := db.PendingFirewallActions(); !errors.Is(err, firewall.ErrStateUnsupported) {
			t.Errorf("pending action lost unsupported cause: %v", err)
		}
		if _, fresh, err := db.AdmitFirewallAction(in); fresh || !errors.Is(err, firewall.ErrStateUnsupported) {
			t.Errorf("pending admission lost unsupported cause: fresh %v, %v", fresh, err)
		}
		if _, err := db.ReplaceFirewallState(1, in.Before); !errors.Is(err, firewall.ErrStateUnsupported) {
			t.Errorf("snapshot mutation lost unsupported cause: %v", err)
		}
		if db.WriteTxID() != before {
			t.Error("newer pending action changed the journal")
		}
	})
	for _, kind := range []string{"outer audit", "inner action", "current action"} {
		t.Run(kind, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := batchFixture()
			admitFixture(t, db, in)
			outcome, err := db.TransitionFirewallAction(in.Request.ID, "failed", "not applied", in.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "current action" {
				rewriteStoredAction(t, db, in.Request.ID, 3, func(map[string]json.RawMessage) {})
			} else if err := db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(firewallAuditBucket))
				key := firewallAuditKey(in.Request.ID, outcome.AuditVersion)
				event, _, err := decodeFirewallAuditEvent(key, b.Get(key))
				if err != nil {
					return err
				}
				version := uint64(2)
				if kind == "inner action" {
					event.Action, err = encodeFirewallJournalVersion(outcome, 3)
					if err != nil {
						return err
					}
					version = 1
				}
				raw, err := encodeFirewallJournalVersion(event, version)
				if err != nil {
					return err
				}
				return b.Put(key, raw)
			}); err != nil {
				t.Fatal(err)
			}
			before := db.WriteTxID()
			if _, err := db.FirewallAuditPending(); !errors.Is(err, firewall.ErrStateUnsupported) {
				t.Errorf("pending audit lost unsupported cause: %v", err)
			}
			if err := db.AcknowledgeFirewallAudit(in.Request.ID, outcome.AuditVersion); !errors.Is(err, firewall.ErrStateUnsupported) {
				t.Errorf("audit acknowledgement lost unsupported cause: %v", err)
			}
			if db.WriteTxID() != before {
				t.Error("newer audit changed the journal")
			}
		})
	}
}
