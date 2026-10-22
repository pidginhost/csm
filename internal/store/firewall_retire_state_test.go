package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

func TestFirewallRetireRefusesChangedBase(t *testing.T) {
	for _, revision := range []bool{false, true} {
		t.Run(map[bool]string{false: "state", true: "revision"}[revision], func(t *testing.T) {
			db := openSnapshotDB(t)
			a := unknownBatch(t, db, true)
			state := copyFirewallStateForTest(a.Before)
			want := firewall.ErrStateCorrupt
			if !revision {
				state.Blocked[0].Reason = "changed"
			} else {
				want = firewall.ErrStateConflict
			}
			meta, rows, err := encodeFirewallSnapshot(state)
			if err != nil {
				t.Fatal(err)
			}
			meta.Revision = a.Revision
			if revision {
				meta.Revision++
			}
			raw, err := json.Marshal(meta)
			if err != nil {
				t.Fatal(err)
			}
			// Keep both records valid so the before-state check detects drift.
			if err = db.bolt.Update(func(tx *bolt.Tx) error { return replaceFirewallSnapshot(tx, a.Revision, meta, rows, raw) }); err != nil {
				t.Fatal(err)
			}
			if stored, readErr := db.ReadFirewallAction(a.Request.ID); readErr != nil || !stored.SameManifest(a) {
				t.Fatalf("invalid action fixture: %#v %v", stored, readErr)
			}
			assertFirewallSnapshot(t, db, state, meta.Revision)
			image := batchIndexImage(t, db)
			if _, err := db.RetireFirewallAction(a.Request.ID, time.Now().UTC()); !errors.Is(err, want) {
				t.Fatalf("changed base retirement: %v", err)
			}
			if !bytes.Equal(image, batchIndexImage(t, db)) {
				t.Fatal("refused retirement changed the journal")
			}
		})
	}
}

func TestFirewallRetireSinglePreservesVersion(t *testing.T) {
	for _, manifest := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "manifest"}[manifest], func(t *testing.T) {
			db := openSnapshotDB(t)
			in := victimFixture()
			if !manifest {
				in.Members = nil
			}
			a := admitFixture(t, db, in)
			u, err := db.TransitionFirewallAction(a.Request.ID, "unknown", "lost reply", a.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			if err = db.AcknowledgeFirewallAudit(a.Request.ID, u.AuditVersion); err != nil {
				t.Fatal(err)
			}
			retired, err := db.RetireFirewallAction(a.Request.ID, a.CreatedAt.Add(2*time.Hour))
			if err != nil || !retired.Retired || !retired.SameManifest(a) || (retired.Members != nil) != manifest {
				t.Fatalf("single retirement: %#v %v", retired, err)
			}
			assertFirewallSnapshot(t, db, firewall.FirewallState{Blocked: in.Before.Blocked[1:]}, 2)
		})
	}
}
