package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

func TestFirewallJournalVersionPrecedesSchema(t *testing.T) {
	for name, fields := range map[string]string{
		"checksum type": `"payload":{},"sha256":{}`,
		"payload text":  `"payload":{"detail":"\ud800"},"sha256":"invalid"`,
	} {
		t.Run(name, func(t *testing.T) {
			for _, version := range []uint64{1, 3} {
				raw := []byte(fmt.Sprintf(`{"version":%d,%s}`, version, fields))
				_, actionErr := decodeFirewallAction(raw)
				_, journalErr := decodeFirewallJournal(raw)
				for _, err := range []error{actionErr, journalErr} {
					if !errors.Is(err, firewall.ErrStateCorrupt) || errors.Is(err, firewall.ErrStateUnsupported) != (version == 3) {
						t.Errorf("version %d decoded as %v", version, err)
					}
				}
			}
		})
	}
}

func TestFirewallSnapshotVersionPrecedesSchema(t *testing.T) {
	for name, fields := range map[string]string{
		"revision type":   `"revision":"future","collections":[]`,
		"collection type": `"revision":1,"collections":{}`,
	} {
		for _, version := range []uint64{1, 2} {
			t.Run(fmt.Sprintf("%s/version%d", name, version), func(t *testing.T) {
				db := openSnapshotDB(t)
				in := admissionFixture()
				admitFixture(t, db, in)
				raw := []byte(fmt.Sprintf(`{"version":%d,%s}`, version, fields))
				if err := db.bolt.Update(func(tx *bolt.Tx) error {
					return tx.Bucket([]byte(firewallSnapshotBucket)).Put([]byte(firewallSnapshotKey), raw)
				}); err != nil {
					t.Fatal(err)
				}
				before := db.WriteTxID()
				_, revision, readErr := db.ReadFirewallState()
				if revision != 0 {
					t.Errorf("unreadable snapshot returned revision %d", revision)
				}
				_, transitionErr := db.TransitionFirewallAction(in.Request.ID, "failed", "", in.CreatedAt)
				kernel := &observedKernel{state: in.Before}
				lifecycle := &firewall.Lifecycle{Store: db}
				recoveryErr := lifecycle.Recover(kernel)
				for _, err := range []error{readErr, transitionErr, recoveryErr} {
					if !errors.Is(err, firewall.ErrStateCorrupt) || errors.Is(err, firewall.ErrStateUnsupported) != (version == 2) {
						t.Errorf("version %d read or recovered as %v", version, err)
					}
				}
				if db.WriteTxID() != before || kernel.writes != 0 {
					t.Fatal("unreadable snapshot changed persistent or kernel state")
				}
			})
		}
	}
}

func TestFirewallFutureSchemaKeepsRecoveryAndAuditErrors(t *testing.T) {
	for _, kind := range []string{"pending action", "current action", "inner audit action", "outer audit"} {
		t.Run(kind, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := batchFixture()
			outcome := admitFixture(t, db, in)
			if kind != "pending action" {
				var err error
				outcome, err = db.TransitionFirewallAction(in.Request.ID, "failed", "", in.CreatedAt)
				if err != nil {
					t.Fatal(err)
				}
			}
			// This payload is valid JSON but cannot be interpreted losslessly by
			// this build. The enclosing supported audit must leave it opaque too.
			future := []byte(`{"version":3,"payload":{"detail":"\ud800"},"sha256":{}}`)
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				switch kind {
				case "pending action", "current action":
					return tx.Bucket([]byte(firewallActionsBucket)).Put([]byte(in.Request.ID), future)
				case "inner audit action":
					raw, err := encodeFirewallJournal(firewallAuditEvent{Action: future})
					if err != nil {
						return err
					}
					return tx.Bucket([]byte(firewallAuditBucket)).Put(firewallAuditKey(in.Request.ID, outcome.AuditVersion), raw)
				default:
					return tx.Bucket([]byte(firewallAuditBucket)).Put(firewallAuditKey(in.Request.ID, outcome.AuditVersion), future)
				}
			}); err != nil {
				t.Fatal(err)
			}
			before := db.WriteTxID()
			audited := 0
			lifecycle := &firewall.Lifecycle{Store: db, Audit: func(firewall.FirewallAction) error {
				audited++
				return nil
			}}
			kernel := &observedKernel{state: outcome.Before}
			if err := lifecycle.Recover(kernel); !errors.Is(err, firewall.ErrStateUnsupported) {
				t.Errorf("recovery lost unsupported cause: %v", err)
			}
			if kind == "pending action" {
				if _, fresh, err := db.AdmitFirewallAction(in); fresh || !errors.Is(err, firewall.ErrStateUnsupported) {
					t.Errorf("admission lost unsupported cause: fresh %v, %v", fresh, err)
				}
			} else {
				if err := lifecycle.DeliverAudit(); !errors.Is(err, firewall.ErrStateUnsupported) {
					t.Errorf("audit delivery lost unsupported cause: %v", err)
				}
				if err := db.AcknowledgeFirewallAudit(in.Request.ID, outcome.AuditVersion); !errors.Is(err, firewall.ErrStateUnsupported) {
					t.Errorf("acknowledgement lost unsupported cause: %v", err)
				}
			}
			if db.WriteTxID() != before || kernel.writes != 0 || audited != 0 {
				t.Fatal("unsupported record changed state or reached the audit writer")
			}
		})
	}
}

func TestFirewallAuditRejectsSupportedInvalidText(t *testing.T) {
	db := openSnapshotDB(t)
	in := batchFixture()
	admitFixture(t, db, in)
	outcome, err := db.TransitionFirewallAction(in.Request.ID, "failed", "", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		action, err := encodeFirewallActionRecord(outcome)
		if err != nil {
			return err
		}
		raw, err := encodeFirewallJournal(map[string]json.RawMessage{
			"action": action, "acknowledged": json.RawMessage("false"), "extra": json.RawMessage(`"\ud800"`),
		})
		if err != nil {
			return err
		}
		return tx.Bucket([]byte(firewallAuditBucket)).Put(firewallAuditKey(in.Request.ID, outcome.AuditVersion), raw)
	}); err != nil {
		t.Fatal(err)
	}
	before := db.WriteTxID()
	_, pendingErr := db.FirewallAuditPending()
	ackErr := db.AcknowledgeFirewallAudit(in.Request.ID, outcome.AuditVersion)
	for _, err := range []error{pendingErr, ackErr} {
		if !errors.Is(err, firewall.ErrStateCorrupt) || errors.Is(err, firewall.ErrStateUnsupported) {
			t.Errorf("supported audit with invalid text returned %v", err)
		}
	}
	if db.WriteTxID() != before {
		t.Fatal("invalid audit was acknowledged")
	}
}
