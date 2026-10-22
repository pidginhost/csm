package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// The optional directory exports synthetic fixtures for the old-reader probe.
// With no export requested this still tests every round trip in a temp directory.
func TestFirewallBatchCompatibilityFixture(t *testing.T) {
	dir := os.Getenv("CSM_TEST_BATCH_COMPAT_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	for _, phase := range []string{"planned", "unknown", "verified", "failed", "single"} {
		t.Run(phase, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := batchFixture()
			if phase == "single" {
				in = admissionFixture()
			}
			a := admitFixture(t, db, in)
			if phase != "planned" && phase != "single" {
				var err error
				a, err = db.TransitionFirewallAction(in.Request.ID, phase, "fixture", in.CreatedAt)
				if err != nil {
					t.Fatal(err)
				}
			}
			var raw []byte
			if err := db.bolt.View(func(tx *bolt.Tx) error {
				raw = bytes.Clone(tx.Bucket([]byte(firewallActionsBucket)).Get([]byte(a.Request.ID)))
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeFirewallAction(raw)
			if err != nil || !decoded.SameManifest(a) || decoded.Phase != a.Phase {
				t.Fatalf("fixture round trip = %#v, %v", decoded, err)
			}
			if err := os.WriteFile(filepath.Join(dir, phase+".json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			old, readErr := os.ReadFile(filepath.Join(dir, phase+"-old.json"))
			if readErr == nil {
				fromOld, err := decodeFirewallAction(old)
				if err != nil || !fromOld.SameManifest(a) || fromOld.Phase != a.Phase || !bytes.Equal(raw, old) {
					t.Fatalf("old reader changed stored evidence: %v", err)
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if len(a.ActionMembers()) != 1 && len(a.ActionMembers()) != 2 {
				t.Fatal("fixture has an unexpected manifest")
			}
			if phase != "single" && len(a.Members) != 2 {
				t.Fatal("compatibility fixture lost batch members")
			}
		})
	}
}
