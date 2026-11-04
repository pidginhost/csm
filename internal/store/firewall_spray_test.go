package store

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func TestFirewallBatchValidatesSprayTags(t *testing.T) {
	for _, mode := range []string{"lost tag", "forged tag", "operator tag", "valid tag"} {
		t.Run(mode, func(t *testing.T) {
			a := batchFixture()
			member := &a.Members[0]
			member.Request.LoginSpray = mode != "forged tag"
			for i := range a.After.Blocked {
				row := &a.After.Blocked[i]
				if row.ActionID == member.Request.ID {
					row.LoginSpray = mode != "lost tag"
					row.Automatic = mode != "operator tag"
				}
			}
			db := openSnapshotDB(t)
			if _, err := db.ReplaceFirewallState(0, a.Before); err != nil {
				t.Fatal(err)
			}
			_, fresh, err := db.AdmitFirewallAction(a)
			if mode == "valid tag" {
				if err != nil || !fresh {
					t.Fatalf("valid tag refused: fresh=%t, %v", fresh, err)
				}
			} else if fresh || !errors.Is(err, errInvalidFirewallManifest) {
				t.Fatalf("mismatched tag admitted: fresh=%t, %v", fresh, err)
			}
			a.Phase, a.UpdatedAt, a.AuditVersion = "planned", a.CreatedAt, 1
			raw, err := encodeFirewallActionRecord(a)
			if err != nil {
				t.Fatal(err)
			}
			_, err = decodeFirewallAction(raw)
			if mode == "valid tag" && err != nil || mode != "valid tag" && !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("stored tag validation = %v", err)
			}
		})
	}
}
