package store

import (
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestModSecExclusionTogglePreservesUnreadableList(t *testing.T) {
	for _, corrupt := range []string{`[900500,`, `[900500,"invalid",900501]`} {
		for _, operation := range []string{"add", "remove"} {
			t.Run(corrupt+"/"+operation, func(t *testing.T) {
				db := openTestDB(t)
				if err := db.bolt.Update(func(tx *bolt.Tx) error {
					return tx.Bucket([]byte("meta")).Put([]byte(modsecNoEscalateKey), []byte(corrupt))
				}); err != nil {
					t.Fatal(err)
				}
				if rules, readErr := db.GetModSecNoEscalateRules(); readErr == nil || rules != nil {
					t.Fatalf("unreadable exclusions returned %v, %v; want nil rules and an error", rules, readErr)
				}
				var err error
				if operation == "remove" {
					err = db.RemoveModSecNoEscalateRule(900500)
				} else {
					err = db.AddModSecNoEscalateRule(900502)
				}
				if err == nil {
					t.Error("toggle accepted an unreadable exclusion list")
				}
				if err := db.bolt.View(func(tx *bolt.Tx) error {
					if got := string(tx.Bucket([]byte("meta")).Get([]byte(modsecNoEscalateKey))); got != corrupt {
						t.Errorf("unreadable list changed to %q", got)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
