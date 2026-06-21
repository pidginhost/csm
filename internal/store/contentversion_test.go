package store

import "testing"

func TestEnsureContentLogicVersion(t *testing.T) {
	db := openTestDB(t)
	changed, err := db.EnsureContentLogicVersion("php=1;sig=7;yara=42")
	if err != nil || !changed {
		t.Fatalf("first call should report changed: changed=%v err=%v", changed, err)
	}
	changed, err = db.EnsureContentLogicVersion("php=1;sig=7;yara=42")
	if err != nil || changed {
		t.Fatalf("same token should be a no-op: changed=%v err=%v", changed, err)
	}
	changed, err = db.EnsureContentLogicVersion("php=2;sig=7;yara=42")
	if err != nil || !changed {
		t.Fatalf("new token should report changed: changed=%v err=%v", changed, err)
	}
}
