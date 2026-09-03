package store

import "testing"

func TestContentLogicVersionIsRecordedOnlyAfterCompletedSweep(t *testing.T) {
	db := openTestDB(t)
	changed, err := db.ContentLogicVersionChanged("php=1;sig=7;yara=42")
	if err != nil || !changed {
		t.Fatalf("new token should report changed: changed=%v err=%v", changed, err)
	}
	changed, err = db.ContentLogicVersionChanged("php=1;sig=7;yara=42")
	if err != nil || !changed {
		t.Fatalf("unrecorded token must still request a retry: changed=%v err=%v", changed, err)
	}
	if setErr := db.SetContentLogicVersion("php=1;sig=7;yara=42"); setErr != nil {
		t.Fatalf("record completed token: %v", setErr)
	}
	changed, err = db.ContentLogicVersionChanged("php=1;sig=7;yara=42")
	if err != nil || changed {
		t.Fatalf("recorded token should be a no-op: changed=%v err=%v", changed, err)
	}
	changed, err = db.ContentLogicVersionChanged("php=2;sig=7;yara=42")
	if err != nil || !changed {
		t.Fatalf("new token should report changed: changed=%v err=%v", changed, err)
	}
}
