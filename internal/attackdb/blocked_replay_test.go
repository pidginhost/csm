package attackdb

import (
	"reflect"
	"testing"
)

func TestMarkBlockedReplayDoesNotQueueAnotherWrite(t *testing.T) {
	db := newTestDB(t)
	const ip = "203.0.113.47"
	db.RecordFinding(findingFromIP(ip))
	db.MarkBlocked(ip)
	before := db.LookupIP(ip)
	if before == nil || !before.AutoBlocked {
		t.Fatal("first delivery did not mark the address")
	}
	delete(db.dirtyIPs, ip)
	db.dirty = false
	db.MarkBlocked(ip)
	if _, dirty := db.dirtyIPs[ip]; dirty || db.dirty || !reflect.DeepEqual(before, db.LookupIP(ip)) {
		t.Fatal("repeated delivery changed or queued the attack record")
	}
}
