package store

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSenderProfile_SetAndGet(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	want := SenderProfile{Days: map[string]*SenderDay{
		"2026-01-09": {Sends: 12, IPs: []string{"203.0.113.5", "203.0.113.9"}, MaxHourIPs: 2, Countries: []string{"RO"}, Recipients: []string{"a@example.net"}, SingleRecipients: []string{"a@example.net"}},
		"2026-01-10": {Sends: 1, IPs: []string{"198.51.100.7"}, MaxHourIPs: 1, Countries: []string{"DE"}, Recipients: []string{"b@example.org", "c@example.org"}},
	}}
	if setErr := db.SetSenderProfile("user@example.com", want); setErr != nil {
		t.Fatalf("SetSenderProfile: %v", setErr)
	}
	got, err := db.GetSenderProfile("user@example.com")
	if err != nil {
		t.Fatalf("GetSenderProfile: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestSenderProfile_NotFound(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	got, err := db.GetSenderProfile("nobody@example.com")
	if err != nil || got.Days != nil {
		t.Fatalf("missing profile returned err=%v %+v", err, got)
	}
}

func TestSenderProfile_PruneAdjacentMailboxes(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for i := 0; i < 6; i++ {
		user := fmt.Sprintf("user%d@example.com", i)
		p := SenderProfile{Days: map[string]*SenderDay{"2026-01-01": {Sends: 1}}}
		if setErr := db.SetSenderProfile(user, p); setErr != nil {
			t.Fatal(setErr)
		}
	}
	if pruneErr := db.PruneSenderProfiles("2026-01-02"); pruneErr != nil {
		t.Fatal(pruneErr)
	}
	for i := 0; i < 6; i++ {
		user := fmt.Sprintf("user%d@example.com", i)
		p, getErr := db.GetSenderProfile(user)
		if getErr != nil || p.Days != nil {
			t.Fatalf("expired mailbox %s survived pruning: %+v, %v", user, p, getErr)
		}
	}
}
