package store

import (
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
		"2026-01-09": {Sends: 12, IPs: []string{"203.0.113.5", "203.0.113.9"}, MaxHourIPs: 2, Countries: []string{"RO"}, Recipients: []string{"a@example.net"}},
		"2026-01-10": {Sends: 1, IPs: []string{"198.51.100.7"}, MaxHourIPs: 1, Countries: []string{"DE"}, Recipients: []string{"b@example.org", "c@example.org"}},
	}}
	if err := db.SetSenderProfile("user@example.com", want); err != nil {
		t.Fatalf("SetSenderProfile: %v", err)
	}
	got, found := db.GetSenderProfile("user@example.com")
	if !found {
		t.Fatal("GetSenderProfile: not found")
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

	got, found := db.GetSenderProfile("nobody@example.com")
	if found || got.Days != nil {
		t.Fatalf("missing profile returned found=%v %+v", found, got)
	}
}
