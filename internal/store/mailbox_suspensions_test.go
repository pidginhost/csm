package store

import (
	"errors"
	"reflect"
	"regexp"
	"testing"
	"time"
)

func TestMailboxSuspensionIDStableAndCaseFolded(t *testing.T) {
	a := MailboxSuspensionID("cpanel", "Alice@Example.com")
	b := MailboxSuspensionID("cpanel", "alice@example.com")
	if a != b {
		t.Fatalf("IDs differ by case: %q vs %q", a, b)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(a) {
		t.Fatalf("ID %q is not 16 lowercase hex characters", a)
	}
	if other := MailboxSuspensionID("stalwart", "alice@example.com"); other == a {
		t.Fatalf("backend must be part of the ID, both gave %q", a)
	}
}

func testSuspension(subject string, at time.Time) MailboxSuspension {
	return MailboxSuspension{
		ID:          MailboxSuspensionID("cpanel", subject),
		Backend:     "cpanel",
		Subject:     subject,
		Kind:        SuspensionKindMailbox,
		Account:     "cpuser",
		Applied:     []string{AppliedSuspendLogin, AppliedSuspendOutgoing},
		Check:       "mail_account_compromised",
		Reason:      "test",
		SuspendedAt: at.UTC().Truncate(time.Second),
	}
}

func TestMailboxSuspensionRoundTrip(t *testing.T) {
	db := openTestDB(t)
	want := testSuspension("alice@example.com", time.Now())
	if err := db.PutMailboxSuspension(want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.GetMailboxSuspension(want.ID)
	if err != nil || !ok {
		t.Fatalf("Get = ok %v, err %v", ok, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
	}
	if _, ok, err := db.GetMailboxSuspension(MailboxSuspensionID("cpanel", "nobody@example.com")); ok || err != nil {
		t.Fatalf("unknown ID: ok %v, err %v", ok, err)
	}
}

func TestListMailboxSuspensionsNewestFirst(t *testing.T) {
	db := openTestDB(t)
	base := time.Now().Add(-3 * time.Hour)
	for i, subject := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		if err := db.PutMailboxSuspension(testSuspension(subject, base.Add(time.Duration(i)*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.ListMailboxSuspensions()
	if err != nil {
		t.Fatal(err)
	}
	var subjects []string
	for _, s := range got {
		subjects = append(subjects, s.Subject)
	}
	if want := []string{"c@example.com", "b@example.com", "a@example.com"}; !reflect.DeepEqual(subjects, want) {
		t.Fatalf("order = %v, want %v", subjects, want)
	}
}

func TestMarkMailboxSuspensionReleased(t *testing.T) {
	db := openTestDB(t)
	s := testSuspension("alice@example.com", time.Now().Add(-time.Hour))
	if err := db.PutMailboxSuspension(s); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if err := db.MarkMailboxSuspensionReleased(s.ID, at, "admin"); err != nil {
		t.Fatal(err)
	}
	got, _, err := db.GetMailboxSuspension(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReleasedAt == nil || !got.ReleasedAt.Equal(at) || got.ReleasedBy != "admin" {
		t.Fatalf("released = %v by %q, want %v by admin", got.ReleasedAt, got.ReleasedBy, at)
	}
	err = db.MarkMailboxSuspensionReleased(MailboxSuspensionID("cpanel", "nobody@example.com"), at, "admin")
	if !errors.Is(err, ErrMailboxSuspensionNotFound) {
		t.Fatalf("unknown ID: err = %v, want ErrMailboxSuspensionNotFound", err)
	}
}

func TestPutMailboxSuspensionPrunesOldReleased(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	released := func(subject string, ago time.Duration) MailboxSuspension {
		s := testSuspension(subject, now.Add(-ago-time.Hour))
		at := now.Add(-ago)
		s.ReleasedAt, s.ReleasedBy = &at, "admin"
		return s
	}
	old := released("old@example.com", 31*24*time.Hour)
	recent := released("recent@example.com", 29*24*time.Hour)
	active := testSuspension("active@example.com", now.Add(-40*24*time.Hour))
	for _, s := range []MailboxSuspension{old, recent, active} {
		if err := db.PutMailboxSuspension(s); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.PutMailboxSuspension(testSuspension("new@example.com", now)); err != nil {
		t.Fatal(err)
	}
	got, err := db.ListMailboxSuspensions()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, s := range got {
		have[s.Subject] = true
	}
	if len(got) != 3 || have["old@example.com"] || !have["recent@example.com"] || !have["active@example.com"] || !have["new@example.com"] {
		t.Fatalf("after prune = %v, want recent, active and new only", have)
	}
}
