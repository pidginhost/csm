package store

import (
	"testing"
	"time"
)

func TestGeoHistory_SetAndGet(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	h := GeoHistory{
		Countries: map[string]int64{
			"US": 10,
			"DE": 3,
			"RO": 1,
		},
		LoginCount: 14,
	}

	if err := db.SetGeoHistory("user@example.com", h); err != nil {
		t.Fatalf("SetGeoHistory: %v", err)
	}

	got, found := db.GetGeoHistory("user@example.com")
	if !found {
		t.Fatal("GetGeoHistory: not found")
	}
	if got.LoginCount != 14 {
		t.Fatalf("LoginCount = %d, want 14", got.LoginCount)
	}
	if len(got.Countries) != 3 {
		t.Fatalf("len(Countries) = %d, want 3", len(got.Countries))
	}
	if got.Countries["US"] != 10 {
		t.Fatalf("Countries[US] = %d, want 10", got.Countries["US"])
	}
	if got.Countries["DE"] != 3 {
		t.Fatalf("Countries[DE] = %d, want 3", got.Countries["DE"])
	}
	if got.Countries["RO"] != 1 {
		t.Fatalf("Countries[RO] = %d, want 1", got.Countries["RO"])
	}
}

func TestGeoHistory_NotFound(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	_, found := db.GetGeoHistory("nonexistent@example.com")
	if found {
		t.Fatal("GetGeoHistory(nonexistent) should not be found")
	}
}

func TestForwarderHash_SetAndGet(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	key := "user@example.com:/etc/valiases/example.com"
	hash := "sha256:abcdef1234567890"

	if err := db.SetForwarderHash(key, hash); err != nil {
		t.Fatalf("SetForwarderHash: %v", err)
	}

	got, found := db.GetForwarderHash(key)
	if !found {
		t.Fatal("GetForwarderHash: not found")
	}
	if got != hash {
		t.Fatalf("GetForwarderHash = %q, want %q", got, hash)
	}

	// Nonexistent key returns false.
	_, found = db.GetForwarderHash("nonexistent")
	if found {
		t.Fatal("GetForwarderHash(nonexistent) should not be found")
	}
}

func TestEmailAuditMeta(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Initially should be zero.
	got := db.GetEmailPWLastRefresh()
	if !got.IsZero() {
		t.Fatalf("initial GetEmailPWLastRefresh = %v, want zero", got)
	}

	// Set and get back.
	now := time.Now().Truncate(time.Second)
	if err := db.SetEmailPWLastRefresh(now); err != nil {
		t.Fatalf("SetEmailPWLastRefresh: %v", err)
	}

	got = db.GetEmailPWLastRefresh()
	if !got.Equal(now) {
		t.Fatalf("GetEmailPWLastRefresh = %v, want %v", got, now)
	}
}

func TestMetaString(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Initially empty.
	got := db.GetMetaString("email:dkim_last_check")
	if got != "" {
		t.Fatalf("initial GetMetaString = %q, want empty", got)
	}

	// Set and get back.
	ts := "2026-04-04T10:00:00Z"
	if err := db.SetMetaString("email:dkim_last_check", ts); err != nil {
		t.Fatalf("SetMetaString: %v", err)
	}

	got = db.GetMetaString("email:dkim_last_check")
	if got != ts {
		t.Fatalf("GetMetaString = %q, want %q", got, ts)
	}
}
