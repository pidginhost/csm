package workerproc

import (
	"strconv"
	"testing"
	"time"
)

func fixedStrikes(now *time.Time) *Strikes {
	s := NewStrikes()
	s.now = func() time.Time { return *now }
	return s
}

func TestStrikesBlockAfterTwoFailures(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := fixedStrikes(&now)
	s.Record("a")
	if s.Blocked("a") {
		t.Fatal("blocked after one failure")
	}
	s.Record("a")
	if !s.Blocked("a") || s.Blocked("b") {
		t.Fatal("two failures did not block exactly that input")
	}
}

func TestStrikesExpireAfterTTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := fixedStrikes(&now)
	s.Record("a")
	s.Record("a")
	now = now.Add(StrikeTTL + time.Second)
	if s.Blocked("a") {
		t.Fatal("strikes did not expire")
	}
	s.Record("a")
	if s.Blocked("a") {
		t.Fatal("an expired strike still counted")
	}
}

func TestStrikesLenDropsExpiredInputs(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := fixedStrikes(&now)
	s.Record("expired")
	s.Record("expired")
	now = now.Add(StrikeTTL)
	s.Record("recent")
	if got := s.Len(); got != 2 {
		t.Fatalf("Len at expiry boundary = %d, want 2", got)
	}
	now = now.Add(time.Second)
	if got := s.Len(); got != 1 || s.Blocked("expired") {
		t.Fatalf("Len = %d, want only the recent input", got)
	}
	s.Record("recent")
	if !s.Blocked("recent") {
		t.Fatal("expiry discarded a recent failure")
	}
	now = now.Add(StrikeTTL + time.Second)
	if got := s.Len(); got != 0 {
		t.Fatalf("Len = %d after all failures expired, want 0", got)
	}
}

func TestStrikesEvictOldestWhenFull(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := fixedStrikes(&now)
	for i := range 1025 {
		now = now.Add(time.Second)
		s.Record(strconv.Itoa(i))
		s.Record(strconv.Itoa(i))
	}
	if got := s.Len(); got != 1024 {
		t.Fatalf("Len = %d", got)
	}
	if s.Blocked("0") || !s.Blocked("1") || !s.Blocked("1024") {
		t.Fatal("eviction did not drop exactly the oldest input")
	}
}

func TestStrikesWithCustomLimit(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := NewStrikesWith(3, 10*time.Minute)
	s.now = func() time.Time { return now }
	for i := range 3 {
		if s.Blocked("src") {
			t.Fatalf("blocked after %d failures, want 3", i)
		}
		s.Record("src")
		now = now.Add(4 * time.Minute)
	}
	now = now.Add(-4 * time.Minute)
	if !s.Blocked("src") {
		t.Fatal("three failures 4 minutes apart did not block")
	}

	s = NewStrikesWith(3, 10*time.Minute)
	s.now = func() time.Time { return now }
	s.Record("src")
	now = now.Add(4 * time.Minute)
	s.Record("src")
	now = now.Add(11 * time.Minute)
	s.Record("src")
	if s.Blocked("src") {
		t.Fatal("a failure 11 minutes after the previous one still counted the old ones")
	}
}
