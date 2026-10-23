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
