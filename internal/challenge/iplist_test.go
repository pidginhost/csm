package challenge

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIPListAddAndContains(t *testing.T) {
	dir := t.TempDir()
	l := NewIPList(dir)
	l.Add("203.0.113.5", "test", 1*time.Hour)

	if !l.Contains("203.0.113.5") {
		t.Error("added IP should be contained")
	}
	if l.Contains("1.1.1.1") {
		t.Error("unknown IP should not be contained")
	}
}

func TestIPListRemove(t *testing.T) {
	dir := t.TempDir()
	l := NewIPList(dir)
	l.Add("203.0.113.5", "test", 1*time.Hour)
	l.Remove("203.0.113.5")

	if l.Contains("203.0.113.5") {
		t.Error("removed IP should not be contained")
	}
}

func TestIPListExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	l := NewIPList(dir)
	// Add with very short TTL — already expired.
	l.mu.Lock()
	l.ips["203.0.113.5"] = challengeEntry{
		ExpiresAt: time.Now().Add(-1 * time.Second),
		Reason:    "brute-force",
	}
	l.ips["203.0.113.6"] = challengeEntry{
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Reason:    "test",
	}
	l.mu.Unlock()

	expired := l.ExpiredEntries()
	if len(expired) != 1 {
		t.Fatalf("got %d expired, want 1", len(expired))
	}
	if expired[0].IP != "203.0.113.5" {
		t.Errorf("expired IP = %q", expired[0].IP)
	}
	if l.Contains("203.0.113.5") {
		t.Error("expired IP should have been removed")
	}
	if !l.Contains("203.0.113.6") {
		t.Error("unexpired IP should still be contained")
	}
}

func TestIPListCleanExpiredRemovesOld(t *testing.T) {
	dir := t.TempDir()
	l := NewIPList(dir)
	l.mu.Lock()
	l.ips["old"] = challengeEntry{ExpiresAt: time.Now().Add(-1 * time.Minute)}
	l.mu.Unlock()

	l.CleanExpired()
	if l.Contains("old") {
		t.Error("CleanExpired should remove expired entries")
	}
}

func TestIPListFlushWritesFile(t *testing.T) {
	dir := t.TempDir()
	l := NewIPList(dir)
	l.Add("203.0.113.5", "test", 1*time.Hour)

	data, err := os.ReadFile(filepath.Join(dir, "challenge_ips.txt"))
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	if len(data) == 0 {
		t.Error("file should not be empty")
	}
}
