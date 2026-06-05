package challenge

import (
	"os"
	"path/filepath"
	"strings"
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

func TestIPListExpiredEntriesSkipsNonEscalating(t *testing.T) {
	dir := t.TempDir()
	l := NewIPList(dir)
	l.Add("203.0.113.5", "escalate", -1*time.Second)
	l.AddNonEscalating("203.0.113.6", "challenge-only", -1*time.Second)

	expired := l.ExpiredEntries()
	if len(expired) != 1 {
		t.Fatalf("got %d expired, want 1", len(expired))
	}
	if expired[0].IP != "203.0.113.5" {
		t.Fatalf("expired IP = %q, want 203.0.113.5", expired[0].IP)
	}
	if l.Contains("203.0.113.5") {
		t.Error("escalating expired IP should have been removed")
	}
	if l.Contains("203.0.113.6") {
		t.Error("non-escalating expired IP should have been removed")
	}
}

func TestIPListExpiredEntriesFlushesNonEscalatingRemoval(t *testing.T) {
	dir := t.TempDir()
	l := NewIPList(dir)
	l.AddNonEscalating("203.0.113.6", "challenge-only", -1*time.Second)

	if expired := l.ExpiredEntries(); len(expired) != 0 {
		t.Fatalf("got expired entries %v, want none", expired)
	}
	if l.Contains("203.0.113.6") {
		t.Fatal("non-escalating expired IP should have been removed")
	}
	data, err := os.ReadFile(filepath.Join(dir, "challenge_ips.txt"))
	if err != nil {
		t.Fatalf("read challenge map: %v", err)
	}
	if strings.Contains(string(data), "203.0.113.6 challenge") {
		t.Fatalf("challenge map still contains expired non-escalating IP: %s", data)
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

func TestNewIPListWithMapPathClearsStaleMap(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "run", "challenge_ips.txt")
	if err := os.MkdirAll(filepath.Dir(mapPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mapPath, []byte("203.0.113.8 challenge\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	NewIPListWithMapPath(dir, mapPath)

	data, err := os.ReadFile(mapPath)
	if err != nil {
		t.Fatalf("map not rewritten: %v", err)
	}
	if strings.Contains(string(data), "203.0.113.8 challenge") {
		t.Fatalf("stale challenge entry remained after new list: %s", data)
	}
}

func TestIPListWritesNginxMapAndReloadsOnChanges(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "run", "challenge_ips.txt")
	nginxMapPath := filepath.Join(dir, "run", "challenge_ips.nginx.map")
	l := NewIPListWithMapPath(dir, mapPath)

	reloads := 0
	l.SetNginxMap(nginxMapPath, func() error {
		reloads++
		return nil
	})
	if reloads != 1 {
		t.Fatalf("initial stale-map clear reloads = %d, want 1", reloads)
	}
	reloads = 0

	l.Add("203.0.113.5", "test", time.Hour)
	if reloads != 1 {
		t.Fatalf("reloads after Add = %d, want 1", reloads)
	}
	data, err := os.ReadFile(nginxMapPath)
	if err != nil {
		t.Fatalf("nginx map not written: %v", err)
	}
	if !strings.Contains(string(data), "203.0.113.5 1;") {
		t.Fatalf("nginx map missing challenged IP: %s", data)
	}

	l.Add("203.0.113.5", "test", time.Hour)
	if reloads != 1 {
		t.Fatalf("unchanged Add reloads = %d, want 1", reloads)
	}

	l.Remove("203.0.113.5")
	if reloads != 2 {
		t.Fatalf("reloads after Remove = %d, want 2", reloads)
	}
	data, err = os.ReadFile(nginxMapPath)
	if err != nil {
		t.Fatalf("nginx map not readable after Remove: %v", err)
	}
	if strings.Contains(string(data), "203.0.113.5 1;") {
		t.Fatalf("nginx map kept removed IP: %s", data)
	}
}
