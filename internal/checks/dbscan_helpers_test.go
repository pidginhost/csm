package checks

import "testing"

// --- safeGet ----------------------------------------------------------

func TestSafeGetInBounds(t *testing.T) {
	parts := []string{"a", "b", "c"}
	if got := safeGet(parts, 1); got != "b" {
		t.Errorf("got %q, want b", got)
	}
}

func TestSafeGetOutOfBounds(t *testing.T) {
	parts := []string{"a"}
	if got := safeGet(parts, 5); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- truncateDB -------------------------------------------------------

func TestTruncateDBShort(t *testing.T) {
	if got := truncateDB("hello", 10); got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestTruncateDBLong(t *testing.T) {
	if got := truncateDB("hello world", 5); got != "hello..." {
		t.Errorf("got %q", got)
	}
}
