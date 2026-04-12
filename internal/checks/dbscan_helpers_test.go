package checks

import "testing"

// --- isKnownSafeDBOption ----------------------------------------------

func TestIsKnownSafeDBOptionExact(t *testing.T) {
	for _, name := range []string{"active_plugins", "widget_text", "cron"} {
		if !isKnownSafeDBOption(name) {
			t.Errorf("%q should be safe", name)
		}
	}
}

func TestIsKnownSafeDBOptionPrefix(t *testing.T) {
	for _, name := range []string{"wordfence_rules", "wf_scan_status", "sucuri_config", "litespeed_option"} {
		if !isKnownSafeDBOption(name) {
			t.Errorf("%q should be safe (prefix match)", name)
		}
	}
}

func TestIsKnownSafeDBOptionUnsafe(t *testing.T) {
	for _, name := range []string{"siteurl", "blogname", "random_option"} {
		if isKnownSafeDBOption(name) {
			t.Errorf("%q should not be safe", name)
		}
	}
}

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
