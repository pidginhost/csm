package state

import (
	"os"
	"testing"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
)

func TestStoreOpenClose(t *testing.T) {
	dir, err := os.MkdirTemp("", "csm-state-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	s.SetRaw("key1", "val1")
	_ = s.Close()

	// Reopen and verify
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer func() { _ = s2.Close() }()

	v, ok := s2.GetRaw("key1")
	if !ok || v != "val1" {
		t.Errorf("GetRaw(key1) = %q, %v, want 'val1', true", v, ok)
	}
}

func TestFilterNew(t *testing.T) {
	dir, err := os.MkdirTemp("", "csm-state-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	now := time.Now()
	findings := []alert.Finding{
		{Check: "a", Message: "msg1", Timestamp: now},
		{Check: "b", Message: "msg2", Timestamp: now},
	}

	// First time — all should be new
	newF := s.FilterNew(findings)
	if len(newF) != 2 {
		t.Errorf("first FilterNew: got %d, want 2", len(newF))
	}

	// Update state
	s.Update(findings)

	// Second time — none should be new
	newF = s.FilterNew(findings)
	if len(newF) != 0 {
		t.Errorf("second FilterNew: got %d, want 0", len(newF))
	}
}

func TestSetBaseline(t *testing.T) {
	dir, err := os.MkdirTemp("", "csm-state-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	findings := []alert.Finding{
		{Check: "a", Message: "existing"},
	}
	s.SetBaseline(findings)

	// Same finding should not be new
	newF := s.FilterNew(findings)
	if len(newF) != 0 {
		t.Errorf("after baseline: got %d new, want 0", len(newF))
	}

	// Different finding should be new
	different := []alert.Finding{
		{Check: "b", Message: "new thing"},
	}
	newF = s.FilterNew(different)
	if len(newF) != 1 {
		t.Errorf("new finding after baseline: got %d, want 1", len(newF))
	}
}

func TestDirtyTracking(t *testing.T) {
	dir, err := os.MkdirTemp("", "csm-state-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Not dirty initially
	if s.dirty {
		t.Error("store should not be dirty after open")
	}

	s.SetRaw("k", "v")
	if !s.dirty {
		t.Error("store should be dirty after SetRaw")
	}

	_ = s.Close()

	// Reopen — setting same value should not dirty
	s2, _ := Open(dir)
	s2.SetRaw("k", "v") // same value
	if s2.dirty {
		t.Error("store should not be dirty when SetRaw with same value")
	}
	_ = s2.Close()
}
