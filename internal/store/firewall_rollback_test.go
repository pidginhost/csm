package store

import (
	"bytes"
	"testing"
	"time"
)

func TestFirewallRollbackRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if _, ok := db.GetFirewallRollback(); ok {
		t.Fatal("fresh DB should have no pending rollback")
	}

	now := time.Now().UTC().Truncate(time.Second)
	rb := FirewallRollback{
		PrevYAML:  []byte("hostname: old\n"),
		PrevHash:  "sha256:old",
		NewHash:   "sha256:new",
		AppliedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
		AppliedBy: "tok-test",
	}
	if err := db.SaveFirewallRollback(rb); err != nil {
		t.Fatal(err)
	}

	got, ok := db.GetFirewallRollback()
	if !ok {
		t.Fatal("expected pending rollback after save")
	}
	if !bytes.Equal(got.PrevYAML, rb.PrevYAML) {
		t.Errorf("PrevYAML mismatch: got %q, want %q", got.PrevYAML, rb.PrevYAML)
	}
	if got.PrevHash != rb.PrevHash || got.NewHash != rb.NewHash || got.AppliedBy != rb.AppliedBy {
		t.Errorf("metadata mismatch: got %+v want %+v", got, rb)
	}
	if !got.AppliedAt.Equal(rb.AppliedAt) || !got.ExpiresAt.Equal(rb.ExpiresAt) {
		t.Errorf("timestamps drifted: applied_at %v vs %v, expires_at %v vs %v",
			got.AppliedAt, rb.AppliedAt, got.ExpiresAt, rb.ExpiresAt)
	}

	if err := db.ClearFirewallRollback(); err != nil {
		t.Fatal(err)
	}
	if _, ok := db.GetFirewallRollback(); ok {
		t.Error("expected no rollback after Clear")
	}

	// Clear is idempotent.
	if err := db.ClearFirewallRollback(); err != nil {
		t.Errorf("Clear on empty bucket should be no-op, got %v", err)
	}
}

func TestFirewallRollbackOverwrites(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	first := FirewallRollback{PrevYAML: []byte("a"), AppliedBy: "first"}
	second := FirewallRollback{PrevYAML: []byte("b"), AppliedBy: "second"}
	if err := db.SaveFirewallRollback(first); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveFirewallRollback(second); err != nil {
		t.Fatal(err)
	}
	got, ok := db.GetFirewallRollback()
	if !ok {
		t.Fatal("expected pending rollback")
	}
	if got.AppliedBy != "second" {
		t.Errorf("expected overwrite to keep second, got AppliedBy=%q", got.AppliedBy)
	}
}
