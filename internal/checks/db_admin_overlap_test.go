package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// withFreshStore replaces store.Global() with a fresh bbolt DB rooted
// at t.TempDir() and restores the previous global on cleanup.
func withFreshStore(t *testing.T) {
	t.Helper()
	old := store.Global()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("opening test store: %v", err)
	}
	store.SetGlobal(db)
	t.Cleanup(func() {
		_ = db.Close()
		store.SetGlobal(old)
	})
}

func TestBuildAdminOverlapFindings_SingleEmailTwoAccounts(t *testing.T) {
	now := time.Now()
	overlaps := map[string][]store.AdminEmailEntry{
		"contractor@example.test": {
			{Account: "alice", Schema: "alice_wp", LastSeen: now},
			{Account: "bob", Schema: "bob_wp", LastSeen: now},
		},
	}
	findings := buildAdminOverlapFindings(overlaps)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Check != "admin_cross_account_overlap" {
		t.Errorf("check = %q, want admin_cross_account_overlap", f.Check)
	}
	if !strings.Contains(f.Message, "alice") || !strings.Contains(f.Message, "bob") {
		t.Errorf("message missing account list: %q", f.Message)
	}
	if !strings.Contains(f.Details, "contractor@example.test") {
		t.Errorf("details missing email: %q", f.Details)
	}
}

func TestBuildAdminOverlapFindings_DeterministicAccountOrder(t *testing.T) {
	now := time.Now()
	overlaps := map[string][]store.AdminEmailEntry{
		"shared@example.test": {
			{Account: "zulu", Schema: "zulu_wp", LastSeen: now},
			{Account: "alpha", Schema: "alpha_wp", LastSeen: now},
			{Account: "mike", Schema: "mike_wp", LastSeen: now},
		},
	}
	findings := buildAdminOverlapFindings(overlaps)
	if len(findings) != 1 {
		t.Fatalf("got %d findings", len(findings))
	}
	// Sorted alphabetically -> alpha, mike, zulu.
	want := "alpha, mike, zulu"
	if !strings.Contains(findings[0].Message, want) {
		t.Errorf("account order not deterministic; message=%q does not contain %q", findings[0].Message, want)
	}
}

func TestBuildAdminOverlapFindings_DedupsAccountInMessageEvenWhenTwoSchemasShareAccount(t *testing.T) {
	// A single cPanel account may host multiple WordPress installs
	// (primary domain + add-on domains). The same admin email recorded
	// against the same account but two schemas counts as one account in
	// the overlap message -- otherwise a single-account multi-schema
	// install would falsely look like cross-account overlap.
	now := time.Now()
	overlaps := map[string][]store.AdminEmailEntry{
		"owner@example.test": {
			{Account: "alice", Schema: "alice_wp", LastSeen: now},
			{Account: "alice", Schema: "alice_blog", LastSeen: now},
		},
	}
	findings := buildAdminOverlapFindings(overlaps)
	if len(findings) != 1 {
		t.Fatalf("got %d findings", len(findings))
	}
	if !strings.Contains(findings[0].Message, "1 accounts") {
		t.Errorf("expected single-account count, message=%q", findings[0].Message)
	}
}

func TestCheckAdminEmailOverlap_NoStoreReturnsNil(t *testing.T) {
	// store.Global() is nil at this point unless something else set it.
	old := store.Global()
	store.SetGlobal(nil)
	defer store.SetGlobal(old)

	got := CheckAdminEmailOverlap(context.Background(), &config.Config{}, nil)
	if got != nil {
		t.Errorf("expected nil findings when store is unavailable, got %d", len(got))
	}
}

func TestCheckAdminEmailOverlap_EmitsFindingWhenOverlapPreExistsInStore(t *testing.T) {
	withFreshStore(t)

	// Pre-seed two recordings for the same email on different accounts.
	// The integration path (parseWPConfig + MySQL) is mocked out by the
	// absence of /home/*/public_html/wp-config.php on the test host; the
	// emit-overlap branch is what we exercise here.
	now := time.Now()
	db := store.Global()
	if err := db.RecordAdminEmail("shared@example.test", "alice", "alice_wp", now); err != nil {
		t.Fatalf("RecordAdminEmail: %v", err)
	}
	if err := db.RecordAdminEmail("shared@example.test", "bob", "bob_wp", now); err != nil {
		t.Fatalf("RecordAdminEmail: %v", err)
	}

	cfg := &config.Config{}
	cfg.Detection.AdminOverlapMinAccounts = 2

	findings := CheckAdminEmailOverlap(context.Background(), cfg, nil)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Check != "admin_cross_account_overlap" {
		t.Errorf("check = %q", findings[0].Check)
	}
	if !strings.Contains(findings[0].Message, "shared@example.test") {
		t.Errorf("message missing email: %q", findings[0].Message)
	}
}

func TestCheckAdminEmailOverlap_ConfigurableThresholdSilencesTwoAccountCase(t *testing.T) {
	withFreshStore(t)
	now := time.Now()
	db := store.Global()
	_ = db.RecordAdminEmail("shared@example.test", "alice", "alice_wp", now)
	_ = db.RecordAdminEmail("shared@example.test", "bob", "bob_wp", now)

	cfg := &config.Config{}
	cfg.Detection.AdminOverlapMinAccounts = 3 // raise above current overlap

	findings := CheckAdminEmailOverlap(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("threshold=3 must silence two-account overlap, got %d", len(findings))
	}
}
