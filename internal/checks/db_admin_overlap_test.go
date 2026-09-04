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

func TestCheckAdminEmailOverlap_TrustedEmailSilencesOverlap(t *testing.T) {
	withFreshStore(t)
	now := time.Now()
	db := store.Global()
	_ = db.RecordAdminEmail("Admin@Dev.Example.test", "alice", "alice_wp", now)
	_ = db.RecordAdminEmail("admin@dev.example.test", "bob", "bob_wp", now)
	_ = db.RecordAdminEmail("admin@dev.example.test", "carol", "carol_wp", now)

	cfg := &config.Config{}
	cfg.Detection.AdminOverlapMinAccounts = 2
	cfg.Detection.AdminOverlapTrustedEmails = []string{"admin@dev.example.test"}

	findings := CheckAdminEmailOverlap(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Fatalf("trusted admin email must silence overlap, got %v", findings)
	}
}

func TestCheckAdminEmailOverlap_TrustedDomainSilencesOverlap(t *testing.T) {
	withFreshStore(t)
	now := time.Now()
	db := store.Global()
	_ = db.RecordAdminEmail("ops@dev.example.test", "alice", "alice_wp", now)
	_ = db.RecordAdminEmail("ops@dev.example.test", "bob", "bob_wp", now)

	cfg := &config.Config{}
	cfg.Detection.AdminOverlapMinAccounts = 2
	cfg.Detection.AdminOverlapTrustedDomains = []string{"DEV.EXAMPLE.TEST"}

	findings := CheckAdminEmailOverlap(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Fatalf("trusted admin domain must silence overlap, got %v", findings)
	}
}

func TestCheckAdminEmailOverlap_TrustedDomainDoesNotSilenceDifferentDomain(t *testing.T) {
	withFreshStore(t)
	now := time.Now()
	db := store.Global()
	_ = db.RecordAdminEmail("ops@contractor.example.test", "alice", "alice_wp", now)
	_ = db.RecordAdminEmail("ops@contractor.example.test", "bob", "bob_wp", now)

	cfg := &config.Config{}
	cfg.Detection.AdminOverlapMinAccounts = 2
	cfg.Detection.AdminOverlapTrustedDomains = []string{"dev.example.test"}

	findings := CheckAdminEmailOverlap(context.Background(), cfg, nil)
	if len(findings) != 1 {
		t.Fatalf("different domain must still alert, got %v", findings)
	}
}

func TestBuildAdminOverlapFindings_StableKeyAcrossScans(t *testing.T) {
	// Every scan refreshes the LastSeen stamp of each admin observation.
	// The overlap itself is unchanged, so the finding has to keep one
	// identity across scans; otherwise each run stores another copy and
	// the operator sees one row per scan instead of one per overlap.
	overlaps := func(seen time.Time) map[string][]store.AdminEmailEntry {
		return map[string][]store.AdminEmailEntry{
			"contractor@example.test": {
				{Account: "alice", Schema: "alice_wp", LastSeen: seen},
				{Account: "bob", Schema: "bob_wp", LastSeen: seen},
			},
		}
	}
	first := buildAdminOverlapFindings(overlaps(time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)))
	second := buildAdminOverlapFindings(overlaps(time.Date(2026, 9, 5, 11, 30, 0, 0, time.UTC)))
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("got %d and %d findings, want 1 each", len(first), len(second))
	}
	if first[0].Key() != second[0].Key() {
		t.Errorf("key changed across scans:\n first  = %q\n second = %q", first[0].Key(), second[0].Key())
	}
	if first[0].Fingerprint() != second[0].Fingerprint() {
		t.Errorf("fingerprint changed across scans: %q vs %q", first[0].Fingerprint(), second[0].Fingerprint())
	}
}

func TestBuildAdminOverlapFindings_KeyTracksAccountMembership(t *testing.T) {
	// A third account joining the overlap is a new fact, not the same
	// one seen again, so the identity must change with the account set.
	seen := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	two := buildAdminOverlapFindings(map[string][]store.AdminEmailEntry{
		"contractor@example.test": {
			{Account: "alice", Schema: "alice_wp", LastSeen: seen},
			{Account: "bob", Schema: "bob_wp", LastSeen: seen},
		},
	})
	three := buildAdminOverlapFindings(map[string][]store.AdminEmailEntry{
		"contractor@example.test": {
			{Account: "alice", Schema: "alice_wp", LastSeen: seen},
			{Account: "bob", Schema: "bob_wp", LastSeen: seen},
			{Account: "carol", Schema: "carol_wp", LastSeen: seen},
		},
	})
	if two[0].Key() == three[0].Key() {
		t.Errorf("key ignored a new account joining the overlap: %q", two[0].Key())
	}
}
