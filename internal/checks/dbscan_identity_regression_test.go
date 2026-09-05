package checks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

// Baselining an inactive snippet or a small orphan group must not suppress
// the alert when that same row starts executing or becomes a content farm.
func TestDBContentIdentityReportsEscalation(t *testing.T) {
	for _, tc := range []struct {
		name string
		find func(*testing.T, bool) alert.Finding
	}{
		{"stored code", func(t *testing.T, active bool) alert.Finding {
			status := "trash"
			if active {
				status = "publish"
			}
			got := storedCodeFindings(t, [][3]string{{"4052", status, xorSnippet}})
			if len(got) != 1 {
				t.Fatalf("stored-code findings = %d, want 1", len(got))
			}
			return got[0]
		}},
		{"stored cloak", func(t *testing.T, active bool) alert.Finding {
			status := "draft"
			if active {
				status = "publish"
			}
			code := []byte(`<?php if (stripos($_SERVER['HTTP_USER_AGENT'],'googlebot')) { define('DONOTCACHEPAGE', true); }`)
			got := storedCloakFinding("alice", wpDBCreds{dbName: "wp"}, "wp_", storedCodeRow{id: "4052", status: status, code: code})
			if got == nil {
				t.Fatal("expected a stored-cloak finding")
			}
			return *got
		}},
		{"phantom author", func(t *testing.T, active bool) alert.Finding {
			count := phantomAuthorFarmSize - 1
			if active {
				count++
			}
			withMockPhantomAuthorRows(t, []string{fmt.Sprintf("42\t%d", count)})
			got := checkWPPhantomAuthors("alice", wpDBCreds{dbName: "wp"}, "wp_", "wp_", 1)
			if len(got) != 1 {
				t.Fatalf("phantom-author findings = %d, want 1", len(got))
			}
			return got[0]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := tc.find(t, false), tc.find(t, true)
			if before.Severity >= after.Severity {
				t.Fatal("fixture did not escalate the condition")
			}
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := st.Close(); err != nil {
					t.Error(err)
				}
			})
			st.SetBaseline([]alert.Finding{before})
			if got := st.FilterNew([]alert.Finding{before}); len(got) != 0 {
				t.Fatal("baseline did not suppress the original finding")
			}
			if got := st.FilterNew([]alert.Finding{after}); len(got) != 1 {
				t.Error("baseline suppressed the escalated finding")
			}
			if before.Key() == after.Key() {
				t.Error("escalation reused the key of a dismissible lower-risk condition")
			}
		})
	}
}

// Two accounts can point WordPress at the same database. Their findings must
// remain separately attributable and dismissible after scan deduplication.
func TestDBContentIdentitySeparatesAccounts(t *testing.T) {
	taxonomyRows(t, []string{"48\tpost_tag\t1\thttps://casino.example"})
	creds := wpDBCreds{dbHost: "localhost", dbName: "shared"}
	alice := checkWPSpamTaxonomy("alice", creds, "wp_")
	bob := checkWPSpamTaxonomy("bob", creds, "wp_")
	if len(alice) != 1 || len(bob) != 1 {
		t.Fatalf("got %d and %d findings, want 1 each", len(alice), len(bob))
	}
	if got := alert.Deduplicate(append(alice, bob...)); len(got) != 2 {
		t.Error("deduplication lost one account's finding")
	}
	if alice[0].Fingerprint() == bob[0].Fingerprint() {
		t.Error("accounts share an alert fingerprint")
	}
}

func TestDBContentIdentitySeparatesSiteURLPoisonReasons(t *testing.T) {
	previous := runMySQLQuery
	t.Cleanup(func() { runMySQLQuery = previous })
	value := "https://example.com/" + strings.Repeat("a", 200)
	suffix := "?payload"
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "'siteurl', 'home', 'admin_email'") {
			return []string{"siteurl\t" + value + suffix}
		}
		return nil
	}
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp"}
	query := checkWPOptions("alice", creds, "wp_")
	suffix = "#payload"
	fragment := checkWPOptions("alice", creds, "wp_")
	if len(query) != 1 || len(fragment) != 1 {
		t.Fatalf("got %d and %d findings, want 1 each", len(query), len(fragment))
	}
	if query[0].Message == fragment[0].Message || query[0].Details != fragment[0].Details {
		t.Fatal("fixture must distinguish the poison reasons only in Message")
	}
	if query[0].Key() == fragment[0].Key() {
		t.Error("different poison reasons share one dismissible identity")
	}
}

func TestDBContentIdentityIgnoresPhantomAuthorCountWithinTier(t *testing.T) {
	for _, count := range []int{1, phantomAuthorFarmSize} {
		find := func(n int) alert.Finding {
			withMockPhantomAuthorRows(t, []string{fmt.Sprintf("42\t%d", n)})
			got := checkWPPhantomAuthors("alice", wpDBCreds{dbName: "wp"}, "wp_", "wp_", 1)
			if len(got) != 1 {
				t.Fatalf("findings = %d, want 1", len(got))
			}
			return got[0]
		}
		before, after := find(count), find(count+1)
		if before.Message == after.Message {
			t.Fatal("fixture did not change the count")
		}
		if before.Key() != after.Key() || before.Fingerprint() != after.Fingerprint() {
			t.Errorf("count change within tier %v minted a new identity", before.Severity)
		}
	}
}
