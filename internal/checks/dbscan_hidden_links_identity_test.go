package checks

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

func hiddenLinkIdentityRows(style string, count int) []hiddenLinkRow {
	markup := `<div style="` + style + `"><a href="https://one.example/">one</a><a href="https://two.test/">two</a></div>`
	rows := make([]hiddenLinkRow, count)
	for i := range rows {
		rows[i] = hiddenLinkRow{label: fmt.Sprintf("post %d", i+1), hit: hiddenOffsiteLinks(markup, "shop.example")}
	}
	return rows
}

func oneHiddenLinkFinding(t *testing.T, user string, creds wpDBCreds, prefix string, rows []hiddenLinkRow) alert.Finding {
	t.Helper()
	findings := buildHiddenLinkFindings(user, creds, prefix, rows)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one hidden-link finding", findings)
	}
	return findings[0]
}

func TestHiddenLinkEscalationSurvivesAcknowledgement(t *testing.T) {
	creds := wpDBCreds{dbHost: "localhost", dbName: "site"}
	warning := oneHiddenLinkFinding(t, "alice", creds, "wp_", hiddenLinkIdentityRows("display:none", 1))
	high := oneHiddenLinkFinding(t, "alice", creds, "wp_", hiddenLinkIdentityRows("left:-9999px", 1))
	if warning.Severity != alert.Warning || high.Severity != alert.High {
		t.Fatalf("parser grades = %s/%s, want Warning/High", warning.Severity, high.Severity)
	}
	for _, acknowledgement := range []string{"baseline", "dismissal"} {
		t.Run(acknowledgement, func(t *testing.T) {
			s, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			if acknowledgement == "baseline" {
				s.SetBaseline([]alert.Finding{warning})
			} else {
				s.Update([]alert.Finding{warning})
				s.DismissFinding(warning.Key())
			}
			if got := s.FilterNew([]alert.Finding{warning}); len(got) != 0 {
				t.Fatalf("acknowledged Warning re-alerted: %+v", got)
			}
			got := s.FilterNew([]alert.Finding{high})
			if len(got) != 1 || got[0].Severity != alert.High {
				t.Fatalf("escalation = %+v, want one new High", got)
			}
			s.Update(got)
			if got := s.FilterNew([]alert.Finding{high}); len(got) != 0 {
				t.Fatalf("unchanged High re-alerted: %+v", got)
			}
			churn := oneHiddenLinkFinding(t, "alice", creds, "wp_", hiddenLinkIdentityRows("top:-12000px", 15))
			if got := s.FilterNew([]alert.Finding{churn}); len(got) != 0 {
				t.Fatalf("same evidence in more rows re-alerted: %+v", got)
			}
		})
	}
	if warning.Key() == high.Key() || warning.Fingerprint() == high.Fingerprint() {
		t.Fatal("stronger concealment has the same identity as the Warning")
	}
}

func TestHiddenLinkIdentityIgnoresRowCountAndOrder(t *testing.T) {
	creds := wpDBCreds{dbHost: "localhost", dbName: "site"}
	for _, style := range []string{"display:none", "left:-9999px"} {
		first := oneHiddenLinkFinding(t, "alice", creds, "wp_", hiddenLinkIdentityRows(style, 1))
		rows := hiddenLinkIdentityRows(style, maxHiddenLinkRowsShown+3)
		slices.Reverse(rows)
		changed := oneHiddenLinkFinding(t, "alice", creds, "wp_", rows)
		if first.Message == changed.Message || first.Details == changed.Details {
			t.Fatal("fixture did not change counts and displayed row sample")
		}
		if first.Key() != changed.Key() || first.Fingerprint() != changed.Fingerprint() {
			t.Fatalf("row growth changed identity for %s", style)
		}
		slices.Reverse(rows)
		reordered := oneHiddenLinkFinding(t, "alice", creds, "wp_", rows)
		if reordered.Key() != changed.Key() || reordered.Fingerprint() != changed.Fingerprint() {
			t.Fatalf("row ordering changed identity for %s", style)
		}
	}
}

func TestHiddenLinkIdentityIncludesAllDestinations(t *testing.T) {
	var links strings.Builder
	for i := range maxHiddenLinkHostsShown + 2 {
		fmt.Fprintf(&links, `<a href="https://host%02d.example/">x</a>`, i)
	}
	markup := `<div style="left:-9999px">` + links.String() + `</div>`
	creds := wpDBCreds{dbHost: "localhost", dbName: "site"}
	first := oneHiddenLinkFinding(t, "alice", creds, "wp_", []hiddenLinkRow{{label: "post 1", hit: hiddenOffsiteLinks(markup, "shop.test")}})
	changedMarkup := strings.ReplaceAll(markup, fmt.Sprintf("host%02d.example", maxHiddenLinkHostsShown+1), "z-last.example")
	changed := oneHiddenLinkFinding(t, "alice", creds, "wp_", []hiddenLinkRow{{label: "post 1", hit: hiddenOffsiteLinks(changedMarkup, "shop.test")}})
	if first.Details != changed.Details {
		t.Fatal("fixture must change a destination beyond the displayed sample")
	}
	if first.Key() == changed.Key() || first.Fingerprint() == changed.Fingerprint() {
		t.Fatal("changed destination beyond the display limit retained its identity")
	}
}

func TestHiddenLinkIdentitySeparatesInstallations(t *testing.T) {
	creds := wpDBCreds{dbHost: "localhost", dbName: "site"}
	rows := hiddenLinkIdentityRows("left:-9999px", 1)
	first := oneHiddenLinkFinding(t, "alice", creds, "wp_", rows)
	for _, tc := range []struct {
		name, user, host, database, prefix string
	}{
		{"account", "bob", "localhost", "site", "wp_"},
		{"host", "alice", "db.internal", "site", "wp_"},
		{"database", "alice", "localhost", "other", "wp_"},
		{"prefix", "alice", "localhost", "site", "other_"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := oneHiddenLinkFinding(t, tc.user, wpDBCreds{dbHost: tc.host, dbName: tc.database}, tc.prefix, rows)
			if first.Key() == other.Key() || first.Fingerprint() == other.Fingerprint() {
				t.Fatal("different installation shares the finding identity")
			}
		})
	}
}
