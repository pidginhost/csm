package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestMailIPEntry_FailTargets_AggregatesSortsAndCountsAccountless(t *testing.T) {
	now := time.Date(2026, 6, 24, 1, 0, 0, 0, time.UTC)
	e := &mailIPEntry{
		failedAccounts: map[string][]time.Time{
			"alice@example.com": {now, now, now}, // 3
			"bob@example.com":   {now},           // 1
		},
		// 6 total failures: 4 named + 2 accountless (lines with no user=).
		times: []time.Time{now, now, now, now, now, now},
	}
	targets, accountless := e.failTargets()
	if accountless != 2 {
		t.Fatalf("accountless = %d, want 2", accountless)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if targets[0].Account != "alice@example.com" || targets[0].Count != 3 {
		t.Errorf("targets[0] = %+v, want {alice@example.com 3}", targets[0])
	}
	if targets[1].Account != "bob@example.com" || targets[1].Count != 1 {
		t.Errorf("targets[1] = %+v, want {bob@example.com 1}", targets[1])
	}
}

func TestMailIPEntry_FailTargets_TieBreaksByAccountName(t *testing.T) {
	now := time.Date(2026, 6, 24, 1, 0, 0, 0, time.UTC)
	e := &mailIPEntry{
		failedAccounts: map[string][]time.Time{
			"zed@example.com": {now},
			"amy@example.com": {now},
		},
		times: []time.Time{now, now},
	}
	targets, accountless := e.failTargets()
	if accountless != 0 {
		t.Fatalf("accountless = %d, want 0", accountless)
	}
	if len(targets) != 2 || targets[0].Account != "amy@example.com" || targets[1].Account != "zed@example.com" {
		t.Fatalf("equal-count targets must sort by account name asc, got %+v", targets)
	}
}

func TestMailIPEntry_FailTargets_AllAccountless(t *testing.T) {
	now := time.Date(2026, 6, 24, 1, 0, 0, 0, time.UTC)
	e := &mailIPEntry{times: []time.Time{now, now, now}}
	targets, accountless := e.failTargets()
	if len(targets) != 0 {
		t.Fatalf("targets = %+v, want none", targets)
	}
	if accountless != 3 {
		t.Fatalf("accountless = %d, want 3", accountless)
	}
}

func TestFormatMailFailTargets(t *testing.T) {
	cases := []struct {
		name        string
		targets     []mailFailTarget
		accountless int
		want        string
	}{
		{"no information", nil, 0, ""},
		{"single named", []mailFailTarget{{"a@x.ro", 3}}, 0, "Targets: a@x.ro (3)"},
		{"named plus accountless", []mailFailTarget{{"a@x.ro", 3}}, 2, "Targets: a@x.ro (3); 2 with no mailbox"},
		{"two named", []mailFailTarget{{"a@x.ro", 3}, {"b@y.ro", 1}}, 0, "Targets: a@x.ro (3), b@y.ro (1)"},
		{"only accountless", nil, 4, "Targets: 4 with no mailbox"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatMailFailTargets(tc.targets, tc.accountless, maxMailTargetsListed); got != tc.want {
				t.Errorf("formatMailFailTargets() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatMailFailTargets_CapsListWithRemainder(t *testing.T) {
	targets := []mailFailTarget{
		{"a@x", 7}, {"b@x", 6}, {"c@x", 5}, {"d@x", 4},
		{"e@x", 3}, {"f@x", 2}, {"g@x", 1},
	}
	got := formatMailFailTargets(targets, 0, 5)
	want := "Targets: a@x (7), b@x (6), c@x (5), d@x (4), e@x (3) (+2 more)"
	if got != want {
		t.Fatalf("formatMailFailTargets() = %q, want %q", got, want)
	}
}

func TestMailAuthTracker_BruteForceFindingNamesTargets(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 24, 1, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.9"
	// perIPThreshold is 5; fire the finding with a mixed target set.
	accounts := []string{
		"victim@example.com", "victim@example.com", "victim@example.com",
		"other@example.com", "",
	}
	var last []alert.Finding
	for _, a := range accounts {
		last = tr.Record(ip, a)
	}
	var f *alert.Finding
	for i := range last {
		if last[i].Check == "mail_bruteforce" {
			f = &last[i]
			break
		}
	}
	if f == nil {
		t.Fatalf("no mail_bruteforce finding in %v", last)
	}
	if !strings.Contains(f.Details, "victim@example.com (3)") {
		t.Errorf("Details must name the dominant target mailbox: %q", f.Details)
	}
	if !strings.Contains(f.Details, "other@example.com (1)") {
		t.Errorf("Details must name secondary target mailbox: %q", f.Details)
	}
	if !strings.Contains(f.Details, "1 with no mailbox") {
		t.Errorf("Details must report accountless failures: %q", f.Details)
	}
}

func TestMailAuthTracker_SuspectedFindingNamesTargets(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.11"
	acct := "comenzi@example.ro"
	establishGoodSource(tr, clock, ip, acct)
	var suspected *alert.Finding
	for i := 0; i < 6 && suspected == nil; i++ {
		for _, f := range tr.Record(ip, acct) {
			if f.Check == "mail_bruteforce_suspected" {
				ff := f
				suspected = &ff
				break
			}
		}
		clock.advance(30 * time.Second)
	}
	if suspected == nil {
		t.Fatalf("expected mail_bruteforce_suspected advisory")
	}
	if !strings.Contains(suspected.Details, acct) {
		t.Errorf("suspected advisory Details must name the fat-fingered mailbox %q: %q", acct, suspected.Details)
	}
}
