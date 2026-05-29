package incident

import (
	"strconv"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func incForGroup(id string, kind Kind, status Status, sev alert.Severity, ip, account, domain, mailbox string, updated time.Time) Incident {
	return Incident{
		ID: id, Kind: kind, Status: status, Severity: sev,
		Account: account, Domain: domain, Mailbox: mailbox,
		CorrelationKey: &Key{
			Account: account, Domain: domain, Mailbox: mailbox, RemoteIP: ip,
		},
		CreatedAt: updated.Add(-30 * time.Minute),
		UpdatedAt: updated,
	}
}

func TestBuildGroupsBucketByIPWhenPresent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := []Incident{
		incForGroup("inc_a", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.1", "", "", "u1", now),
		incForGroup("inc_b", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.1", "", "", "u2", now.Add(time.Minute)),
		incForGroup("inc_c", KindMailboxTakeover, StatusOpen, alert.Critical, "192.0.2.2", "", "", "u3", now.Add(2*time.Minute)),
	}
	resp := BuildGroups(in, GroupFilter{})
	if resp.TotalGroups != 2 {
		t.Fatalf("TotalGroups = %d, want 2 (one per IP)", resp.TotalGroups)
	}
	first := resp.Groups[0]
	if first.SourceKind != "ip" || first.Source != "192.0.2.1" {
		t.Errorf("first group source = (%s,%s), want (ip,192.0.2.1)", first.SourceKind, first.Source)
	}
	if first.IncidentCount != 2 {
		t.Errorf("first group incident_count = %d, want 2", first.IncidentCount)
	}
}

func TestBuildGroupsBucketByTimelineRemoteIPWhenCorrelationKeyOmitsIP(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := []Incident{
		{
			ID:        "inc_a",
			Kind:      KindMailboxTakeover,
			Status:    StatusOpen,
			Severity:  alert.High,
			Mailbox:   "u1@example.com",
			CreatedAt: now,
			UpdatedAt: now,
			CorrelationKey: &Key{
				Mailbox: "u1@example.com",
			},
			Timeline: []IncidentEvent{{RemoteIP: "192.0.2.1"}},
		},
		{
			ID:        "inc_b",
			Kind:      KindMailboxTakeover,
			Status:    StatusOpen,
			Severity:  alert.High,
			Mailbox:   "u2@example.com",
			CreatedAt: now.Add(time.Minute),
			UpdatedAt: now.Add(time.Minute),
			CorrelationKey: &Key{
				Mailbox: "u2@example.com",
			},
			Timeline: []IncidentEvent{{RemoteIP: "192.0.2.1"}},
		},
	}

	resp := BuildGroups(in, GroupFilter{})
	if resp.TotalGroups != 1 {
		t.Fatalf("TotalGroups = %d, want 1 attacker-IP group: %+v", resp.TotalGroups, resp.Groups)
	}
	if resp.Groups[0].SourceKind != "ip" || resp.Groups[0].Source != "192.0.2.1" {
		t.Fatalf("group source = (%s,%s), want (ip,192.0.2.1)", resp.Groups[0].SourceKind, resp.Groups[0].Source)
	}
	if resp.Groups[0].IncidentCount != 2 {
		t.Fatalf("IncidentCount = %d, want 2", resp.Groups[0].IncidentCount)
	}
}

func TestBuildGroupsBucketByAccountFallback(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := []Incident{
		incForGroup("inc_a", KindWebAccountCompromise, StatusOpen, alert.High, "", "alice", "", "", now),
		incForGroup("inc_b", KindWebAccountCompromise, StatusOpen, alert.High, "", "alice", "", "", now.Add(time.Minute)),
	}
	resp := BuildGroups(in, GroupFilter{})
	if len(resp.Groups) != 1 || resp.Groups[0].SourceKind != "account" || resp.Groups[0].Source != "alice" {
		t.Fatalf("expected one account-keyed group, got %+v", resp.Groups)
	}
	if resp.Groups[0].IncidentCount != 2 {
		t.Errorf("incident_count = %d, want 2", resp.Groups[0].IncidentCount)
	}
}

func TestBuildGroupsBucketByHostKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := []Incident{
		{
			ID:             "inc_host",
			Kind:           KindHostIntegrityRisk,
			Status:         StatusOpen,
			Severity:       alert.High,
			CorrelationKey: &Key{Host: "host"},
			CreatedAt:      now,
			UpdatedAt:      now,
		},
	}
	resp := BuildGroups(in, GroupFilter{})
	if len(resp.Groups) != 1 || resp.Groups[0].SourceKind != "host" || resp.Groups[0].Source != "host" {
		t.Fatalf("expected one host-keyed group, got %+v", resp.Groups)
	}
}

func TestBuildGroupsKeepsHostTakeoverAsOwnKind(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := []Incident{
		{
			ID:             "inc_integrity",
			Kind:           KindHostIntegrityRisk,
			Status:         StatusOpen,
			Severity:       alert.High,
			CorrelationKey: &Key{Host: "host"},
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		{
			ID:             "inc_takeover",
			Kind:           KindHostTakeover,
			Status:         StatusOpen,
			Severity:       alert.Critical,
			CorrelationKey: &Key{Host: "host"},
			CreatedAt:      now,
			UpdatedAt:      now.Add(time.Minute),
		},
	}
	resp := BuildGroups(in, GroupFilter{})
	if resp.TotalGroups != 2 {
		t.Fatalf("TotalGroups = %d, want separate host-integrity and takeover groups: %+v", resp.TotalGroups, resp.Groups)
	}
	for _, group := range resp.Groups {
		if group.SourceKind != "host" || group.Source != "host" {
			t.Fatalf("host group source = (%s,%s), want (host,host)", group.SourceKind, group.Source)
		}
	}
}

func TestBuildGroupsSortsByCountThenSeverityThenLastSeen(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := []Incident{
		// Single-incident bucket but CRITICAL.
		incForGroup("crit", KindMailboxTakeover, StatusOpen, alert.Critical, "192.0.2.1", "", "", "u1", now),
		// Three incidents bucket, HIGH severity.
		incForGroup("a", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.2", "", "", "x", now),
		incForGroup("b", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.2", "", "", "y", now.Add(time.Minute)),
		incForGroup("c", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.2", "", "", "z", now.Add(2*time.Minute)),
	}
	resp := BuildGroups(in, GroupFilter{})
	if resp.Groups[0].Source != "192.0.2.2" || resp.Groups[0].IncidentCount != 3 {
		t.Errorf("expected the 3-count HIGH bucket first, got %+v", resp.Groups[0])
	}
	if resp.Groups[1].SeverityMax != alert.Critical {
		t.Errorf("expected CRITICAL bucket second, got severity=%s", resp.Groups[1].SeverityMax)
	}
}

func TestBuildGroupsScanCapHonored(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var in []Incident
	for i := 0; i < IncidentGroupsScanCap+50; i++ {
		in = append(in, incForGroup("inc"+strconv.Itoa(i), KindMailboxTakeover, StatusOpen, alert.High, "", "u"+strconv.Itoa(i), "", "", now))
	}
	resp := BuildGroups(in, GroupFilter{})
	if !resp.Truncated {
		t.Fatal("expected truncated=true past scan cap")
	}
	if resp.ScannedIncidents != IncidentGroupsScanCap {
		t.Errorf("scanned = %d, want cap %d", resp.ScannedIncidents, IncidentGroupsScanCap)
	}
}

func TestBuildGroupsScanCapAppliesAfterFilters(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := make([]Incident, 0, IncidentGroupsScanCap+2)
	for i := 0; i < IncidentGroupsScanCap+1; i++ {
		in = append(in, incForGroup("done"+strconv.Itoa(i), KindMailboxTakeover, StatusResolved, alert.High, "", "u"+strconv.Itoa(i), "", "", now.Add(time.Duration(i)*time.Second)))
	}
	in = append(in, incForGroup("active", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.99", "", "", "active", now.Add(time.Hour)))

	resp := BuildGroups(in, GroupFilter{StatusSet: []Status{StatusOpen, StatusContained}})
	if resp.TotalGroups != 1 {
		t.Fatalf("TotalGroups = %d, want 1 active group after skipping resolved rows: %+v", resp.TotalGroups, resp.Groups)
	}
	if resp.Groups[0].Source != "192.0.2.99" {
		t.Fatalf("active group source = %q, want 192.0.2.99", resp.Groups[0].Source)
	}
	if resp.ScannedIncidents != 1 {
		t.Fatalf("ScannedIncidents = %d, want 1 matching active incident", resp.ScannedIncidents)
	}
	if resp.Truncated {
		t.Fatal("Truncated = true, want false because matching active set is below cap")
	}
}

func TestBuildGroupsHonorsStatusFilter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := []Incident{
		incForGroup("open", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.1", "", "", "x", now),
		incForGroup("done", KindMailboxTakeover, StatusResolved, alert.High, "192.0.2.1", "", "", "y", now),
	}
	resp := BuildGroups(in, GroupFilter{StatusSet: []Status{StatusOpen, StatusContained}})
	if resp.TotalGroups != 1 {
		t.Fatalf("status filter should hide resolved bucket, got %d groups", resp.TotalGroups)
	}
	if resp.Groups[0].IncidentCount != 1 {
		t.Errorf("incident_count after status filter = %d, want 1", resp.Groups[0].IncidentCount)
	}
}

func TestBuildGroupsKindFilter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := []Incident{
		incForGroup("a", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.1", "", "", "x", now),
		incForGroup("b", KindWebAccountCompromise, StatusOpen, alert.High, "", "alice", "", "", now),
	}
	resp := BuildGroups(in, GroupFilter{Kind: KindMailboxTakeover})
	if resp.TotalGroups != 1 || resp.Groups[0].Kind != KindMailboxTakeover {
		t.Fatalf("kind filter dropped wrong rows: %+v", resp.Groups)
	}
}

func TestBuildGroupsSampleIDsAreNewestFirst(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := []Incident{
		incForGroup("oldest", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.1", "", "", "x", now),
		incForGroup("middle", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.1", "", "", "y", now.Add(time.Minute)),
		incForGroup("newest", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.1", "", "", "z", now.Add(2*time.Minute)),
		incForGroup("extra", KindMailboxTakeover, StatusOpen, alert.High, "192.0.2.1", "", "", "w", now.Add(3*time.Minute)),
	}
	resp := BuildGroups(in, GroupFilter{})
	if len(resp.Groups[0].SampleIDs) != 3 {
		t.Fatalf("sample_ids capped at 3, got %d", len(resp.Groups[0].SampleIDs))
	}
	if resp.Groups[0].SampleIDs[0] != "extra" {
		t.Errorf("sample_ids[0] = %q, want newest (extra)", resp.Groups[0].SampleIDs[0])
	}
}

func TestBuildGroupsMaxGroupsCap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var in []Incident
	for i := 0; i < 5; i++ {
		in = append(in, incForGroup("inc"+strconv.Itoa(i), KindMailboxTakeover, StatusOpen, alert.High, "192.0.2."+strconv.Itoa(i+1), "", "", "x", now))
	}
	resp := BuildGroups(in, GroupFilter{MaxGroups: 2})
	if len(resp.Groups) != 2 {
		t.Errorf("len(Groups) = %d, want 2 (cap)", len(resp.Groups))
	}
	if resp.TotalGroups != 5 {
		t.Errorf("TotalGroups = %d, want 5 (pre-cap)", resp.TotalGroups)
	}
}

func TestBuildGroupsOffsetPaginates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var in []Incident
	for i := 0; i < 5; i++ {
		// Distinct incident counts per IP so sort order is deterministic:
		// IP .1 -> 5 incidents, .2 -> 4, .3 -> 3, .4 -> 2, .5 -> 1.
		count := 5 - i
		for j := 0; j < count; j++ {
			id := "ip" + strconv.Itoa(i+1) + "-" + strconv.Itoa(j)
			in = append(in, incForGroup(id, KindMailboxTakeover, StatusOpen, alert.High, "192.0.2."+strconv.Itoa(i+1), "", "", "x", now))
		}
	}

	first := BuildGroups(in, GroupFilter{Offset: 0, MaxGroups: 2})
	if first.TotalGroups != 5 {
		t.Fatalf("page 1 TotalGroups = %d, want 5", first.TotalGroups)
	}
	if len(first.Groups) != 2 || first.Groups[0].Source != "192.0.2.1" || first.Groups[1].Source != "192.0.2.2" {
		t.Fatalf("page 1 sources = %+v, want [.1 .2]", first.Groups)
	}

	second := BuildGroups(in, GroupFilter{Offset: 2, MaxGroups: 2})
	if second.TotalGroups != 5 {
		t.Fatalf("page 2 TotalGroups = %d, want 5", second.TotalGroups)
	}
	if len(second.Groups) != 2 || second.Groups[0].Source != "192.0.2.3" || second.Groups[1].Source != "192.0.2.4" {
		t.Fatalf("page 2 sources = %+v, want [.3 .4]", second.Groups)
	}

	third := BuildGroups(in, GroupFilter{Offset: 4, MaxGroups: 2})
	if len(third.Groups) != 1 || third.Groups[0].Source != "192.0.2.5" {
		t.Fatalf("page 3 sources = %+v, want [.5]", third.Groups)
	}

	past := BuildGroups(in, GroupFilter{Offset: 99, MaxGroups: 2})
	if len(past.Groups) != 0 {
		t.Fatalf("offset past end returned %d groups, want 0", len(past.Groups))
	}
	if past.TotalGroups != 5 {
		t.Fatalf("past TotalGroups = %d, want 5 (offset does not change total)", past.TotalGroups)
	}
}
