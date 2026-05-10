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
