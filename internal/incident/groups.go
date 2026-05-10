package incident

import (
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// IncidentGroupsScanCap is the hard upper bound on incidents inspected
// per BuildGroups call. Bounded scan keeps the grouped view cheap even
// on hosts with tens of thousands of historical incidents.
const IncidentGroupsScanCap = 10000

// Group is one row of the grouped incident view: a (kind, source)
// bucket plus rolled-up counters. Source identifies what the bucket is
// keyed on -- IP for credential-spray patterns, account/domain/mailbox
// when the source IP is unknown.
type Group struct {
	Key            string         `json:"key"`
	Kind           Kind           `json:"kind"`
	SourceKind     string         `json:"source_kind"`
	Source         string         `json:"source"`
	IncidentCount  int            `json:"incident_count"`
	OpenCount      int            `json:"open_count"`
	ContainedCount int            `json:"contained_count"`
	ResolvedCount  int            `json:"resolved_count"`
	DismissedCount int            `json:"dismissed_count"`
	SeverityMax    alert.Severity `json:"-"`
	SeverityLabel  string         `json:"severity_max"`
	FirstSeen      time.Time      `json:"first_seen"`
	LastSeen       time.Time      `json:"last_seen"`
	SampleIDs      []string       `json:"sample_ids"`
}

// GroupsResponse is the wire shape for /api/v1/incidents/groups.
type GroupsResponse struct {
	Groups           []Group `json:"groups"`
	TotalGroups      int     `json:"total_groups"`
	ScannedIncidents int     `json:"scanned_incidents"`
	Truncated        bool    `json:"truncated"`
}

// GroupFilter narrows what BuildGroups buckets. Empty fields mean "no
// filter on that dimension".
type GroupFilter struct {
	// StatusSet, when non-empty, restricts incidents to the listed
	// statuses. Pass {StatusOpen, StatusContained} to surface only
	// active incidents (the default web UI mode).
	StatusSet []Status
	// Kind, when non-empty, restricts incidents to a specific kind.
	Kind Kind
	// MaxGroups caps the returned slice. Zero or negative means "no
	// cap"; the handler still applies a sane upper bound.
	MaxGroups int
}

// BuildGroups buckets the supplied incidents by (kind, source) and
// returns the rolled-up groups sorted by incident_count desc, then
// severity_max desc, then last_seen desc. SampleIDs holds up to three
// of the most recently updated members of each group so the UI can
// drill in without a follow-up call.
//
// `incidents` may be the full correlator snapshot. The function caps
// its scan at IncidentGroupsScanCap; the returned `truncated` flag
// reports whether the cap clipped the input. Callers fed by
// Correlator.Snapshot() get an already-newest-first slice; sort
// stability there means the truncation drops the oldest entries
// first, which is what an operator wants.
func BuildGroups(incidents []Incident, filter GroupFilter) GroupsResponse {
	scanned := len(incidents)
	truncated := false
	if scanned > IncidentGroupsScanCap {
		incidents = incidents[:IncidentGroupsScanCap]
		scanned = IncidentGroupsScanCap
		truncated = true
	}

	statusAllowed := func(Status) bool { return true }
	if len(filter.StatusSet) > 0 {
		set := make(map[Status]struct{}, len(filter.StatusSet))
		for _, s := range filter.StatusSet {
			set[s] = struct{}{}
		}
		statusAllowed = func(s Status) bool {
			_, ok := set[s]
			return ok
		}
	}

	type sampleEntry struct {
		id        string
		updatedAt time.Time
	}
	type aggregator struct {
		group     Group
		samples   []sampleEntry
		statusMap map[Status]int
	}

	bucketKey := func(kind Kind, sourceKind, source string) string {
		return string(kind) + "|" + sourceKind + ":" + source
	}

	buckets := make(map[string]*aggregator)
	for _, inc := range incidents {
		if !statusAllowed(inc.Status) {
			continue
		}
		if filter.Kind != "" && inc.Kind != filter.Kind {
			continue
		}
		sourceKind, source := groupSource(inc)
		k := bucketKey(inc.Kind, sourceKind, source)
		agg, ok := buckets[k]
		if !ok {
			agg = &aggregator{
				group: Group{
					Key:        k,
					Kind:       inc.Kind,
					SourceKind: sourceKind,
					Source:     source,
					FirstSeen:  inc.CreatedAt,
					LastSeen:   inc.UpdatedAt,
				},
				statusMap: map[Status]int{},
			}
			buckets[k] = agg
		}
		agg.group.IncidentCount++
		agg.statusMap[inc.Status]++
		if inc.Severity > agg.group.SeverityMax {
			agg.group.SeverityMax = inc.Severity
		}
		if inc.CreatedAt.Before(agg.group.FirstSeen) || agg.group.FirstSeen.IsZero() {
			agg.group.FirstSeen = inc.CreatedAt
		}
		if inc.UpdatedAt.After(agg.group.LastSeen) {
			agg.group.LastSeen = inc.UpdatedAt
		}
		agg.samples = append(agg.samples, sampleEntry{id: inc.ID, updatedAt: inc.UpdatedAt})
	}

	out := make([]Group, 0, len(buckets))
	for _, agg := range buckets {
		agg.group.OpenCount = agg.statusMap[StatusOpen]
		agg.group.ContainedCount = agg.statusMap[StatusContained]
		agg.group.ResolvedCount = agg.statusMap[StatusResolved]
		agg.group.DismissedCount = agg.statusMap[StatusDismissed]
		agg.group.SeverityLabel = agg.group.SeverityMax.String()

		// Top-3 most recently updated members.
		sort.SliceStable(agg.samples, func(i, j int) bool {
			return agg.samples[i].updatedAt.After(agg.samples[j].updatedAt)
		})
		n := len(agg.samples)
		if n > 3 {
			n = 3
		}
		ids := make([]string, n)
		for i := 0; i < n; i++ {
			ids[i] = agg.samples[i].id
		}
		agg.group.SampleIDs = ids

		out = append(out, agg.group)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IncidentCount != out[j].IncidentCount {
			return out[i].IncidentCount > out[j].IncidentCount
		}
		if out[i].SeverityMax != out[j].SeverityMax {
			return out[i].SeverityMax > out[j].SeverityMax
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})

	totalGroups := len(out)
	if filter.MaxGroups > 0 && len(out) > filter.MaxGroups {
		out = out[:filter.MaxGroups]
	}

	return GroupsResponse{
		Groups:           out,
		TotalGroups:      totalGroups,
		ScannedIncidents: scanned,
		Truncated:        truncated,
	}
}

// groupSource derives the (source_kind, source) pair the UI uses to
// label and drill into a group. Cascade order: remote_ip > account >
// domain > mailbox > "_unkeyed". The IP path is the most useful
// grouping for credential-spray patterns and the most common shape on
// busy hosts.
func groupSource(inc Incident) (sourceKind, source string) {
	if inc.CorrelationKey != nil && inc.CorrelationKey.RemoteIP != "" {
		return "ip", inc.CorrelationKey.RemoteIP
	}
	if inc.Account != "" {
		return "account", inc.Account
	}
	if inc.Domain != "" {
		return "domain", inc.Domain
	}
	if inc.Mailbox != "" {
		return "mailbox", inc.Mailbox
	}
	return "_unkeyed", ""
}
