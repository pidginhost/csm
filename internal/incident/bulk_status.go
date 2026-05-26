package incident

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// BulkStatusFilter selects stale active incidents for a bounded operator
// transition. The caller must supply at least one age guard and a positive
// limit so a broad filter cannot accidentally close every incident.
type BulkStatusFilter struct {
	FromStatuses   []Status
	To             Status
	OlderThan      time.Duration
	LastSeenBefore time.Time
	Kind           Kind
	Domain         string
	Account        string
	Mailbox        string
	Limit          int
	DryRun         bool
	Details        string
	Now            time.Time
}

// BulkStatusItem is a small preview row for bulk incident status changes.
type BulkStatusItem struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Status     string    `json:"status"`
	NewStatus  string    `json:"new_status"`
	Severity   string    `json:"severity"`
	Domain     string    `json:"domain,omitempty"`
	Account    string    `json:"account,omitempty"`
	Mailbox    string    `json:"mailbox,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// BulkStatusResult reports how many incidents matched the filter and how
// many were changed. Items is capped by BulkStatusFilter.Limit.
type BulkStatusResult struct {
	Matched int
	Updated int
	Items   []BulkStatusItem
}

// BulkSetStatus previews or applies one closing transition to matching
// incidents. Matching and mutation happen under the correlator lock so a
// fresh finding cannot update LastSeen between filter evaluation and close.
func (c *Correlator) BulkSetStatus(filter BulkStatusFilter) (BulkStatusResult, error) {
	if filter.To != StatusResolved && filter.To != StatusDismissed {
		return BulkStatusResult{}, fmt.Errorf("incident: bulk target status must be resolved or dismissed")
	}
	if filter.OlderThan <= 0 && filter.LastSeenBefore.IsZero() {
		return BulkStatusResult{}, fmt.Errorf("incident: bulk status requires older-than or last-seen-before")
	}
	if filter.Limit <= 0 {
		return BulkStatusResult{}, fmt.Errorf("incident: bulk status requires a positive limit")
	}
	now := filter.Now
	if now.IsZero() {
		now = c.now()
	}
	statusSet := make(map[Status]struct{}, len(filter.FromStatuses))
	for _, status := range filter.FromStatuses {
		if !validStatus(status) {
			return BulkStatusResult{}, fmt.Errorf("incident: invalid status %q", status)
		}
		statusSet[status] = struct{}{}
	}
	if len(statusSet) == 0 {
		return BulkStatusResult{}, fmt.Errorf("incident: bulk status requires a source status")
	}

	var persist []queuedPersist
	result := BulkStatusResult{Items: make([]BulkStatusItem, 0, filter.Limit)}

	c.mu.Lock()
	matched := make([]*Incident, 0, len(c.incidents))
	for _, inc := range c.incidents {
		if bulkStatusMatches(inc, filter, statusSet, now) {
			matched = append(matched, inc)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if !matched[i].UpdatedAt.Equal(matched[j].UpdatedAt) {
			return matched[i].UpdatedAt.Before(matched[j].UpdatedAt)
		}
		return matched[i].ID < matched[j].ID
	})
	result.Matched = len(matched)

	for _, inc := range matched {
		if len(result.Items) >= filter.Limit {
			break
		}
		from := inc.Status
		result.Items = append(result.Items, bulkStatusItem(inc, filter.To))
		if filter.DryRun {
			continue
		}
		inc.Status = filter.To
		inc.UpdatedAt = now
		inc.ClosedAt = now
		inc.ClosedBy = "operator"
		inc.Actions = append(inc.Actions, IncidentAction{
			Time:    now,
			Action:  "incident_status_changed",
			Result:  "ok",
			Details: string(from) + " -> " + string(filter.To) + ": " + filter.Details,
		})
		c.counters.statusChangedTotal.Add(1)
		c.unbindLocked(inc.ID)
		if req, ok := c.queuePersistLocked(*inc); ok {
			persist = append(persist, req)
		}
		result.Updated++
	}
	c.mu.Unlock()

	for _, req := range persist {
		c.runQueuedPersist(req)
	}
	return result, nil
}

func bulkStatusMatches(inc *Incident, filter BulkStatusFilter, statusSet map[Status]struct{}, now time.Time) bool {
	if _, ok := statusSet[inc.Status]; !ok {
		return false
	}
	if filter.OlderThan > 0 {
		cutoff := now.Add(-filter.OlderThan)
		if inc.UpdatedAt.After(cutoff) {
			return false
		}
	}
	if !filter.LastSeenBefore.IsZero() && inc.UpdatedAt.After(filter.LastSeenBefore) {
		return false
	}
	if filter.Kind != "" && inc.Kind != filter.Kind {
		return false
	}
	if filter.Domain != "" && !strings.EqualFold(inc.Domain, filter.Domain) {
		return false
	}
	if filter.Account != "" && !strings.EqualFold(inc.Account, filter.Account) {
		return false
	}
	if filter.Mailbox != "" && !strings.EqualFold(inc.Mailbox, filter.Mailbox) {
		return false
	}
	return true
}

func bulkStatusItem(inc *Incident, to Status) BulkStatusItem {
	return BulkStatusItem{
		ID:         inc.ID,
		Kind:       string(inc.Kind),
		Status:     string(inc.Status),
		NewStatus:  string(to),
		Severity:   inc.Severity.String(),
		Domain:     inc.Domain,
		Account:    inc.Account,
		Mailbox:    inc.Mailbox,
		CreatedAt:  inc.CreatedAt,
		LastSeenAt: inc.UpdatedAt,
	}
}
