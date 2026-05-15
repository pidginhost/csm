package daemon

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/incident"
)

const (
	defaultIncidentListLimit = 100
	maxIncidentListLimit     = 1000
	defaultIncidentBulkLimit = 100
	maxIncidentBulkLimit     = 1000
)

// handleIncidentsList returns a bounded, newest-first incident page.
func (c *ControlListener) handleIncidentsList(argsRaw json.RawMessage) (any, error) {
	var args control.IncidentListArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, err
		}
	}
	statuses, statusLabel, err := incidentListStatusFilter(args.Status)
	if err != nil {
		return nil, err
	}
	offset := args.Offset
	if offset < 0 {
		offset = 0
	}
	limit := args.Limit
	if args.All {
		limit = 0
	} else {
		if limit <= 0 {
			limit = defaultIncidentListLimit
		}
		if limit > maxIncidentListLimit {
			limit = maxIncidentListLimit
		}
	}

	co := IncidentCorrelator()
	items, total := co.SnapshotPageStatuses(statuses, offset, limit)
	return control.IncidentListResult{
		Items:  items,
		Total:  total,
		Offset: offset,
		Limit:  limit,
		Status: statusLabel,
	}, nil
}

func incidentListStatusFilter(status string) ([]incident.Status, string, error) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "all":
		return nil, "all", nil
	case "active":
		return []incident.Status{incident.StatusOpen, incident.StatusContained}, "active", nil
	case string(incident.StatusOpen):
		return []incident.Status{incident.StatusOpen}, string(incident.StatusOpen), nil
	case string(incident.StatusContained):
		return []incident.Status{incident.StatusContained}, string(incident.StatusContained), nil
	case string(incident.StatusResolved):
		return []incident.Status{incident.StatusResolved}, string(incident.StatusResolved), nil
	case string(incident.StatusDismissed):
		return []incident.Status{incident.StatusDismissed}, string(incident.StatusDismissed), nil
	default:
		return nil, "", fmt.Errorf("unknown status: %q", status)
	}
}

func incidentBulkStatusFilter(status string) ([]incident.Status, string, error) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "active":
		return []incident.Status{incident.StatusOpen, incident.StatusContained}, "active", nil
	case string(incident.StatusOpen):
		return []incident.Status{incident.StatusOpen}, string(incident.StatusOpen), nil
	case string(incident.StatusContained):
		return []incident.Status{incident.StatusContained}, string(incident.StatusContained), nil
	default:
		return nil, "", fmt.Errorf("bulk status source must be active, open, or contained")
	}
}

// handleIncidentsShow returns one incident by id; ErrIncidentNotFound on miss.
func (c *ControlListener) handleIncidentsShow(argsRaw json.RawMessage) (any, error) {
	var args control.IncidentShowArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, err
		}
	}
	co := IncidentCorrelator()
	inc, ok := co.Get(args.ID)
	if !ok {
		return nil, incident.ErrIncidentNotFound
	}
	return inc, nil
}

// handleIncidentsStatus transitions an incident's status. Returns
// {"ok": true} on success; ErrIncidentNotFound or validation error on
// failure.
func (c *ControlListener) handleIncidentsStatus(argsRaw json.RawMessage) (any, error) {
	var args control.IncidentStatusArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, err
		}
	}
	co := IncidentCorrelator()
	if err := co.SetStatus(args.ID, incident.Status(args.Status), args.Details); err != nil {
		return nil, err
	}
	return map[string]bool{"ok": true}, nil
}

func (c *ControlListener) handleIncidentsBulkStatus(argsRaw json.RawMessage) (any, error) {
	var args control.IncidentBulkStatusArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, err
		}
	}
	statuses, statusLabel, err := incidentBulkStatusFilter(args.Status)
	if err != nil {
		return nil, err
	}
	to := incident.Status(strings.ToLower(strings.TrimSpace(args.To)))
	if to == "" {
		to = incident.StatusResolved
	}
	if to != incident.StatusResolved && to != incident.StatusDismissed {
		return nil, fmt.Errorf("bulk status target must be resolved or dismissed")
	}
	if args.OlderThanSeconds < 0 {
		return nil, fmt.Errorf("older-than must be positive")
	}
	olderThan := time.Duration(args.OlderThanSeconds) * time.Second
	if olderThan <= 0 && args.LastSeenBefore.IsZero() {
		return nil, fmt.Errorf("bulk status requires --older-than or --last-seen-before")
	}
	limit := args.Limit
	if limit <= 0 {
		limit = defaultIncidentBulkLimit
	}
	if limit > maxIncidentBulkLimit {
		limit = maxIncidentBulkLimit
	}
	if args.Apply && !args.Confirm {
		return nil, fmt.Errorf("bulk status apply requires confirmation")
	}
	dryRun := !args.Apply

	co := IncidentCorrelator()
	res, err := co.BulkSetStatus(incident.BulkStatusFilter{
		FromStatuses:   statuses,
		To:             to,
		OlderThan:      olderThan,
		LastSeenBefore: args.LastSeenBefore,
		Kind:           incident.Kind(strings.TrimSpace(args.Kind)),
		Domain:         strings.TrimSpace(args.Domain),
		Account:        strings.TrimSpace(args.Account),
		Mailbox:        strings.TrimSpace(args.Mailbox),
		Limit:          limit,
		DryRun:         dryRun,
		Details:        strings.TrimSpace(args.Details),
	})
	if err != nil {
		return nil, err
	}
	return control.IncidentBulkStatusResult{
		DryRun:           dryRun,
		Matched:          res.Matched,
		Updated:          res.Updated,
		Limit:            limit,
		Status:           statusLabel,
		To:               string(to),
		OlderThanSeconds: args.OlderThanSeconds,
		LastSeenBefore:   args.LastSeenBefore,
		Items:            res.Items,
	}, nil
}
