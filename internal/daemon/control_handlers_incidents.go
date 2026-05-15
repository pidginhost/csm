package daemon

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/incident"
)

const (
	defaultIncidentListLimit = 100
	maxIncidentListLimit     = 1000
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
