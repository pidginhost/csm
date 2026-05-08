package daemon

import (
	"encoding/json"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/incident"
)

// handleIncidentsList returns every incident newest-UpdatedAt first.
func (c *ControlListener) handleIncidentsList(_ json.RawMessage) (any, error) {
	co := IncidentCorrelator()
	return co.Snapshot(), nil
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
