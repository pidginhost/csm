package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/incident"
)

func TestHandleIncidentsListReturnsSnapshot(t *testing.T) {
	resetIncidentForTest()
	c := IncidentCorrelator()
	_, _, _ = c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Now()})

	cl := &ControlListener{}
	res, err := cl.handleIncidentsList(nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	b, _ := json.Marshal(res)
	var list []incident.Incident
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("len: %d", len(list))
	}
}

func TestHandleIncidentsShowByID(t *testing.T) {
	resetIncidentForTest()
	c := IncidentCorrelator()
	id, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Now()})

	cl := &ControlListener{}
	args, _ := json.Marshal(control.IncidentShowArgs{ID: id})
	res, err := cl.handleIncidentsShow(args)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	b, _ := json.Marshal(res)
	var inc incident.Incident
	if err := json.Unmarshal(b, &inc); err != nil {
		t.Fatal(err)
	}
	if inc.ID != id {
		t.Errorf("id: %q vs %q", inc.ID, id)
	}
}

func TestHandleIncidentsShowMissReturnsError(t *testing.T) {
	resetIncidentForTest()
	_ = IncidentCorrelator()
	cl := &ControlListener{}
	args, _ := json.Marshal(control.IncidentShowArgs{ID: "inc_nope"})
	if _, err := cl.handleIncidentsShow(args); err == nil {
		t.Error("expected error for missing incident")
	}
}

func TestHandleIncidentsStatusUpdates(t *testing.T) {
	resetIncidentForTest()
	c := IncidentCorrelator()
	id, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Now()})

	cl := &ControlListener{}
	args, _ := json.Marshal(control.IncidentStatusArgs{ID: id, Status: "resolved", Details: "op"})
	if _, err := cl.handleIncidentsStatus(args); err != nil {
		t.Fatalf("handler: %v", err)
	}
	got, _ := c.Get(id)
	if got.Status != incident.StatusResolved {
		t.Errorf("status: %v", got.Status)
	}
}
