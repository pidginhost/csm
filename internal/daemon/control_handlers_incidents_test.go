package daemon

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/incident"
)

func TestHandleIncidentsListReturnsBoundedPage(t *testing.T) {
	resetIncidentForTest()
	c := IncidentCorrelator()
	for i := 0; i < 105; i++ {
		_, _, _ = c.OnFinding(alert.Finding{
			Check:     "x",
			Severity:  alert.High,
			TenantID:  "acct-" + strconv.Itoa(i),
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
		})
	}

	cl := &ControlListener{}
	res, err := cl.handleIncidentsList(nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	b, _ := json.Marshal(res)
	var page control.IncidentListResult
	if err := json.Unmarshal(b, &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.Total != 105 {
		t.Errorf("total: %d, want 105", page.Total)
	}
	if len(page.Items) != defaultIncidentListLimit {
		t.Errorf("items len: %d, want %d", len(page.Items), defaultIncidentListLimit)
	}
	if page.Limit != defaultIncidentListLimit || page.Offset != 0 || page.Status != "all" {
		t.Errorf("page metadata = %+v", page)
	}
}

func TestHandleIncidentsListFiltersStatusAndHonorsAll(t *testing.T) {
	resetIncidentForTest()
	c := IncidentCorrelator()
	openID, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Now()})
	doneID, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "bob", Timestamp: time.Now().Add(time.Second)})
	if openID == "" || doneID == "" {
		t.Fatal("seed incidents missing")
	}
	if err := c.SetStatus(doneID, incident.StatusResolved, "done"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	args, _ := json.Marshal(control.IncidentListArgs{Status: "open", All: true})
	cl := &ControlListener{}
	res, err := cl.handleIncidentsList(args)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	b, _ := json.Marshal(res)
	var page control.IncidentListResult
	if err := json.Unmarshal(b, &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != openID {
		t.Fatalf("open page = %+v, want only %s", page, openID)
	}
	if page.Limit != 0 || page.Status != "open" {
		t.Errorf("page metadata = %+v", page)
	}
}

func TestHandleIncidentsListRejectsUnknownStatus(t *testing.T) {
	resetIncidentForTest()
	_ = IncidentCorrelator()
	args, _ := json.Marshal(control.IncidentListArgs{Status: "opn"})
	cl := &ControlListener{}
	if _, err := cl.handleIncidentsList(args); err == nil {
		t.Fatal("expected unknown status error")
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
