package daemon

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admissionowner"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

// Exercise dispatch and socket framing, rather than constructing a status
// response in the test. HTTP has a matching provider-copy contract test.
func TestControlStatusAdmissionMatchesTheProvider(t *testing.T) {
	sock := redirectControlSocket(t)
	d := newDaemonForListener(t)
	db, restore := openTestBoltStore(t, t.TempDir())
	defer restore()
	cfg, err := config.LoadBytes([]byte("auto_response:\n  dry_run: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.StatePath = t.TempDir()
	config.SetActive(cfg)
	d.cfg = cfg
	opts := testAdmissionOptions(d, db)
	// An empty executable owner starts a forecast without touching an
	// engine. Its publication and mode transition are still real.
	opts.Blocks = func() admissionowner.BlockEngine { return nil }
	opts.ScheduleEvery = time.Millisecond
	d.admission = admissionowner.Start(opts)
	defer d.admission.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err = d.admission.Reload(); err != nil {
			t.Fatal(err)
		}
		if status := d.AdmissionStatus(); status.Owner.DryRun.SessionID != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the owner did not publish its forecast session")
		}
		time.Sleep(time.Millisecond)
	}
	listener, err := NewControlListener(d)
	if err != nil {
		t.Fatal(err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); listener.Run(stop) }()
	defer func() { close(stop); listener.Stop(); <-done }()

	var session string
	for _, active := range []bool{true, false} {
		if !active {
			next := *cfg
			dry := false
			next.AutoResponse.DryRun = &dry
			config.SetActive(&next)
			if err = d.admission.Reload(); err != nil {
				t.Fatal(err)
			}
		}
		want := d.AdmissionStatus()
		response := roundtrip(t, sock, control.Request{Cmd: control.CmdStatus})
		if !response.OK {
			t.Fatalf("status request failed: %s", response.Error)
		}
		var result struct {
			Snapshot struct {
				Admission json.RawMessage `json:"admission"`
			} `json:"snapshot"`
		}
		if err = json.Unmarshal(response.Result, &result); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		var gotJSON, wantJSON map[string]any
		if err = json.Unmarshal(encoded, &wantJSON); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(result.Snapshot.Admission, &gotJSON); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotJSON, wantJSON) {
			t.Fatalf("socket admission %v, provider %v", gotJSON, wantJSON)
		}
		var got health.AdmissionStatus
		if err = json.Unmarshal(result.Snapshot.Admission, &got); err != nil {
			t.Fatal(err)
		}
		dry := got.Owner.DryRun
		if dry.Active != active || dry.SessionID == nil || dry.ResetReason == nil || *dry.ResetReason != "startup" {
			t.Fatalf("active=%v: forecast identity = %+v", active, dry)
		}
		if active {
			session = *dry.SessionID
			if dry.Ceiling == nil || dry.Ceiling.Limit != config.DefaultAdmissionCeiling {
				t.Fatalf("active ceiling = %+v", dry.Ceiling)
			}
		} else if *dry.SessionID != session || dry.Ceiling != nil || dry.Occupancy != nil {
			t.Fatalf("inactive forecast was not cleared: %+v", dry)
		}
		predictions := []string{"capacity_admit", "existing_actual", "existing_shadow", "ceiling", "set_full", "pending_recovery", "forecast_limited", "not_modelled"}
		for _, counts := range []map[string]uint64{dry.Picks, dry.LastHour} {
			if len(counts) != len(predictions) {
				t.Fatalf("prediction keys = %v", counts)
			}
			for _, key := range predictions {
				if n, exists := counts[key]; !exists || n != 0 {
					t.Fatalf("%s is not an explicit zero: %v", key, counts)
				}
			}
		}
	}
}
