package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/admissionowner"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// A placement collision must remain visible from the real ledger through
// the owner's count, joined anonymization and the operator's comparison.
func TestCompareCountsOwnerPlacementRefusals(t *testing.T) {
	for _, busy := range []bool{false, true} {
		t.Run(map[bool]string{false: "ended", true: "in flight"}[busy], func(t *testing.T) {
			dir := t.TempDir()
			db, err := store.Open(filepath.Join(dir, "state"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			var mu sync.Mutex
			wall := compareTS
			clock := func() (admission.ClockReading, error) {
				mu.Lock()
				defer mu.Unlock()
				return admission.ClockReading{Wall: wall, BootID: "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b", SinceBoot: time.Hour + wall.Sub(compareTS)}, nil
			}
			var rows []actionlog.Record
			o := admissionowner.Start(admissionowner.Options{
				DB: db, StatePath: filepath.Join(dir, "state"), Clock: clock,
				Ceiling:     func() (uint32, string) { return admission.MaxCeiling, "default" },
				Inventory:   func() (admission.InventoryObservation, error) { return admission.InventoryObservation{}, nil },
				LegacySpend: func(string, time.Time) (admission.LegacySpend, error) { return admission.LegacySpend{}, nil },
				WriteAudit: func(batch []actionlog.Record) error {
					mu.Lock()
					defer mu.Unlock()
					for _, r := range batch {
						r.V = actionlog.SchemaVersion
						rows = append(rows, r)
					}
					return nil
				},
				TickEvery: time.Hour, InventoryEvery: time.Hour, StatusEvery: time.Hour,
				DeliverEvery: time.Hour, NoticeEvery: time.Hour, DrainEvery: time.Hour, ScheduleEvery: time.Hour,
			})
			t.Cleanup(o.Stop)
			if st := o.Status(); st.Owner.Error != "" || st.Owner.InventoryError != "" {
				t.Fatalf("owner did not start: %+v", st.Owner)
			}
			reg, _, err := admissionowner.Registry()
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := store.OpenAdmissionLedger(db, reg)
			if err != nil {
				t.Fatal(err)
			}
			reading, _ := clock()
			if _, err = ledger.Tick(reading); err != nil {
				t.Fatal(err)
			}
			finding := alert.Finding{
				Check: "ssh_login_unknown_ip", Severity: alert.High, Timestamp: compareTS,
				SourceIP: "192.0.2.10", Message: "Authentication report",
				Observation: alert.Observation{Producer: string(checks.ProducerSSHLog), Stream: "ssh", Cursor: "offset=1", ObservedAt: compareTS},
			}
			root, err := o.Mint(finding, finding.SourceIP)
			if err != nil {
				t.Fatal(err)
			}
			req := admission.CandidateRequest{Kind: admission.KindBlockIP, Target: root.Target(), Primary: root.ID()}
			first, _, err := ledger.EnqueueGroup([]admission.Arrival{{Evidence: root, Request: req}}, nil)
			if err != nil || len(first) != 1 || first[0].Err != nil || !first[0].Created {
				t.Fatalf("initial placement: %+v %v", first, err)
			}
			c, err := ledger.Terminate(first[0].Candidate, admission.ReasonPolicy)
			if err != nil {
				t.Fatal(err)
			}
			// Only damage leaves a candidate at the generation the episode
			// will choose next, without updating the episode's own line.
			req.Episode, req.Generation = c.Key.Episode, 2
			stray, created, err := ledger.Enqueue(req)
			if err != nil || !created {
				t.Fatalf("stray placement: %v %v", created, err)
			}
			id, err := stray.Key.ID()
			if err != nil {
				t.Fatal(err)
			}
			if busy {
				_, _, _, err = ledger.Reserve(id, admission.LaneGeneral, compareTS.Add(time.Hour))
			} else {
				_, err = ledger.Terminate(id, admission.ReasonPolicy)
			}
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			wall = compareTS.Add(time.Second)
			mu.Unlock()
			if err = o.Reload(); err != nil {
				t.Fatal(err)
			}
			finding.Timestamp, finding.Observation.ObservedAt = compareTS.Add(time.Second), compareTS.Add(time.Second)
			finding.Observation.Cursor = "offset=2"
			root, err = o.Mint(finding, finding.SourceIP)
			if err != nil {
				t.Fatal(err)
			}
			if err = o.Respond(admission.KindBlockIP, root, 0); err != nil {
				t.Fatal(err)
			}
			o.Stop()
			var counted uint64
			for _, row := range ledger.Status().Counters.Rows {
				if row.Event == "refused" && row.Reason == "invalid" {
					counted += row.N
				}
			}
			if counted != 1 {
				t.Fatalf("ledger invalid refusals = %d, want 1", counted)
			}
			mu.Lock()
			defer mu.Unlock()
			var summaries []actionlog.Record
			for _, row := range rows {
				if row.Count != 0 {
					summaries = append(summaries, row)
				}
			}
			if len(summaries) != 1 || summaries[0].Count != 1 || summaries[0].Result != "refused" || summaries[0].Error != "invalid" ||
				summaries[0].Reason != "ssh_login_unknown_ip" || summaries[0].ActorDetail != "scan" || summaries[0].Action != "block_ip" ||
				summaries[0].Target != "" || summaries[0].FindingID != "" || summaries[0].ActionID != "" || summaries[0].Account != "" {
				t.Fatalf("owner lost the placement refusal: %+v", summaries)
			}
			legacy := actionlog.Record{V: 1, Timestamp: compareTS.Add(time.Minute), Op: "respond.block_ip", Action: "block", Actor: actionlog.Daemon,
				FindingID: root.FindingID(), Target: finding.SourceIP, Reason: "CSM auto-block: authentication", Result: actionlog.Applied}
			fp, ap := filepath.Join(dir, "raw-findings.jsonl"), filepath.Join(dir, "raw-actions.jsonl")
			fo, ao := filepath.Join(dir, "findings.jsonl.gz"), filepath.Join(dir, "actions.jsonl.gz")
			salt := filepath.Join(dir, "salt")
			writeTestSalt(t, salt)
			writeInput(t, fp, encodeLines(t, alert.NewAuditEvent("host.example", finding)))
			writeInput(t, ap, encodeLines(t, anySlice(append(summaries, legacy))...))
			if err = testRun().execute([]string{"anonymize", "--salt-file", salt, "--out", fo, "--actions", ap, "--actions-out", ao,
				"--manifest", filepath.Join(dir, "manifest.json"), fp}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err = run([]string{"compare", "--findings", fo, "--actions", ao}, &out); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"legacy automatic actions: 1", "unexplained: 1: FAIL", "invalid refusals: 1: FAIL"} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing %q:\n%s", want, out.String())
				}
			}
		})
	}
}
