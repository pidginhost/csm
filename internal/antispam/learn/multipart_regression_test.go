package learn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestEngineMultipartOperatorRetryKeepsOneBodyAndMark(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed", true: "pending"}[uncertain], func(t *testing.T) {
			f := newAuditFixture(t)
			e := newTestEngine(t, f)
			snap, parts := f.multipartReport(t, digest('x'), digest('p'))
			staged := 0
			f.bodies.writeFile = func(file *os.File, body []byte) error {
				staged++
				if !bytes.Equal(body, parts[1]) {
					t.Error("staged a body other than the selected single part")
				}
				return writeSync(file, body)
			}
			if uncertain {
				f.storage.onAdd = func(Digest, int32) (bool, error) { return true, ErrUncertain }
			}
			req := opRequest(ActionSpam, snap)
			first, firstErr := e.Operator(context.Background(), req)
			want := ResultPartial
			if uncertain {
				want = ResultPending
			}
			if firstErr != nil || first.Outcome != want || len(first.Clusters) != 2 {
				t.Fatalf("first result %+v err=%v", first, firstErr)
			}
			_, before, _, _ := f.storage.native()
			for range 2 {
				res, err := e.Operator(context.Background(), req)
				wantClusters := []ClusterOutcome{{ClusterID: first.Clusters[0].ClusterID, Result: ResultCommitted}, {Result: ResultSkipped + ":" + SkipMultipartSeed}}
				if err != nil || res.Outcome != ResultPartial || !reflect.DeepEqual(res.Clusters, wantClusters) || !reflect.DeepEqual(res.Digests, first.Digests) {
					t.Fatalf("retry result %+v err=%v", res, err)
				}
			}
			if _, after, adds, _ := f.storage.native(); after != before || adds != 1 || staged != 1 {
				t.Fatalf("body inspections %d to %d, adds=%d staged=%d", before, after, adds, staged)
			}
			c, ok := f.cluster(t, first.Clusters[0].ClusterID)
			if !ok || !reflect.DeepEqual(c.Marks, []string{req.RequestID}) || c.BodySHA != sha(parts[1]) {
				t.Fatalf("cluster %+v", c)
			}
			body, err := f.bodies.Read(c.ID, c.BodyLen, c.BodySHA)
			if err != nil || !bytes.Equal(body, parts[1]) {
				t.Fatalf("retained body differs from the selected part: %v", err)
			}
			if v, ok := f.storage.value(digest('p')); !ok || v != OperatorWeight {
				t.Fatalf("anchor value=%d present=%v", v, ok)
			}
			if _, ok := f.storage.value(digest('h')); ok {
				t.Fatal("published the other digest")
			}
			if viewErr := f.ledger.View(func(v LedgerView) error {
				u, usageErr := v.Usage(0, true)
				if u != (Usage{BodyBytes: int64(len(parts[1])), Aliases: 1}) {
					t.Errorf("operator usage %+v", u)
				}
				return usageErr
			}); viewErr != nil {
				t.Fatal(viewErr)
			}
			entries, err := os.ReadDir(f.bodies.Dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != BodyName(c.ID) {
				t.Fatalf("body entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestEngineMultipartCandidateInspectionFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		insp Inspection
		err  error
	}{
		{name: "rejected", err: ErrMessageRejected},
		{name: "no digest"},
		{name: "several digests", insp: Inspection{Distinct: 2, Results: []Result{{Queried: digest('h')}, {Queried: digest('p')}}}},
		{name: "unrelated", insp: Inspection{Distinct: 1, Results: []Result{{Queried: digest('x')}}}},
		{name: "already found", insp: Inspection{Distinct: 1, Results: []Result{{Queried: digest('h'), Stored: digest('h'), Found: true, Confirmed: true, Prob: 1, Value: 2, Flag: 1}}}},
		{name: "backend failure", err: ErrReadFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuditFixture(t)
			e := newTestEngine(t, f)
			snap, parts := f.multipartReport(t, digest('h'), digest('p'))
			attempts := 0
			client := inspectionHook{nativeClient: f.storage, inspect: func(ctx context.Context, body []byte) (Inspection, error) {
				if bytes.Equal(body, parts[0]) {
					attempts++
					return tc.insp, tc.err
				}
				return f.storage.Inspect(ctx, body)
			}}
			engineTurn(t, e, func() { e.cfg.Client = client; e.pub.client = client })
			out, err := e.SubmitReport(context.Background(), Candidate{UID: 1002, Snapshot: snap})
			if err != nil || attempts != 1 {
				t.Fatalf("outcome %+v attempts=%d err=%v", out, attempts, err)
			}
			if tc.err == ErrReadFailed {
				if !out.Deferred || !errors.Is(out.Err, ErrReadFailed) || len(out.Committed) != 0 || len(out.Pending) != 0 {
					t.Fatalf("backend failure outcome %+v", out)
				}
				entries, err := os.ReadDir(f.bodies.Dir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("staged after inspection failure: %v err=%v", entries, err)
				}
				if _, _, adds, _ := f.storage.native(); adds != 0 {
					t.Fatalf("sent %d adds after inspection failure", adds)
				}
				return
			}
			if out.Err != nil || out.Deferred || len(out.Committed) != 1 {
				t.Fatalf("fallback outcome %+v", out)
			}
			c, ok := f.cluster(t, out.Committed[0])
			if !ok || c.Anchor != digest('p') || c.BodySHA != sha(parts[1]) {
				t.Fatalf("fallback cluster %+v", c)
			}
			if !reflect.DeepEqual(out.Skips, []Skip{{Digest: digest('h'), Reason: SkipMultipartSeed}}) {
				t.Fatalf("fallback skips %+v", out.Skips)
			}
		})
	}
}
