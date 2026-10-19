package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/control"
)

type fakeLearner struct {
	calls int
	got   learn.OperatorRequest
	res   learn.OperatorResult
	err   error
}

func (f *fakeLearner) Operator(_ context.Context, r learn.OperatorRequest) (learn.OperatorResult, error) {
	f.calls++
	f.got = r
	return f.res, f.err
}

func withLearner(t *testing.T, l learnOperator) {
	t.Helper()
	saved := antispamLearnOperator
	antispamLearnOperator = func(*Daemon) learnOperator { return l }
	t.Cleanup(func() { antispamLearnOperator = saved })
}

func learnArgs(t *testing.T, action, name, body string) json.RawMessage {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	data, err := json.Marshal(control.AntispamLearnArgs{Action: action, RequestID: strings.Repeat("ab", 16), Name: name, SnapshotSHA: hex.EncodeToString(sum[:]), Snapshot: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func captureActions(t *testing.T) *[]actionlog.Record {
	t.Helper()
	var recs []actionlog.Record
	actionlog.SetSink(actionShowSink(func(r actionlog.Record) error {
		recs = append(recs, r)
		return nil
	}), "")
	t.Cleanup(func() { actionlog.SetSink(nil, "") })
	return &recs
}

func TestControlLearnDisabledRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		antispam, learning bool
		mode               string
		learner            bool
		err                error
	}{
		"antispam off":  {false, true, "", true, nil},
		"learning off":  {true, false, "", true, nil},
		"observe":       {true, true, "observe", true, nil},
		"not running":   {true, true, "", false, nil},
		"gate closed":   {true, true, "", true, learn.ErrLearningOff},
		"state frozen":  {true, true, "", true, learn.ErrStateMismatch},
		"request reuse": {true, true, "", true, learn.ErrRequestReused},
	} {
		t.Run(name, func(t *testing.T) {
			d := newDaemonForListener(t)
			d.cfg.EmailProtection.Antispam.Enabled = tc.antispam
			d.cfg.EmailProtection.Antispam.Learning.Enabled = tc.learning
			d.cfg.Mode = tc.mode
			fake := &fakeLearner{err: tc.err}
			if tc.learner {
				withLearner(t, fake)
			} else {
				withLearner(t, nil)
			}
			recs := captureActions(t)
			cl := &ControlListener{d: d}
			if _, err := cl.handleAntispamLearn(learnArgs(t, learn.ActionSpam, "sample.eml", "spam body")); err == nil {
				t.Fatal("refused request reported success")
			}
			if tc.err == nil && fake.calls != 0 {
				t.Fatal("a disabled learner received the file")
			}
			if len(*recs) != 1 || (*recs)[0].Result == actionlog.Applied {
				t.Fatalf("records %+v", *recs)
			}
		})
	}
}

func TestControlLearnAuditRecord(t *testing.T) {
	d := newDaemonForListener(t)
	d.cfg.EmailProtection.Antispam.Enabled = true
	d.cfg.EmailProtection.Antispam.Learning.Enabled = true
	digest := learn.Digest(strings.Repeat("c", 128))
	fake := &fakeLearner{res: learn.OperatorResult{RequestID: strings.Repeat("ab", 16), Digests: []learn.Digest{digest},
		Clusters: []learn.ClusterOutcome{{ClusterID: 7, Result: learn.ResultCommitted}}, Outcome: learn.ResultCommitted, ExitOK: true}}
	withLearner(t, fake)
	recs := captureActions(t)
	cl := &ControlListener{d: d}
	body := "Subject: secret-subject-marker\r\n\r\nsecret-body-marker"
	raw, err := cl.handleAntispamLearn(learnArgs(t, learn.ActionSpam, `in "box".eml`, body))
	if err != nil {
		t.Fatal(err)
	}
	res := raw.(control.AntispamLearnResult)
	if !res.ExitOK || res.Outcome != learn.ResultCommitted || len(res.Clusters) != 1 || res.Clusters[0].ClusterID != 7 || res.Digests[0] != string(digest) {
		t.Fatalf("result %+v", res)
	}
	if string(fake.got.Snapshot) != body || fake.got.Action != learn.ActionSpam || fake.got.RequestID != strings.Repeat("ab", 16) {
		t.Fatalf("learner got %+v", fake.got)
	}
	if len(*recs) != 1 {
		t.Fatalf("records %+v", *recs)
	}
	rec := (*recs)[0]
	if rec.Op != "integrate.antispam_learn" || rec.Action != learn.ActionSpam || rec.Actor != actionlog.CLI ||
		rec.ActorDetail != "csm antispam learn" || rec.Target != `"in \"box\".eml"` || rec.Result != actionlog.Applied {
		t.Fatalf("record %+v", rec)
	}
	if !strings.Contains(rec.Reason, strings.Repeat("ab", 16)) || !strings.Contains(rec.Reason, string(digest)) || !strings.Contains(rec.Reason, "committed") {
		t.Fatalf("reason %q", rec.Reason)
	}
	data, _ := json.Marshal(rec)
	if strings.Contains(string(data), "marker") {
		t.Fatal("the action record carries message content")
	}
	// A failure is recorded too.
	fake.res, fake.err = learn.OperatorResult{}, errors.New("controller unavailable")
	if _, err := cl.handleAntispamLearn(learnArgs(t, learn.ActionForget, "x.eml", body)); err == nil {
		t.Fatal("failure reported as success")
	}
	if len(*recs) != 2 || (*recs)[1].Result != actionlog.Failed || (*recs)[1].Error == "" || (*recs)[1].Action != learn.ActionForget {
		t.Fatalf("records %+v", *recs)
	}
}
