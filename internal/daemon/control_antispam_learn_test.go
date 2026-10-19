package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

func TestControlLearnMalformedRequestAudited(t *testing.T) {
	d := newDaemonForListener(t)
	fake := &fakeLearner{}
	withLearner(t, fake)
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"action":"spam","request_id":"abcdef","name":"mail.eml","snapshot":{}}`),
		json.RawMessage(`{"snapshot":"private-body-marker`),
	} {
		recs := captureActions(t)
		_, err := (&ControlListener{d: d}).handleAntispamLearn(raw)
		if err == nil || len(*recs) != 1 || (*recs)[0].Result != actionlog.Refused {
			t.Fatalf("error %v, records %+v", err, *recs)
		}
		data, err := json.Marshal((*recs)[0])
		if err != nil || strings.Contains(string(data), "private-body-marker") || !strings.Contains((*recs)[0].Reason, "outcome refused") {
			t.Fatalf("invalid audit record: %s, %v", data, err)
		}
	}
	if fake.calls != 0 {
		t.Fatal("malformed request reached the learner")
	}
}

func TestControlLearnPersistsEveryDigest(t *testing.T) {
	d := newDaemonForListener(t)
	d.cfg.EmailProtection.Antispam.Enabled = true
	d.cfg.EmailProtection.Antispam.Learning.Enabled = true
	digests := make([]learn.Digest, learn.MaxExplicitDigests)
	for i := range digests {
		digests[i] = learn.Digest(fmt.Sprintf("%0128x", i))
	}
	withLearner(t, &fakeLearner{res: learn.OperatorResult{Digests: digests, Outcome: learn.ResultCommitted, ExitOK: true}})
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	actionlog.SetSink(actionlog.NewFileSink(func() string { return path }, nil), "")
	t.Cleanup(func() { actionlog.SetSink(nil, "") })
	if _, err := (&ControlListener{d: d}).handleAntispamLearn(learnArgs(t, learn.ActionSpam, "/mail/private/sample.eml", "body")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec actionlog.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Target != `"sample.eml"` {
		t.Errorf("target %q is not a JSON-escaped basename", rec.Target)
	}
	for _, digest := range digests {
		if !strings.Contains(string(data), string(digest)) {
			t.Fatalf("full digest %s is missing from persisted record", digest)
		}
	}
}

func TestControlLearnMaximumSnapshotRoundTrip(t *testing.T) {
	d := newDaemonForListener(t)
	d.cfg.EmailProtection.Antispam.Enabled = true
	d.cfg.EmailProtection.Antispam.Learning.Enabled = true
	fake := &fakeLearner{res: learn.OperatorResult{Outcome: learn.ResultCommitted, ExitOK: true}}
	withLearner(t, fake)
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&ControlListener{d: d}).handleConnection(server)
	}()
	t.Cleanup(func() { _ = client.Close(); <-done })
	body := bytes.Repeat([]byte("x"), learn.MaxBody)
	req := control.Request{Cmd: control.CmdAntispamLearn, Args: learnArgs(t, learn.ActionSpam, "max.eml", string(body))}
	if err := json.NewEncoder(client).Encode(req); err != nil {
		t.Fatal(err)
	}
	var resp control.Response
	if err := json.NewDecoder(client).Decode(&resp); err != nil || !resp.OK {
		t.Fatalf("response %+v, error %v", resp, err)
	}
	<-done
	if fake.calls != 1 || !bytes.Equal(fake.got.Snapshot, body) {
		t.Fatal("maximum snapshot did not reach the learner intact")
	}
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
	if !strings.Contains(rec.Reason, strings.Repeat("ab", 16)) || len(rec.Digests) != 1 || rec.Digests[0] != string(digest) || !strings.Contains(rec.Reason, "committed") {
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

// A deferred request changed nothing; its action record says it was held
// back, not that it failed.
func TestControlLearnDeferredIsRefused(t *testing.T) {
	d := newDaemonForListener(t)
	d.cfg.EmailProtection.Antispam.Enabled = true
	d.cfg.EmailProtection.Antispam.Learning.Enabled = true
	withLearner(t, &fakeLearner{res: learn.OperatorResult{RequestID: strings.Repeat("ab", 16), Outcome: learn.ResultDeferred}})
	recs := captureActions(t)
	cl := &ControlListener{d: d}
	raw, err := cl.handleAntispamLearn(learnArgs(t, learn.ActionSpam, "x.eml", "body"))
	if err != nil || raw.(control.AntispamLearnResult).Outcome != learn.ResultDeferred {
		t.Fatalf("result %+v err %v", raw, err)
	}
	if len(*recs) != 1 || (*recs)[0].Result != actionlog.Refused {
		t.Fatalf("records %+v", *recs)
	}
}

func TestControlLearnStatus(t *testing.T) {
	d := newDaemonForListener(t)
	db, closeDB := openTestBoltStore(t, t.TempDir())
	t.Cleanup(closeDB)
	id := strings.Repeat("ab", 16)
	if err := learn.Open(db).Update(func(tx learn.LedgerTx) error {
		return tx.PutOp(learn.OpRecord{RequestID: id, Action: learn.ActionSpam, Done: true,
			Outcome: &learn.OpOutcome{Clusters: []learn.ClusterOutcome{{ClusterID: 2, Result: learn.ResultCommitted}}, Outcome: learn.ResultCommitted, ExitOK: true}})
	}); err != nil {
		t.Fatal(err)
	}
	cl := &ControlListener{d: d}
	args, _ := json.Marshal(control.AntispamLearnStatusArgs{RequestIDs: []string{id}})
	raw, err := cl.handleAntispamLearnStatus(args)
	if err != nil {
		t.Fatal(err)
	}
	res := raw.(control.AntispamLearnStatusResult)
	if len(res.Requests) != 1 || !res.Requests[0].Found || res.Requests[0].Outcome != learn.ResultCommitted ||
		len(res.Requests[0].Clusters) != 1 || res.Requests[0].Clusters[0].ClusterID != 2 {
		t.Fatalf("status %+v", res)
	}
	bad, _ := json.Marshal(control.AntispamLearnStatusArgs{RequestIDs: []string{"not-an-id"}})
	if _, err := cl.handleAntispamLearnStatus(bad); err == nil {
		t.Fatal("malformed request ID accepted")
	}
}
