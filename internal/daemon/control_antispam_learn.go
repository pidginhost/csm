package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/store"
)

// learnOperatorTimeout ends the wait before the CLI's own; the learner
// keeps the outcome under the request ID either way.
const learnOperatorTimeout = 4 * time.Minute

type learnOperator interface {
	Operator(context.Context, learn.OperatorRequest) (learn.OperatorResult, error)
}

// antispamLearnOperator returns the running learner, or nil; tests replace
// it.
var antispamLearnOperator = func(d *Daemon) learnOperator {
	if r := d.antispamLearner.Load(); r != nil {
		return r.engine
	}
	return nil
}

// handleAntispamLearn runs csm antispam learn for one file (spec 8). Every
// request is recorded in the action log, refusals and failures included,
// with its request ID and digests but never message content.
func (c *ControlListener) handleAntispamLearn(argsRaw json.RawMessage) (any, error) {
	var args control.AntispamLearnArgs
	parseErr := json.Unmarshal(argsRaw, &args)
	name := args.Name
	if name != "" {
		name = filepath.Base(name)
	}
	target, _ := json.Marshal(name)
	rec := actionlog.Record{Op: "integrate.antispam_learn", Action: args.Action, Actor: actionlog.CLI,
		ActorDetail: "csm antispam learn", Target: string(target), Result: actionlog.Refused}
	var res learn.OperatorResult
	var err error
	if parseErr != nil {
		err = fmt.Errorf("%w: malformed learning arguments", errLearnRefused)
	} else {
		res, err = c.antispamLearn(args)
	}
	switch {
	case err != nil:
		if !errors.Is(err, errLearnRefused) {
			rec.Result = actionlog.Failed
		}
		rec.Error = err.Error()
	case res.ExitOK:
		rec.Result = actionlog.Applied
	case res.Outcome == learn.ResultDeferred:
		rec.Error = "deferred: nothing changed"
	default:
		rec.Result = actionlog.Failed
		rec.Error = "outcome " + res.Outcome
	}
	if res.Outcome == "" {
		res.Outcome = string(rec.Result)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			res.Outcome = learn.ResultPending
		}
	}
	rec.Reason = learnReason(args.RequestID, res)
	for _, d := range res.Digests {
		rec.Digests = append(rec.Digests, string(d))
	}
	actionlog.Write(rec)
	if err != nil {
		return nil, err
	}
	out := control.AntispamLearnResult{RequestID: res.RequestID, Outcome: res.Outcome, ExitOK: res.ExitOK}
	for _, cl := range res.Clusters {
		out.Clusters = append(out.Clusters, control.AntispamLearnCluster{ClusterID: cl.ClusterID, Result: cl.Result})
	}
	for _, d := range res.Digests {
		out.Digests = append(out.Digests, string(d))
	}
	return out, nil
}

var errLearnRefused = errors.New("antispam learning refused the request")

func (c *ControlListener) antispamLearn(args control.AntispamLearnArgs) (learn.OperatorResult, error) {
	cfg := c.d.currentCfg()
	switch {
	case cfg.ObserveMode():
		return learn.OperatorResult{}, fmt.Errorf("%w: observe mode does not learn", errLearnRefused)
	case !cfg.EmailProtection.Antispam.Enabled || !cfg.EmailProtection.Antispam.Learning.Enabled:
		return learn.OperatorResult{}, fmt.Errorf("%w: antispam learning is not enabled", errLearnRefused)
	}
	op := antispamLearnOperator(c.d)
	if op == nil {
		return learn.OperatorResult{}, fmt.Errorf("%w: antispam learning is not running; see the antispam_learning findings", errLearnRefused)
	}
	ctx, cancel := context.WithTimeout(context.Background(), learnOperatorTimeout)
	defer cancel()
	res, err := op.Operator(ctx, learn.OperatorRequest{Action: args.Action, RequestID: args.RequestID, Snapshot: args.Snapshot, SnapshotSHA: args.SnapshotSHA})
	if errors.Is(err, learn.ErrLearningOff) {
		err = fmt.Errorf("%w: learning prerequisites are not met; see the antispam_learning findings", errLearnRefused)
	}
	return res, err
}

// learnReason names the request, outcome and clusters. Full digests live
// outside Reason because the file sink bounds free-form explanations.
func learnReason(requestID string, res learn.OperatorResult) string {
	var b strings.Builder
	b.WriteString("request " + requestID)
	if res.Outcome != "" {
		b.WriteString("; outcome " + res.Outcome)
	}
	for _, cl := range res.Clusters {
		if cl.ClusterID == 0 {
			fmt.Fprintf(&b, "; part %s", cl.Result)
		} else {
			fmt.Fprintf(&b, "; cluster %d %s", cl.ClusterID, cl.Result)
		}
	}
	return b.String()
}

// maxStatusRequests bounds one status query.
const maxStatusRequests = 100

// handleAntispamLearnStatus reads recorded outcomes of operator requests
// from the learning ledger, or lists the unfinished ones (spec 8). It reads
// only, so it answers in any mode and with no learner running.
func (c *ControlListener) handleAntispamLearnStatus(argsRaw json.RawMessage) (any, error) {
	var args control.AntispamLearnStatusArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if len(args.RequestIDs) > maxStatusRequests {
		return nil, fmt.Errorf("at most %d request IDs per query", maxStatusRequests)
	}
	for _, id := range args.RequestIDs {
		if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
			return nil, errors.New("a request ID is 32 lowercase hex digits")
		}
	}
	db := store.Global()
	if db == nil {
		return nil, errors.New("the state database is not open")
	}
	statuses, err := learn.RequestStatus(learn.Open(db), args.RequestIDs)
	if err != nil {
		return nil, err
	}
	res := control.AntispamLearnStatusResult{Requests: []control.AntispamLearnStatus{}}
	for _, s := range statuses {
		out := control.AntispamLearnStatus{RequestID: s.RequestID, Action: s.Action, Found: s.Found, Done: s.Done, ExitOK: s.ExitOK, Outcome: s.Outcome}
		for _, d := range s.Digests {
			out.Digests = append(out.Digests, string(d))
		}
		for _, cl := range s.Clusters {
			out.Clusters = append(out.Clusters, control.AntispamLearnStatusCluster{ClusterID: cl.ClusterID, Result: cl.Result, Phase: string(cl.Phase)})
		}
		res.Requests = append(res.Requests, out)
	}
	return res, nil
}
