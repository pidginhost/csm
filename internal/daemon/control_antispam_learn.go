package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/control"
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
	if e := d.antispamLearner.Load(); e != nil {
		return e
	}
	return nil
}

// handleAntispamLearn runs csm antispam learn for one file (spec 8). Every
// request is recorded in the action log, refusals and failures included,
// with its request ID and digests but never message content.
func (c *ControlListener) handleAntispamLearn(argsRaw json.RawMessage) (any, error) {
	var args control.AntispamLearnArgs
	if err := json.Unmarshal(argsRaw, &args); err != nil {
		return nil, fmt.Errorf("parsing args: %w", err)
	}
	target, _ := json.Marshal(args.Name)
	rec := actionlog.Record{Op: "integrate.antispam_learn", Action: args.Action, Actor: actionlog.CLI,
		ActorDetail: "csm antispam learn", Target: string(target), Result: actionlog.Refused}
	res, err := c.antispamLearn(args)
	rec.Reason = learnReason(args.RequestID, res)
	switch {
	case err != nil:
		if !errors.Is(err, errLearnRefused) {
			rec.Result = actionlog.Failed
		}
		rec.Error = err.Error()
	case res.ExitOK:
		rec.Result = actionlog.Applied
	default:
		rec.Result = actionlog.Failed
		rec.Error = "outcome " + res.Outcome
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

// learnReason names the request, outcome, clusters and full digests.
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
	for _, d := range res.Digests {
		b.WriteString("; digest " + string(d))
	}
	return b.String()
}
