package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/store"
)

// learningDir holds the learning keys and anchor messages; tests replace
// it.
var learningDir = antispam.DefaultLearningDir

// handleAntispamLearnFresh provisions a fresh learning namespace (spec
// 7.4). With learning disabled it moves the learning directory aside, keys
// and anchors included, and empties the ledger and watcher state, so the
// next enable creates new keys and a new prefix. Nothing is deleted and
// Redis is never flushed; the old directory stays until the operator
// removes it.
func (c *ControlListener) handleAntispamLearnFresh(_ json.RawMessage) (any, error) {
	rec := actionlog.Record{Op: "integrate.antispam_learn", Action: "fresh_namespace", Actor: actionlog.CLI,
		ActorDetail: "csm antispam learn --fresh-namespace", Result: actionlog.Refused}
	res, err := c.d.freshLearningNamespace(time.Now())
	switch {
	case errors.Is(err, errLearnRefused):
		rec.Error = err.Error()
	case err != nil:
		rec.Result, rec.Error = actionlog.Failed, err.Error()
	default:
		rec.Result = actionlog.Applied
	}
	if res.Archived != "" {
		target, _ := json.Marshal(res.Archived)
		rec.Target = string(target)
	}
	actionlog.Write(rec)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (d *Daemon) freshLearningNamespace(now time.Time) (control.AntispamLearnFreshResult, error) {
	// Holding the learner lock keeps a reload from starting a learner
	// against the state being replaced.
	d.antispamLearnerMu.Lock()
	defer d.antispamLearnerMu.Unlock()
	var res control.AntispamLearnFreshResult
	if d.currentCfg().EmailProtection.Antispam.Learning.Enabled || d.antispamLearner.Load() != nil {
		return res, fmt.Errorf("%w: disable antispam learning first", errLearnRefused)
	}
	db := store.Global()
	if db == nil {
		return res, errors.New("the state database is not open")
	}
	// Move the keys first: an emptied ledger next to the old keys would let
	// the next enable resume the old namespace without its records.
	switch _, err := os.Lstat(learningDir); {
	case err == nil:
		archived := learningDir + ".old-" + now.UTC().Format("20060102T150405Z")
		if _, statErr := os.Lstat(archived); !os.IsNotExist(statErr) {
			return res, fmt.Errorf("%s already exists; retry in a second", archived)
		}
		if err = os.Rename(learningDir, archived); err != nil {
			return res, fmt.Errorf("moving the learning directory aside: %w", err)
		}
		res.Archived = archived
	case !os.IsNotExist(err):
		return res, fmt.Errorf("checking the learning directory: %w", err)
	}
	if err := db.ResetLearning(); err != nil {
		return res, fmt.Errorf("clearing learning state: %w", err)
	}
	return res, nil
}
