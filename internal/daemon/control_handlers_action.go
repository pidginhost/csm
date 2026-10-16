package daemon

import (
	"encoding/json"
	"errors"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/control"
)

// handleActionShow returns one admitted candidate and its attempts from
// the admission owner.
func (c *ControlListener) handleActionShow(argsRaw json.RawMessage) (result any, err error) {
	var args control.ActionShowArgs
	defer func() { recordActionShow(args.ID, err) }()
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, err
		}
	}
	if c.d == nil || c.d.admission == nil {
		return nil, errors.New("admission is not running")
	}
	return c.d.admission.Action(args.ID)
}

// Reads are operator operations too (spec 6). Keep their audit outside the
// owner and its outbox so an audit outage cannot disable a diagnostic read.
func recordActionShow(ref string, err error) {
	record := actionlog.Record{
		Op: "respond.block_ip", Action: "show", Actor: actionlog.CLI,
		ActorDetail: "csm action show", Target: ref, Result: "read",
	}
	if err != nil {
		record.Result, record.Error = actionlog.Failed, err.Error()
	}
	actionlog.Write(record)
}
