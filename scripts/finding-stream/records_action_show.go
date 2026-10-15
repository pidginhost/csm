package main

import "github.com/pidginhost/csm/internal/actionlog"

// Show targets are untrusted lookup references, including malformed input.
// Keep them opaque and separate from lifecycle actions and their join IDs.
func validateActionShow(r actionlog.Record) (parsedTarget, error) {
	if r.Op != "respond.block_ip" || r.Actor != actionlog.CLI || r.ActorDetail != "csm action show" ||
		r.Count != 0 || r.ActionID != "" || r.ActionVersion != 0 || r.FindingID != "" || r.IncidentID != "" || r.UndoOf != "" ||
		r.Account != "" || r.Reason != "" || len(r.Command) != 0 || r.Before != nil || r.After != nil || r.Undo != "" || r.RecoveryPath != "" {
		return parsedTarget{}, errUnknownAction
	}
	if r.Result != "read" && r.Result != actionlog.Failed {
		return parsedTarget{}, errUnknownResult
	}
	if (r.Result == actionlog.Failed) != (r.Error != "") {
		return parsedTarget{}, errUnknownResult
	}
	if r.Target == "" {
		if r.Result != actionlog.Failed {
			return parsedTarget{}, errTargetMissing
		}
		return parsedTarget{kind: "empty"}, nil
	}
	return parseOpaqueTarget(r.Target, "opaque")
}

func (a *Anonymizer) verifyActionShow(o anonAction) bool {
	return o.Op == "respond.block_ip" && o.Actor == string(actionlog.CLI) &&
		(o.Result == "read" || o.Result == string(actionlog.Failed)) &&
		o.HasError == (o.Result == string(actionlog.Failed)) &&
		o.Count == 0 && o.Check == "" && o.Entry == "" && o.Refusal == "" &&
		o.ActionID == "" && o.ActionVersion == 0 && o.FindingID == "" && o.IncidentID == "" && o.UndoOf == "" &&
		o.Account == "" && o.ReasonKind == "empty" && o.ActorIP == "" && o.DurationNS == 0 && o.BeforeExists == nil && o.AfterExists == nil &&
		(o.TargetKind != "empty" || o.Result == string(actionlog.Failed)) &&
		a.validTarget(o.anonTarget, map[string]bool{"opaque": true, "empty": true})
}
