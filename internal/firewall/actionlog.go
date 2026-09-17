package firewall

import (
	"errors"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
)

// recordFirewallAction mirrors successful legacy entries. Paths with multiple
// outcomes record at their public operation boundary instead.
func recordFirewallAction(action, ip, reason, source string, duration time.Duration) {
	recordFirewallResult(action, ip, reason, source, duration, actionlog.Applied, nil)
}

func firewallRecord(action, ip, reason, source string, duration time.Duration) actionlog.Record {
	op, actor := firewallActionOp(action, source)
	rec := actionlog.Record{Op: op, Action: action, Actor: actor, Target: ip, Reason: reason, Result: actionlog.Applied}
	if duration > 0 {
		rec.ActorDetail = "expires in " + duration.String()
	}
	// A block/allow reversal needs the prior state. Creating an allow is not
	// an undo: it also suppresses future automatic blocks for this address.
	return rec
}

func recordFirewallResult(action, ip, reason, source string, duration time.Duration, result actionlog.Result, err error) {
	recordFirewallFindingResult(action, ip, reason, source, duration, result, err, "")
}

func recordFirewallFindingResult(action, ip, reason, source string, duration time.Duration, result actionlog.Result, err error, findingID string) {
	rec := firewallRecord(action, ip, reason, source, duration)
	rec.FindingID = findingID
	rec.Result = result
	if err != nil {
		rec.Error = err.Error()
		rec.Result = actionlog.Failed
		if errors.Is(err, ErrIPProtected) {
			rec.Result = actionlog.Refused
		}
	}
	actionlog.Write(rec)
}

func recordFirewallFailure(action, ip, reason, source string, duration time.Duration, err error) {
	if err != nil {
		recordFirewallResult(action, ip, reason, source, duration, actionlog.Failed, err)
	}
}

func recordBlockOutcome(ip, reason string, duration time.Duration, outcome BlockOutcome, err error, manual bool, findingID string) {
	if !manual && outcome == BlockOutcomeNoop && err == nil {
		return
	}
	rec := firewallRecord("block", ip, reason, InferProvenance("block", reason), duration)
	rec.FindingID = findingID
	rec.Op = "respond.block_ip"
	if manual {
		rec.Op = "operate.manual_firewall"
	}
	switch outcome {
	case BlockOutcomeDryRun:
		rec.Result = actionlog.DryRun
	case BlockOutcomeAllowed, BlockOutcomeAllowlisted:
		rec.Result = actionlog.Refused
	}
	if err != nil {
		rec.Result = actionlog.Failed
		rec.Error = err.Error()
		if errors.Is(err, ErrIPProtected) {
			rec.Result = actionlog.Refused
		}
	}
	actionlog.Write(rec)
}

func firewallActionOp(action, source string) (string, actionlog.Actor) {
	actor := actionlog.DefaultActor()
	switch source {
	case SourceCLI:
		actor = actionlog.CLI
	case SourceWebUI:
		actor = actionlog.WebUI
	}
	switch action {
	case "apply", "restart":
		return "integrate.firewall_ruleset", actor
	}
	if source == SourceCLI || source == SourceWebUI || actor == actionlog.CLI {
		return "operate.manual_firewall", actor
	}
	switch action {
	case "flush", "unblock", "remove_allow", "allow_port", "remove_port_allow", "unblock_subnet":
		return "operate.manual_firewall", actor
	}
	return "respond.block_ip", actor
}
