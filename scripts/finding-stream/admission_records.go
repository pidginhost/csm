package main

import (
	"strings"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/checks"
)

// The admission ledger writes two row forms under respond.block_ip: one
// audit row for each step of an admitted attempt, which names its target by
// the ledger's typed key, and an hourly summary of its decisions, which sets
// count and names no target. Their vocabularies are the ledger's own.

var (
	admissionKinds    = ledgerNames(func(i int) (string, bool) { k := admission.Kind(i); return k.String(), k.Valid() })
	admissionEntries  = ledgerNames(func(i int) (string, bool) { e := admission.Entry(i); return e.String(), e.Valid() })
	admissionRefusals = ledgerNames(func(i int) (string, bool) { r := admission.Reason(i); return r.String(), r.Valid() })
)

// unknown is the fixed summary value for absent or unregistered checks.
// Every other check belongs to the daemon's authoritative registry.
var admissionChecks = func() map[string]bool {
	names := map[string]bool{"unknown": true}
	for _, name := range checks.AllCheckNames() {
		names[name] = true
	}
	return names
}()

// admissionAttemptResults are the steps an audit row records: the
// reservation, the execution and each outcome of an attempt.
var admissionAttemptResults = map[string]bool{
	"reserved": true, "executing": true, "applied": true, "narrowed": true,
	"dry_run": true, "observe": true, "failed": true, "unknown": true,
}

// admissionDecisions are what a summary counts.
var admissionDecisions = map[string]bool{"queued": true, "coalesced": true, "observe": true, "refused": true}

const (
	errSummary       recordError = "record: malformed admission summary"
	errAdmissionStep recordError = "record: admission step without its lane"
)

// ledgerNames collects the names of a ledger enumeration, which starts at 1
// and is contiguous.
func ledgerNames(name func(int) (string, bool)) map[string]bool {
	names := map[string]bool{}
	for i := 1; ; i++ {
		s, ok := name(i)
		if !ok {
			return names
		}
		names[s] = true
	}
}

// admissionLaneReasons are the reason kinds of audit rows: the lane each
// attempt was reserved in. The expiry that follows is dropped.
func admissionLaneReasons() []struct{ prefix, kind string } {
	var out []struct{ prefix, kind string }
	for l := admission.Lane(1); l.Valid(); l++ {
		out = append(out, struct{ prefix, kind string }{l.String() + " lane, expires ", "admission_" + l.String()})
	}
	return out
}

// isAdmissionKey reports whether a respond.block_ip target is the ledger's
// typed key; the firewall writes bare addresses and networks.
func isAdmissionKey(raw string) bool {
	return strings.HasPrefix(raw, "ip:") || strings.HasPrefix(raw, "net:") || strings.HasPrefix(raw, "svc:")
}

func validateAdmissionStep(r actionlog.Record) (parsedTarget, error) {
	if !admissionKinds[r.Action] {
		return parsedTarget{}, errUnknownAction
	}
	if r.Actor != actionlog.Daemon {
		return parsedTarget{}, errUnknownActor
	}
	if !admissionAttemptResults[string(r.Result)] {
		return parsedTarget{}, errUnknownResult
	}
	if r.ActionID == "" || r.ActionVersion == 0 || r.FindingID == "" {
		return parsedTarget{}, errAdmissionStep
	}
	if !strings.HasPrefix(reasonKind(r.Reason), "admission_") {
		return parsedTarget{}, errAdmissionStep
	}
	return parseAdmissionTarget(r.Action, r.Target)
}

// parseAdmissionTarget accepts only a canonical key that fits its kind, as
// the ledger writes it; the ledger's parser refuses any other spelling.
func parseAdmissionTarget(kind, raw string) (parsedTarget, error) {
	t, err := admission.ParseTargetKey(raw, admission.Caps{IPv6: true})
	if err != nil {
		return parsedTarget{}, errTargetAddress
	}
	for k := admission.Kind(1); k.Valid(); k++ {
		if k.String() == kind && admission.ValidateKindTarget(k, t) != nil {
			return parsedTarget{}, errTargetAddress
		}
	}
	p := t.Prefix()
	if svc, ok := t.Service(); ok {
		return parsedTarget{kind: "endpoint", addr: p.Addr(), port: int(svc.Port), proto: svc.Proto.String()}, nil
	}
	if t.IsAddress() {
		return parsedTarget{kind: "ip", addr: p.Addr()}, nil
	}
	return parsedTarget{kind: "cidr", addr: p.Addr(), bits: p.Bits()}, nil
}

// validateSummary checks an hourly summary. It carries the check that asked
// in reason, the entry in actor_detail and a refusal's reason in error, each
// from a closed form, and nothing that names a target, finding or account.
func validateSummary(r actionlog.Record) error {
	switch {
	case r.Op != "respond.block_ip":
		return errSummary
	case !admissionKinds[r.Action]:
		return errUnknownAction
	case r.Actor != actionlog.Daemon:
		return errUnknownActor
	case !admissionDecisions[string(r.Result)]:
		return errUnknownResult
	case r.Target != "" || r.FindingID != "" || r.IncidentID != "" || r.ActionID != "" || r.ActionVersion != 0 ||
		r.UndoOf != "" || r.Account != "" || len(r.Command) > 0 || r.Before != nil || r.After != nil || r.Undo != "" || r.RecoveryPath != "":
		return errSummary
	case !admissionEntries[r.ActorDetail] || !checkName(r.Reason):
		return errSummary
	case (r.Result == actionlog.Refused) != admissionRefusals[r.Error], r.Result != actionlog.Refused && r.Error != "":
		return errSummary
	}
	return nil
}

// checkName accepts only the registered vocabulary and the fixed fallback.
func checkName(s string) bool { return admissionChecks[s] }

// verifySummary holds a transformed summary to the same forms, and treats
// a check that names a learned identity as a leak.
func (a *Anonymizer) verifySummary(o anonAction) bool {
	return o.Op == "respond.block_ip" && admissionKinds[o.Action] && o.Actor == string(actionlog.Daemon) &&
		admissionDecisions[o.Result] && o.Count > 0 && checkName(o.Check) && len(a.leaksIn(o.Check)) == 0 &&
		admissionEntries[o.Entry] && o.ReasonKind == "check" && o.anonTarget == anonTarget{TargetKind: "empty"} &&
		(o.Result == string(actionlog.Refused)) == admissionRefusals[o.Refusal] && o.HasError == (o.Refusal != "") &&
		o.Account == "" && o.ActorIP == "" && o.DurationNS == 0 && o.FindingID == "" && o.IncidentID == "" &&
		o.ActionID == "" && o.ActionVersion == 0 && o.UndoOf == "" && o.BeforeExists == nil && o.AfterExists == nil
}

func admissionTargetKind(kind string) string {
	switch kind {
	case "block_subnet":
		return "cidr"
	case "block_service":
		return "endpoint"
	default:
		return "ip"
	}
}
