package firewall

import (
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
)

// recordFirewallAction mirrors a firewall audit entry onto the unified action
// stream. The firewall keeps its own log because the web UI and the API read
// it; this is what lets an operator see firewall changes next to quarantines,
// process kills and mail freezes instead of one file per subsystem.
func recordFirewallAction(action, ip, reason, source string, duration time.Duration) {
	op, actor := firewallActionOp(action, source)
	rec := actionlog.Record{
		Op:     op,
		Actor:  actor,
		Target: ip,
		Reason: reason,
		Result: actionlog.Applied,
	}
	if duration > 0 {
		rec.ActorDetail = "expires in " + duration.String()
	}
	if undo := firewallUndo(action, ip); undo != "" {
		rec.Undo = undo
	}
	actionlog.Write(rec)
}

// firewallActionOp maps an audit entry onto a privileged operation from the
// capability matrix, plus the actor that asked for it.
func firewallActionOp(action, source string) (string, actionlog.Actor) {
	switch source {
	case SourceCLI:
		return "operate.manual_firewall", actionlog.CLI
	case SourceWebUI:
		return "operate.manual_firewall", actionlog.WebUI
	}
	// A whole-ruleset change is the firewall integration, not one decision
	// about one address.
	switch action {
	case "flush", "apply", "restart":
		return "integrate.firewall_ruleset", actionlog.Daemon
	}
	return "respond.block_ip", actionlog.Daemon
}

// firewallUndo names the command that reverses an entry, for the entries where
// a single command does reverse it.
func firewallUndo(action, ip string) string {
	if ip == "" {
		return ""
	}
	switch action {
	case "block", "tempban", "deny_subnet":
		return "csm firewall allow " + ip
	case "allow":
		return "csm firewall deny " + ip
	}
	return ""
}
