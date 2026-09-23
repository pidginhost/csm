// Package privops is the inventory of every CSM operation that needs privilege
// beyond reading its own files, or that writes outside CSM's own directories.
//
// It exists so an operator can answer three questions before granting a
// security daemon host-level access: what does it touch, what does each of
// those need root (or a capability) for, and how do I turn any of it off.
// `csm privileges` renders it, docs/src/capability-matrix.md ships the
// rendered form, and gates in internal/ci keep both in step with the systemd
// sandbox that actually constrains the daemon.
package privops

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
)

// Privilege is a capability or credential an operation needs.
type Privilege string

const (
	// Root means the operation needs uid 0 rather than one capability: it
	// reads or writes files owned by many different accounts, or it drives a
	// panel tool that assumes root.
	Root Privilege = "root"
	// CapDACReadSearch is the read side of scanning every account's files.
	CapDACReadSearch Privilege = "CAP_DAC_READ_SEARCH"
	// CapSysAdmin covers fanotify and mount inspection.
	CapSysAdmin Privilege = "CAP_SYS_ADMIN"
	// CapNetAdmin covers nftables mutation.
	CapNetAdmin Privilege = "CAP_NET_ADMIN"
	// CapKill covers signalling processes owned by other accounts.
	CapKill Privilege = "CAP_KILL"
	// CapBPF covers loading and attaching BPF programs.
	CapBPF Privilege = "CAP_BPF"
	// CapPerfmon is required alongside CAP_BPF for tracing and LSM programs.
	CapPerfmon Privilege = "CAP_PERFMON"
	// CapSyslog permits reading a restricted kernel message buffer.
	CapSyslog Privilege = "CAP_SYSLOG"
	// CapAuditControl permits querying and loading kernel audit rules.
	CapAuditControl Privilege = "CAP_AUDIT_CONTROL"
	// CapSysModule permits loading or unloading kernel modules.
	CapSysModule Privilege = "CAP_SYS_MODULE"
	// CapLinuxImmutable permits changing the executable's immutable flag.
	CapLinuxImmutable Privilege = "CAP_LINUX_IMMUTABLE"
	// Unprivileged marks work CSM does inside its own directories.
	Unprivileged Privilege = "none"
)

// KnownPrivileges lists every privilege an operation may declare.
func KnownPrivileges() []Privilege {
	return []Privilege{Root, CapDACReadSearch, CapSysAdmin, CapNetAdmin, CapKill, CapBPF, CapPerfmon, CapSyslog, CapAuditControl, CapSysModule, CapLinuxImmutable, Unprivileged}
}

// Trigger says who starts an operation.
type Trigger string

const (
	// Automatic operations run on the daemon's own schedule or in response to
	// a detection, with no operator in the loop.
	Automatic Trigger = "automatic"
	// Operator operations run only when someone issues a command or clicks a
	// button. Not running the command is how they are turned off.
	Operator Trigger = "operator"
)

// RiskTier is an operation's action-risk tier: what can go wrong if it runs
// on a wrong target. The zero value is unclassified and fails
// TestEveryOperationHasARiskTier.
type RiskTier uint8

const (
	RiskUnclassified RiskTier = iota
	// RiskObserve (tier 0) changes nothing outside CSM's own trees.
	RiskObserve
	// RiskPreview (tier 1) records a recommendation or dry-run decision only.
	// No inventory row currently represents previews separately; rows carry
	// their maximum live effect, even when an execution can be a dry run.
	RiskPreview
	// RiskReversible (tier 2) makes a low-risk host change such as attaching
	// a probe, opening a challenge gate or holding mail. The tier alone
	// does not promise automatic rollback or reversal of incidental writes.
	RiskReversible
	// RiskContain (tier 3) quarantines, blocks or denies one target.
	RiskContain
	// RiskDestructive (tier 4) signals processes, restarts or reloads services,
	// or rewrites content or configuration, including an existing archive.
	RiskDestructive
)

// Number is the tier as the safety model numbers it, 0 to 4, or -1 when the
// operation is unclassified or invalid.
func (r RiskTier) Number() int {
	if r < RiskObserve || r > RiskDestructive {
		return -1
	}
	return int(r) - 1
}

// MarshalJSON uses the same public tier number as the text and Markdown
// views. The internal zero value is an unclassified sentinel, not tier 0.
func (r RiskTier) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprint(r.Number())), nil
}

// UnmarshalJSON translates public tier numbers back to their internal values.
// JSON null leaves the destination unchanged, as it does for other scalars.
func (r *RiskTier) UnmarshalJSON(data []byte) error {
	var number *int
	if err := json.Unmarshal(data, &number); err != nil {
		return err
	}
	if number == nil {
		return nil
	}
	if *number < -1 || *number > RiskDestructive.Number() {
		return fmt.Errorf("invalid risk tier %d", *number)
	}
	*r = RiskTier(*number + 1) // #nosec G115 -- public tiers -1 through 4 map to 0 through 5.
	return nil
}

// SafetyContract describes current authority, identity, recovery and limits.
// It is inventory metadata, not an enforcement mechanism or a claim that
// the full action lifecycle is implemented. Remaining gaps stay explicit.
type SafetyContract struct {
	// Authority is the evidence and opt-ins required before it may run.
	Authority string
	// Identity is how the target is revalidated immediately before the change.
	Identity string
	// Recovery is how the change is reversed, or what it cannot undo.
	Recovery string
	// Limit names current bounds and where they do not apply.
	Limit string
}

// csmOwnedPrefixes are the trees CSM creates and manages for itself. Writing
// inside them is not a host change: an operator who removes CSM removes them.
var csmOwnedPrefixes = []string{
	"/var/lib/csm",
	"/opt/csm",
	"/var/log/csm",
	"/var/log/csm-php-shield",
	"/etc/csm",
	"/var/cache/csm",
	"/var/run/csm",
}

// Op is one privileged or state-changing operation.
type Op struct {
	// ID is stable and namespaced as <subsystem>.<action>. Operators and
	// panel integrations may key on it.
	ID string
	// Subsystem groups related operations in the rendered matrix.
	Subsystem string
	// Summary is one line: what the operation does.
	Summary string
	// Privileges is what the operation needs from the kernel or from uid 0.
	Privileges []Privilege
	// Trigger says whether the daemon starts this on its own.
	Trigger Trigger
	// Writes lists what the operation writes while it runs, including writes
	// made by a tool it invokes. Filesystem paths start with "/"; anything
	// else is a resource written as <kind>:<name>. Empty means read-only.
	Writes []string
	// Unsandboxed marks operations outside the daemon's systemd sandbox:
	// transient services or standalone CLI commands. Mixed operations must
	// have separate rows for their in-daemon writes.
	Unsandboxed bool
	// DisableKey is the config key that stops the operation, and DisableValue
	// the YAML value to give it. An empty key makes no claim of a config switch.
	DisableKey   string
	DisableValue string
	// DisableReason explains why an automatic operation cannot be stopped
	// through config. It must not invent a switch that only stops some callers.
	DisableReason string
	// Audited reports whether the operation writes a record to the action
	// log. False is not a claim that the operation is silent, only that it is
	// not yet on that stream; the daemon log still carries it.
	Audited bool
	// Risk is the operation's action-risk tier.
	Risk RiskTier
	// Contract is the operation's safety contract; nil until its slice of the
	// safety model specifies it.
	Contract *SafetyContract
	// RecoveryGap names recovery work not covered by this inventory's
	// contracts. Required for host-changing operations without a contract.
	RecoveryGap string
	// WithoutPrivilege says what an operator loses by withholding the
	// privilege, so the matrix reads as a decision, not a demand.
	WithoutPrivilege string
}

// ChangesHost reports whether the operation writes outside CSM's own trees.
func (o Op) ChangesHost() bool {
	for _, w := range o.Writes {
		if !strings.HasPrefix(w, "/") {
			return true
		}
		if !csmOwned(w) {
			return true
		}
	}
	return false
}

func csmOwned(name string) bool {
	name = path.Clean(name)
	for _, prefix := range csmOwnedPrefixes {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	return false
}

// Operations returns the inventory, ordered by subsystem then ID.
func Operations() []Op {
	ops := append([]Op(nil), operations...)
	for i := range ops {
		ops[i].Privileges = slices.Clone(ops[i].Privileges)
		ops[i].Writes = slices.Clone(ops[i].Writes)
		if ops[i].Contract != nil {
			c := *ops[i].Contract
			ops[i].Contract = &c
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Subsystem != ops[j].Subsystem {
			return ops[i].Subsystem < ops[j].Subsystem
		}
		return ops[i].ID < ops[j].ID
	})
	return ops
}

// DisableInstruction is shared by terminal and documentation output.
func (o Op) DisableInstruction() string {
	if o.DisableKey != "" {
		return o.DisableKey + ": " + o.DisableValue
	}
	if o.Trigger == Operator {
		return "do not run the command"
	}
	if o.DisableReason != "" {
		return "not configurable: " + o.DisableReason
	}
	return "not configurable"
}

// Markdown renders the inventory as the table shipped in the docs.
func Markdown() string {
	var b strings.Builder
	b.WriteString("| Operation | Needs | Trigger | Risk tier | Writes | Turn it off | Action record | Without the privilege |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, op := range Operations() {
		privs := make([]string, 0, len(op.Privileges))
		for _, p := range op.Privileges {
			privs = append(privs, string(p))
		}
		writes := "nothing (read-only)"
		if len(op.Writes) > 0 {
			writes = strings.Join(op.Writes, ", ")
		}
		if op.Unsandboxed {
			writes += " (outside the systemd sandbox)"
		}
		off := op.DisableInstruction()
		if op.DisableKey != "" {
			off = "`" + off + "`"
		}
		audited := "no"
		if op.Audited {
			audited = "yes"
		}
		fmt.Fprintf(&b, "| `%s`<br>%s | %s | %s | %d | %s | %s | %s | %s |\n",
			op.ID, op.Summary, strings.Join(privs, ", "), op.Trigger, op.Risk.Number(), writes, off, audited, op.WithoutPrivilege)
	}
	return b.String()
}
