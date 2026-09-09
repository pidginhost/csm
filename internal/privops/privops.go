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
	"fmt"
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
	// Unprivileged marks work CSM does inside its own directories.
	Unprivileged Privilege = "none"
)

// KnownPrivileges lists every privilege an operation may declare.
func KnownPrivileges() []Privilege {
	return []Privilege{Root, CapDACReadSearch, CapSysAdmin, CapNetAdmin, CapKill, CapBPF, Unprivileged}
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
	// Unsandboxed marks operations that run outside the daemon's systemd
	// sandbox, in a transient unit forked by PID 1, because the tool they
	// drive writes an unbounded set of paths.
	Unsandboxed bool
	// DisableKey is the config key that stops the operation, and DisableValue
	// the value to give it. Required for automatic operations that change
	// host state.
	DisableKey   string
	DisableValue string
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

func csmOwned(path string) bool {
	for _, prefix := range csmOwnedPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// Operations returns the inventory, ordered by subsystem then ID.
func Operations() []Op {
	ops := append([]Op(nil), operations...)
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Subsystem != ops[j].Subsystem {
			return ops[i].Subsystem < ops[j].Subsystem
		}
		return ops[i].ID < ops[j].ID
	})
	return ops
}

// Markdown renders the inventory as the table shipped in the docs.
func Markdown() string {
	var b strings.Builder
	b.WriteString("| Operation | Needs | Trigger | Writes | Turn it off | Without the privilege |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
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
		off := "not configurable"
		switch {
		case op.DisableKey != "":
			off = fmt.Sprintf("`%s: %s`", op.DisableKey, op.DisableValue)
		case op.Trigger == Operator:
			off = "do not run the command"
		}
		fmt.Fprintf(&b, "| `%s`<br>%s | %s | %s | %s | %s | %s |\n",
			op.ID, op.Summary, strings.Join(privs, ", "), op.Trigger, writes, off, op.WithoutPrivilege)
	}
	return b.String()
}
