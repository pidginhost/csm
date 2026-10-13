package antispam

import (
	"encoding/json"
	"slices"
	"strings"
)

// CodeRspamdConfig reports rspamd's loaded settings defeating CSM's files.
const CodeRspamdConfig = "rspamd_config"

// Action is what reconcile does next (spec section 6.1).
type Action int

const (
	// Keep changes nothing: the host matches the configuration, or a
	// problem prevents a safe change.
	Keep Action = iota
	// Install applies CSM's integration for the configured settings.
	Install
	// Uninstall removes CSM's integration.
	Uninstall
)

// Assessment is reconcile's view of one host.
type Assessment struct {
	Action Action
	// Installed is true when any CSM file, block or record is on the host.
	Installed bool
	// Problems are reported whatever the action.
	Problems []Problem
}

// Assess decides what reconcile does (spec sections 6.1 and 6.5). For a
// disabled integration f needs only Targets, GeneratedConf and Record, as
// hostfacts.CollectInstalled reads them; enabled, f is a full collection.
func Assess(enabled bool, s Settings, f HostFacts) Assessment {
	a := Assessment{Installed: leftovers(f)}
	if !enabled {
		if !a.Installed {
			return a
		}
		a.Problems = CheckRemoval(f.Targets)
		if !blocking(a.Problems) {
			a.Action = Uninstall
		}
		return a
	}
	a.Problems = CheckHost(f)
	isCurrent := a.Installed && current(s, f)
	if isCurrent {
		// A temporary host probe failure cannot hide a confirmed override.
		a.Problems = append(a.Problems, loadedConflicts(s, f)...)
	}
	switch {
	case hasSeverity(a.Problems, Definite):
		a.uninstall(f)
	case hasSeverity(a.Problems, Temporary):
		return a
	case !isCurrent:
		// Replacing a shared block must be just as safe as removing it.
		if removal := CheckRemoval(f.Targets); blocking(removal) {
			a.report(removal)
			return a
		}
		a.Action = Install
	}
	return a
}

// uninstall removes an installation when CSM can edit every file safely,
// and otherwise reports why it cannot.
func (a *Assessment) uninstall(f HostFacts) {
	if !a.Installed {
		return
	}
	removal := CheckRemoval(f.Targets)
	if blocking(removal) {
		a.report(removal)
		return
	}
	a.Action = Uninstall
}

// report adds the problems not already reported: CheckHost and
// CheckRemoval share the path rules.
func (a *Assessment) report(problems []Problem) {
	for _, p := range problems {
		if !slices.Contains(a.Problems, p) {
			a.Problems = append(a.Problems, p)
		}
	}
}

// leftovers reports whether any part of CSM's integration is on the host.
// An unreadable record counts: only a remove can settle it.
func leftovers(f HostFacts) bool {
	if !f.Record.Missing || hasMarker(f.GeneratedConf) {
		return true
	}
	for _, t := range f.Targets {
		if t.Kind == TargetRspamd && IsManaged(t.Content) || t.Kind != TargetRspamd && hasMarker(t.Content) {
			return true
		}
	}
	return false
}

func hasMarker(s string) bool {
	return strings.Contains(s, MarkerBegin) || strings.Contains(s, MarkerEnd)
}

// current reports whether the host holds exactly s: CSM's files, a
// completed record for them, and the hooks active in the generated
// configuration.
func current(s Settings, f HostFacts) bool {
	managed, err := ManagedContent(s)
	if err != nil {
		return false
	}
	want := Generation(managed)
	if Generation(InstalledContent(f.Targets)) != want || f.Record.Err != nil {
		return false
	}
	r, err := DecodeRecord([]byte(f.Record.Content))
	if err != nil || !r.Complete() || *r.Generation != want {
		return false
	}
	hooks, err := RenderExim(s)
	if err != nil || f.GeneratedErr != nil || f.EximSettings.Err != nil {
		return false
	}
	opts := ParseEximOptions(f.EximSettings.Stdout)
	return CheckGenerated(f.GeneratedConf, hooks, opts["acl_smtp_rcpt"], opts["acl_smtp_data"]) == nil
}

// loadedConflicts compares the settings rspamd loaded with CSM's files,
// as the apply transaction does after staging them.
func loadedConflicts(s Settings, f HostFacts) []Problem {
	var out []Problem
	var conflicts []string
	unreadable := false
	modules, err := EnabledModules(f.RspamdModules.Stdout)
	if f.RspamdModules.Err != nil || err != nil {
		unreadable = true
	} else {
		conflicts = append(conflicts, checkRspamdModules(modules)...)
	}
	data := []byte(f.RspamdActions.Stdout)
	if f.RspamdActions.Err != nil || !json.Valid(data) {
		unreadable = true
	} else if actions, err := ParseActions(data); err != nil {
		out = append(out, Problem{Code: CodeRspamdConfig, Severity: Definite,
			Detail: "rspamd actions use a form CSM cannot compare; set them only through CSM's local.d/actions.conf"})
	} else {
		conflicts = append(conflicts, checkRspamdActions(actions, s)...)
	}
	for _, c := range conflicts {
		out = append(out, Problem{Code: CodeRspamdConfig, Severity: Definite, Detail: c})
	}
	if unreadable {
		out = append(out, Problem{Code: CodeRspamdConfig, Severity: Temporary,
			Detail: "cannot read the settings rspamd loaded; check rspamadm configdump"})
	}
	return out
}

func hasSeverity(problems []Problem, sev Severity) bool {
	for _, p := range problems {
		if p.Severity == sev {
			return true
		}
	}
	return false
}

// blocking reports a problem that stops a change.
func blocking(problems []Problem) bool {
	return hasSeverity(problems, Definite) || hasSeverity(problems, Temporary)
}
