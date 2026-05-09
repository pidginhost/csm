package modsec

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// Registry maps every parsed ModSecurity rule ID to its declared action
// (deny, drop, block, pass, log, allow). It is consulted by the LiteSpeed
// log-line classifier - error_log records every match as "triggered!"
// regardless of whether the rule's action denied the request, so the action
// lookup is the only signal that distinguishes a real deny from a noisy
// pass-action informational rule.
type Registry struct {
	actions map[int]string
}

// Action returns the declared action for ruleID and whether it is known.
// An unknown ID is the safe default: callers should treat it as a potential
// block to preserve coverage when the rule files have not been parsed yet.
func (r *Registry) Action(ruleID int) (action string, known bool) {
	if r == nil {
		return "", false
	}
	a, ok := r.actions[ruleID]
	return a, ok
}

// Len returns the number of rules in the registry. Useful for startup
// telemetry: zero typically means rule directories are missing.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.actions)
}

// BuildRegistry walks every directory in dirs (recursively), parses each
// .conf file via ParseRulesFileAll, and returns a Registry mapping rule IDs
// to actions. Per-file parse errors are swallowed; a vendor pack with one
// malformed file should not blank the whole registry.
//
// Duplicate IDs across files are resolved last-write-wins, mirroring the
// behaviour of ModSecurity itself when two SecRule directives share an ID
// (the later definition takes effect).
func BuildRegistry(dirs []string) (*Registry, error) {
	actions := make(map[int]string)
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".conf") {
				return nil
			}
			// Per-file parse errors are intentionally discarded so one
			// malformed vendor file (truncated mid-rule, encoding glitch,
			// in-flight modsec_assemble overwrite) does not blank the whole
			// registry. The cost is silent on the leaf package; daemon-side
			// telemetry surfaces the eventual rule count via the startup log.
			rules, _ := ParseRulesFileAll(path)
			for _, r := range rules {
				if r.Action != "" {
					actions[r.ID] = r.Action
				}
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, fs.ErrNotExist) {
			return &Registry{actions: actions}, walkErr
		}
	}
	return &Registry{actions: actions}, nil
}

var globalRegistry atomic.Pointer[Registry]

// SetGlobal installs r as the daemon-wide registry. Callers are expected to
// rebuild and re-set on a refresh interval. Safe for concurrent use.
func SetGlobal(r *Registry) {
	globalRegistry.Store(r)
}

// Global returns the currently installed registry, or nil if none has been
// set yet (e.g. during very early daemon startup, or in unit tests that
// did not seed one). Callers must nil-check.
func Global() *Registry {
	return globalRegistry.Load()
}

// ResetGlobalForTest clears the global registry. Test-only helper.
func ResetGlobalForTest() {
	globalRegistry.Store(nil)
}
