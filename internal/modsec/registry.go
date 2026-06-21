package modsec

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// Registry maps parsed ModSecurity rule IDs with a decisive disposition to
// that action (deny, drop, block, redirect, proxy, pause, pass, allow).
// Rules with only metadata actions are intentionally absent so callers use
// the unknown-rule default. It is consulted by the LiteSpeed
// log-line classifier - error_log records every match as "triggered!"
// regardless of whether the rule's action denied the request, so the action
// lookup is the only signal that distinguishes a real deny from a noisy
// pass-action informational rule.
type Registry struct {
	actions map[int]string
}

// Action returns the declared action for ruleID and whether it is known.
// An unknown ID is the safe default: callers should treat it as a potential
// block when they have a populated registry but not this specific rule.
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
// Precedence: dirs is treated as most-specific-first. Within a single
// directory, files are walked in lexical order and a duplicate rule ID
// uses last-write-wins, mirroring how ModSecurity itself resolves two
// SecRule directives that share an ID. Across directories, the first
// directory to define a rule keeps it - that way an operator override in
// /etc/apache2/conf.d/modsec_vendor_configs/ is not silently replaced by
// a stale system fallback in /usr/share/modsecurity-crs/rules/.
func BuildRegistry(dirs []string) (*Registry, error) {
	actions := make(map[int]string)
	claimed := make(map[int]struct{})
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		perDirActions := make(map[int]string)
		perDirClaimed := make(map[int]struct{})
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
				perDirClaimed[r.ID] = struct{}{}
				if r.Action != "" {
					perDirActions[r.ID] = r.Action
				} else {
					delete(perDirActions, r.ID)
				}
			}
			return nil
		})
		// Promote the per-directory map into the global map only for IDs
		// that no earlier (more-specific) directory has already claimed.
		for id := range perDirClaimed {
			if _, exists := claimed[id]; !exists {
				claimed[id] = struct{}{}
				action, hasAction := perDirActions[id]
				if !hasAction {
					continue
				}
				actions[id] = action
			}
		}
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

// ReplaceGlobal installs r as the daemon-wide registry, EXCEPT when r is empty
// (or nil) while the currently-installed registry is non-empty: in that case
// the previous registry is kept and false is returned.
//
// The vendor rule tree is transiently empty or unreadable during cPanel's
// nightly modsec_assemble rewrite and during a boot-time web-server
// mis-detection window (a LiteSpeed host probed before lsws has finished
// starting resolves to the wrong rule directories). Replacing a populated
// registry with an empty one would discard known pass and deny actions until
// the next successful refresh.
//
// Refresh callers should use this instead of SetGlobal. Returns true if r was
// installed, false if the previous registry was kept.
func ReplaceGlobal(r *Registry) bool {
	for {
		prev := globalRegistry.Load()
		if r == nil || r.Len() == 0 {
			if prev != nil && prev.Len() > 0 {
				return false
			}
		}
		if globalRegistry.CompareAndSwap(prev, r) {
			return true
		}
	}
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
