package modsec

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	actions     map[int]string
	fingerprint string
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

// Fingerprint identifies the exact file contents used to build the registry.
// Empty means the build was incomplete and must not be cached.
func (r *Registry) Fingerprint() string {
	if r == nil {
		return ""
	}
	return r.fingerprint
}

// BuildRegistry walks every directory in dirs (recursively), parses each
// .conf file, and returns a Registry mapping rule IDs
// to actions. Read and parse errors are returned alongside the usable rules;
// a vendor pack with one malformed file should not blank the whole registry,
// but a refresh must not cache that incomplete build as unchanged.
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
	digest := sha256.New()
	// Read failures and parse failures are not the same for caching. Bytes
	// that could not be read leave the tree unknown, so the build must not be
	// cached. A file that was read in full but cannot be parsed -- a vendor
	// file past the line ceiling, a truncated rule -- produces the same
	// result on every pass, so it must not force a reparse every refresh.
	var readErr, parseErr error
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		perDirActions := make(map[int]string)
		perDirClaimed := make(map[int]struct{})
		fmt.Fprintf(digest, "dir:%q\n", dir)
		walkErr := walkRuleFiles(dir, func(path string) error {
			var rules []Rule
			var fileParseErr error
			fileDigest, err := readRuleFile(path, func(reader io.Reader) error {
				rules, fileParseErr = parseRules(reader)
				// Read the rest even when the parser stopped early, so the
				// digest always describes the whole file and matches what
				// RuleTreeFingerprint computes for the same tree.
				_, drainErr := io.Copy(io.Discard, reader)
				return drainErr
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(digest, "file:%q:%x\n", path, fileDigest)
			if fileParseErr != nil {
				parseErr = errors.Join(parseErr, fmt.Errorf("%s: %w", path, fileParseErr))
			}
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
		readErr = errors.Join(readErr, walkErr)
	}
	reg := &Registry{actions: actions}
	if readErr == nil {
		reg.fingerprint = hex.EncodeToString(digest.Sum(nil))
	}
	return reg, errors.Join(readErr, parseErr)
}

// Both the parser and fingerprint must see the same paths and precedence.
// WalkDir visits files lexically and does not descend into symlinked dirs;
// symlinked .conf files are opened by the visitor, following their targets.
func walkRuleFiles(dir string, visit func(string) error) error {
	var readErr error
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Candidate directories commonly do not exist on this platform.
			// A failure inside an existing tree means the walk is incomplete.
			if path != dir || !errors.Is(err, fs.ErrNotExist) {
				readErr = errors.Join(readErr, err)
			}
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".conf") {
			return nil
		}
		if err := visit(path); err != nil {
			readErr = errors.Join(readErr, fmt.Errorf("%s: %w", path, err))
		}
		return nil
	})
	return errors.Join(readErr, walkErr)
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
