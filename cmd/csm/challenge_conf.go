package main

import (
	"fmt"
	"os"
	"regexp"

	"github.com/pidginhost/csm/internal/challenge"
)

// challengeConfSrc / challengeConfDest locate the legacy Apache/LSWS
// challenge snippet: the template shipped with the package and the copy
// the installer deploys. Vars so tests can redirect them to a temp tree.
var challengeConfSrc = "/opt/csm/configs/csm_challenge.conf"
var challengeConfDest = "/etc/apache2/conf.d/csm_challenge.conf"

var challengeMapDirective = regexp.MustCompile(`(?m)^\s*RewriteMap\s+csm_challenge\s+"?txt:([^"\s]+)"?`)

// challengeMapPaths returns every path a "RewriteMap csm_challenge txt:"
// directive in data references.
func challengeMapPaths(data []byte) []string {
	matches := challengeMapDirective.FindAllSubmatch(data, -1)
	paths := make([]string, 0, len(matches))
	for _, m := range matches {
		paths = append(paths, string(m[1]))
	}
	return paths
}

// reconcileChallengeConf re-deploys the legacy challenge snippet when its
// RewriteMap references a map file the daemon does not maintain. Such a
// path makes Apache/LSWS config validation fail host-wide (AH00526) as
// soon as the referenced file goes missing, which once aborted a nightly
// cPanel update and cascaded into mass false mail bans. Binary-swap
// upgrades never re-run the installer, so the daemon repins the snippet at
// startup. Files without the directive, or whose paths already match the
// daemon map, are operator territory and stay untouched.
//
// Returns true when the snippet was rewritten.
func reconcileChallengeConf() bool {
	installed, err := os.ReadFile(challengeConfDest)
	if err != nil {
		return false
	}
	paths := challengeMapPaths(installed)
	if len(paths) == 0 {
		return false
	}
	stale := false
	for _, p := range paths {
		if p != challenge.DefaultMapPath {
			stale = true
		}
	}
	if !stale {
		return false
	}

	// #nosec G304 -- challengeConfSrc is the fixed shipped-template path.
	tmpl, err := os.ReadFile(challengeConfSrc)
	if err != nil {
		return false
	}
	// Refuse a template that would re-install a wrong path (e.g. a stale
	// package left behind by a partial upgrade).
	tmplPaths := challengeMapPaths(tmpl)
	if len(tmplPaths) == 0 {
		return false
	}
	for _, p := range tmplPaths {
		if p != challenge.DefaultMapPath {
			return false
		}
	}

	// #nosec G306 -- Apache conf.d file; the webserver reads it.
	if err := os.WriteFile(challengeConfDest, tmpl, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "challenge: reconcile %s: %v\n", challengeConfDest, err)
		return false
	}
	fmt.Fprintf(os.Stderr, "challenge: re-pinned %s to daemon map path %s\n", challengeConfDest, challenge.DefaultMapPath)
	return true
}
