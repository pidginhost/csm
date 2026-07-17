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

var ensureChallengeMapFile = func() error {
	return challenge.EnsureMapFile(challenge.DefaultMapPath)
}

var challengeMapDirective = regexp.MustCompile(`(?m)^[\t ]*(?i:RewriteMap)(?:[\t ]|\\\r?\n)+csm_challenge(?:[\t ]|\\\r?\n)+(?:"txt:([^"\r\n]+)"|'txt:([^'\r\n]+)'|txt:([^\t \r\n]+))(?:[\t \r]|$)`)

// challengeMapPaths returns every path a "RewriteMap csm_challenge txt:"
// directive in data references.
func challengeMapPaths(data []byte) []string {
	matches := challengeMapDirective.FindAllSubmatch(data, -1)
	paths := make([]string, 0, len(matches))
	for _, m := range matches {
		for _, path := range m[1:] {
			if len(path) != 0 {
				paths = append(paths, string(path))
				break
			}
		}
	}
	return paths
}

func prepareChallengeConf() (bool, error) {
	if err := ensureChallengeMapFile(); err != nil {
		return false, fmt.Errorf("ensure daemon map %s: %w", challenge.DefaultMapPath, err)
	}
	return reconcileChallengeConf()
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
func reconcileChallengeConf() (bool, error) {
	// #nosec G304 -- challengeConfDest is the fixed legacy Apache path.
	installed, err := os.ReadFile(challengeConfDest)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read installed snippet %s: %w", challengeConfDest, err)
	}
	paths := challengeMapPaths(installed)
	if len(paths) == 0 {
		return false, nil
	}
	stale := false
	for _, p := range paths {
		if p != challenge.DefaultMapPath {
			stale = true
		}
	}

	var tmpl []byte
	if stale {
		// #nosec G304 -- challengeConfSrc is the fixed shipped-template path.
		tmpl, err = os.ReadFile(challengeConfSrc)
		if err != nil {
			return false, fmt.Errorf("read shipped template %s: %w", challengeConfSrc, err)
		}
		// Refuse a template that would re-install a wrong path (e.g. a stale
		// package left behind by a partial upgrade).
		tmplPaths := challengeMapPaths(tmpl)
		if len(tmplPaths) == 0 {
			return false, fmt.Errorf("shipped template %s has no challenge RewriteMap", challengeConfSrc)
		}
		for _, p := range tmplPaths {
			if p != challenge.DefaultMapPath {
				return false, fmt.Errorf("shipped template %s points at unsupported map %s", challengeConfSrc, p)
			}
		}
	}

	if !stale {
		return false, nil
	}

	if err := writeFileAtomic(challengeConfDest, tmpl, 0o644); err != nil {
		return false, fmt.Errorf("replace installed snippet %s: %w", challengeConfDest, err)
	}
	fmt.Fprintf(os.Stderr, "challenge: re-pinned %s to daemon map path %s\n", challengeConfDest, challenge.DefaultMapPath)
	return true, nil
}
