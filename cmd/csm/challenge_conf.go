package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"

	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integration/webserver"
	"github.com/pidginhost/csm/internal/platform"
)

// challengeConfSrc / challengeConfDest locate the legacy Apache/LSWS
// challenge snippet: the template shipped with the package and the copy
// the installer deploys. Vars so tests can redirect them to a temp tree.
var challengeConfSrc = "/opt/csm/configs/csm_challenge.conf"
var challengeConfDest = "/etc/apache2/conf.d/csm_challenge.conf"

var ensureChallengeMapFile = func() error {
	return challenge.EnsureMapFile(challenge.DefaultMapPath)
}

// newWebserverIntegration builds the integration installer for the detected
// webserver. Var so tests can supply one wired to a temp tree.
var newWebserverIntegration = func(cfg *config.Config) (*webserver.Installer, error) {
	return webserver.New(platform.Detect(), cfg)
}

// ensureRuntimeChallengeMap keeps a runtime-directory map present for a
// snippet that still references it. Var so tests can observe the paths.
var ensureRuntimeChallengeMap = challenge.EnsureMapFile

// runtimeChallengeMapRef matches the map paths CSM used to keep under the
// service's runtime directory, which systemd deletes on every stop.
var runtimeChallengeMapRef = regexp.MustCompile(`(?:/var)?/run/csm/challenge_ips(?:\.nginx\.map|\.txt)\b`)

// runtimeChallengeMapPaths returns, sorted and de-duplicated, every
// runtime-directory map path the snippets still reference.
func runtimeChallengeMapPaths(snippets ...[]byte) []string {
	seen := make(map[string]struct{})
	for _, data := range snippets {
		for _, m := range runtimeChallengeMapRef.FindAll(data, -1) {
			seen[string(m)] = struct{}{}
		}
	}
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
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

// prepareChallengeConf makes the webserver's challenge configuration
// consistent with this binary at daemon start: the daemon maps exist, the
// legacy installer snippet points at them, a CSM-managed integration snippet
// from an older template is refreshed, and any snippet that still references
// a runtime-directory map keeps that file present until it is refreshed.
// Reports whether a snippet was rewritten. Errors are joined so one failing
// step never skips the fallback that keeps the webserver validating.
func prepareChallengeConf(cfg *config.Config) (bool, error) {
	var errs []error
	inst, err := newWebserverIntegration(cfg)
	if err != nil {
		inst = nil
		if !errors.Is(err, webserver.ErrUnknownWebserver) {
			errs = append(errs, fmt.Errorf("webserver integration: %w", err))
		}
	}
	snippetPath := ""
	if inst != nil {
		snippetPath = inst.Handler.SnippetPath()
	}

	rewritten := false
	if err := ensureChallengeMapFile(); err != nil {
		// A snippet must never be pointed at a map that does not exist.
		errs = append(errs, fmt.Errorf("ensure daemon map %s: %w", challenge.DefaultMapPath, err))
	} else {
		repinned, err := reconcileChallengeConf()
		if err != nil {
			errs = append(errs, err)
		}
		rewritten = repinned
		if inst != nil {
			refreshed, err := refreshWebserverIntegration(inst)
			if err != nil {
				errs = append(errs, err)
			}
			rewritten = rewritten || refreshed
		}
	}
	if err := keepRuntimeChallengeMaps(challengeConfDest, snippetPath); err != nil {
		errs = append(errs, err)
	}
	return rewritten, errors.Join(errs...)
}

// refreshWebserverIntegration rewrites the integration snippet when it is
// CSM-managed and older than the shipped template, through the installer's
// own configtest-then-reload flow. Missing, current and operator-edited
// snippets are left alone.
func refreshWebserverIntegration(inst *webserver.Installer) (bool, error) {
	path := inst.Handler.SnippetPath()
	status, err := inst.Status()
	if err != nil {
		return false, fmt.Errorf("webserver integration status %s: %w", path, err)
	}
	if status.Status != "stale" {
		return false, nil
	}
	res, err := inst.Upgrade()
	if err != nil {
		return false, fmt.Errorf("webserver integration upgrade %s: %s (fix the cause, then run `csm webserver-integration upgrade`)", path, res.Message)
	}
	fmt.Fprintf(os.Stderr, "challenge: %s %s\n", path, res.Message)
	return true, nil
}

// keepRuntimeChallengeMaps creates, for every snippet that still references a
// map under the runtime directory, that map file. Such a snippet survives when
// it was operator-edited or when refreshing it failed; without the file the
// webserver fails its configtest host-wide.
func keepRuntimeChallengeMaps(snippetPaths ...string) error {
	var bodies [][]byte
	for _, p := range snippetPaths {
		if p == "" {
			continue
		}
		// #nosec G304 -- p is one of the two fixed snippet paths.
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("read snippet %s: %w", p, err)
		}
		bodies = append(bodies, data)
	}
	var errs []error
	for _, path := range runtimeChallengeMapPaths(bodies...) {
		if err := ensureRuntimeChallengeMap(path); err != nil {
			errs = append(errs, fmt.Errorf("keep runtime map %s: %w", path, err))
			continue
		}
		fmt.Fprintf(os.Stderr, "challenge: a webserver snippet still references %s; keeping it until the snippet is refreshed (csm webserver-integration upgrade)\n", path)
	}
	return errors.Join(errs...)
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
