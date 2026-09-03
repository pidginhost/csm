package checks

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
)

// wpInstall is one discovered WordPress installation.
type wpInstall struct {
	// ConfigPath is the wp-config.php file; DocRoot is the directory holding it.
	ConfigPath string
	DocRoot    string
	// Account owns the install, empty when the path is not attributable.
	Account string
	Served  servedState
}

// wpSkipSubstrings keep copies of a site out of discovery. A staging or backup
// tree holds a complete WordPress install, but scanning it means querying a
// database the site does not serve and fixing files nobody reaches.
var wpSkipSubstrings = []string{"/cache/", "/backup", "/staging", "/.trash/"}

// wpDiscovery is one discovery result together with the coverage gap it
// produced. The gap travels with the result so a cached discovery can credit
// every later caller, not only the one that paid for the walk.
type wpDiscovery struct {
	installs     []wpInstall
	panelDomains map[string][]string
	// incomplete records that discovery could not see the whole host. Findings
	// from an incomplete scan must survive the cycle's purge.
	incomplete bool
}

// apply credits the coverage gap to the check that asked for the installs.
// Discovery is shared; completeness is not -- every consumer needs the gap
// recorded under its own name or its findings are purged as if the scan had
// been complete.
func (d wpDiscovery) apply(ctx context.Context, gapCheck string) {
	if !d.incomplete || gapCheck == "" {
		return
	}
	markCheckIncomplete(ctx, gapCheck)
}

// wpInstalls returns every WordPress installation visible to CSM, honouring the
// account scope carried by ctx. gapCheck names the check credited with any
// coverage gap discovery hits.
func wpInstalls(ctx context.Context, gapCheck string) []wpInstall {
	installs, _ := wpInstallsWithDomains(ctx, gapCheck)
	return installs
}

// wpInstallsWithDomains additionally returns the panel's account-to-domain map,
// which the database scan needs for its tenant-boundary checks. The map is nil
// when the panel's own map could not be parsed completely: a partial ownership
// map turns a legitimate domain into a foreign-host finding.
func wpInstallsWithDomains(ctx context.Context, gapCheck string) ([]wpInstall, map[string][]string) {
	d := lookupWPInstalls(ctx, "")
	d.apply(ctx, gapCheck)
	return d.installs, d.panelDomains
}

// wpInstallsForAccount restricts discovery to one account. Fix, drop and
// re-check paths use it: they run outside a scan context but act on the
// account named by the finding they are resolving.
func wpInstallsForAccount(ctx context.Context, gapCheck, account string) []wpInstall {
	if !validAccountName.MatchString(account) {
		return nil
	}
	d := lookupWPInstalls(ctx, account)
	d.apply(ctx, gapCheck)
	return d.installs
}

// lookupWPInstalls is the seam Task 2 replaces with a cycle-scoped cache.
func lookupWPInstalls(ctx context.Context, account string) wpDiscovery {
	return discoverWPInstalls(ctx, account)
}

// discoverWPInstalls merges cPanel's document-root map with a walk of the
// account home layout. Neither source is sufficient alone: the map reaches
// roots no walk can predict, and the walk reaches roots the panel has stopped
// serving but whose database is still live.
func discoverWPInstalls(ctx context.Context, account string) wpDiscovery {
	scope := account
	if scope == "" {
		scope = AccountFromContext(ctx)
	}

	var d wpDiscovery
	seen := make(map[string]bool)
	mappedRoots := make(map[string]bool)
	panelDomains := make(map[string][]string)

	add := func(path, owner string, state servedState, missingIsIncomplete bool) {
		if seen[path] {
			return
		}
		info, err := osFS.Lstat(path)
		if err != nil {
			if missingIsIncomplete || !errors.Is(err, fs.ErrNotExist) {
				d.incomplete = true
			}
			return
		}
		if !info.Mode().IsRegular() {
			d.incomplete = true
			return
		}
		seen[path] = true
		if owner == "" {
			_, owner, _ = accountRootOf(path)
		}
		d.installs = append(d.installs, wpInstall{
			ConfigPath: path,
			DocRoot:    filepath.Dir(path),
			Account:    owner,
			Served:     state,
		})
	}

	// cPanel publishes its actual domain-to-document-root map. It is
	// authoritative for served roots and reaches layouts the home walk below
	// cannot see, so it is consulted first.
	vhostData, vhostErr := osFS.ReadFile(userdataDomainsPath)
	domainMapComplete := false
	switch {
	case vhostErr == nil:
		vhosts, complete := parseUserdataDomainRootsChecked(string(vhostData))
		wildcardVhosts, wildcardComplete := parseWildcardUserdataDomainRootsChecked(string(vhostData))
		vhosts = append(vhosts, wildcardVhosts...)
		domainMapComplete = complete && wildcardComplete && len(vhosts) > 0
		if !domainMapComplete {
			d.incomplete = true
		}
		domainOwners := make(map[string]string, len(vhosts))
		for _, vh := range vhosts {
			root := filepath.Clean(vh.docroot)
			if !docrootBelongsToCPanelUser(root, vh.user) {
				d.incomplete = true
				domainMapComplete = false
				continue
			}
			wildcard := strings.HasPrefix(vh.domain, "*.")
			domain := normalizeHost(strings.TrimPrefix(vh.domain, "*."))
			if domain == "" {
				d.incomplete = true
				domainMapComplete = false
			} else {
				domainKey := domain
				if wildcard {
					domainKey = "*." + domain
				}
				owner, exists := domainOwners[domainKey]
				if exists && owner != vh.user {
					// The map is meant to have one authoritative owner per
					// domain. An ambiguous owner cannot safely support a
					// tenant-boundary check.
					d.incomplete = true
					domainMapComplete = false
				} else if !exists {
					domainOwners[domainKey] = vh.user
					panelDomains[vh.user] = append(panelDomains[vh.user], domainKey)
				}
			}

			if scope != "" && vh.user != scope {
				continue
			}
			wpConfig := filepath.Join(root, "wp-config.php")
			mappedRoots[wpConfig] = true
			add(wpConfig, vh.user, servedByPanel, false)
		}
	case vhostMapFailureIsIncomplete(vhostErr):
		d.incomplete = true
	}
	if domainMapComplete {
		d.panelDomains = panelDomains
	}

	// The served map is not sufficient on its own. A document root the panel
	// has stopped serving still holds a live database, and the compromise this
	// scan was widened for sat in exactly such a root -- absent from the domain
	// map, from /etc/userdomains, and from vhost userdata alike. Re-pointing the
	// domain publishes it again, so the home layout is walked whatever the panel
	// says. Anything the map did not name is not served today, but only when the
	// map could be read at all.
	homeState := notServed
	if !domainMapComplete {
		homeState = servedUnknown
	}
	globScope := scope
	if globScope == "" {
		globScope = "*"
	}
	for _, pattern := range []string{
		filepath.Join(globScope, "public_html", "wp-config.php"),
		filepath.Join(globScope, "public_html", "*", "wp-config.php"),
		filepath.Join(globScope, "*", "wp-config.php"),
	} {
		matches, err := accountHomeGlob(pattern)
		if err != nil {
			d.incomplete = true
		}
		for _, path := range matches {
			if seen[path] || skipWPDiscoveryPath(path) {
				continue
			}
			state := homeState
			if mappedRoots[path] {
				// Preserve the panel's declaration even if the first Lstat
				// failed and the file appeared before the home walk.
				state = servedByPanel
			}
			add(path, "", state, true)
		}
	}
	return d
}

// skipWPDiscoveryPath rejects candidates that are not document roots: account
// data directories, dot-directories, and backup, cache or staging copies.
func skipWPDiscoveryPath(path string) bool {
	dir := filepath.Base(filepath.Dir(path))
	if nonDocRootDirs[dir] || strings.HasPrefix(dir, ".") {
		return true
	}
	for _, skip := range wpSkipSubstrings {
		if strings.Contains(path, skip) {
			return true
		}
	}
	return false
}
