package checks

import (
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/platform"
)

// Correlation between a known-vulnerable plugin and the compensating control
// that is supposed to hold the line until it is patched.
//
// CSM ships ModSecurity virtual patches for several of the CVEs in the plugin
// feed, so a vulnerable install is normally filtered while the operator
// schedules an update. When ModSecurity is off for that traffic the patch never
// executes, and the same finding now describes a directly reachable
// vulnerability. Reported separately, the two facts read as routine
// housekeeping; joined, they are an emergency.
//
// This adds no new detection: both inputs are findings CSM already produces.

// vpCoverage is the state that decides whether CSM's shipped virtual patches
// filter a given site.
type vpCoverage struct {
	// engineMode is the host-wide SecRuleEngine value ("on", "detectiononly",
	// "off"), empty when it could not be read.
	engineMode string
	// disabled lists the accounts and vhosts with ModSecurity switched off.
	disabled []modsecDisabledScope
	// aliases maps an account's domain to every other domain of that account
	// served from the same docroot. A per-vhost disabled flag is recorded
	// against the servername, while the plugin inventory knows the site by
	// whichever name resolves to its docroot, so the two rarely match by
	// string.
	aliases map[string][]string
}

// aliasKey scopes an alias set to one account: unrelated accounts may name the
// same docroot path, and one account's disabled flag says nothing about
// another's traffic.
func aliasKey(user, domain string) string {
	return strings.ToLower(strings.TrimSpace(user)) + "\x00" + strings.ToLower(strings.TrimSpace(domain))
}

// vhostAliasSets groups every domain of an account by the docroot it serves,
// so a name can be resolved to all the other names the same site answers to.
func vhostAliasSets(userdataDomains string) map[string][]string {
	vhosts, _ := parseUserdataDomainRootsChecked(userdataDomains)
	byRoot := make(map[string][]string, len(vhosts))
	for _, vh := range vhosts {
		root := aliasKey(vh.user, vh.docroot)
		byRoot[root] = append(byRoot[root], vh.domain)
	}
	sets := make(map[string][]string, len(vhosts))
	for _, vh := range vhosts {
		sets[aliasKey(vh.user, vh.domain)] = byRoot[aliasKey(vh.user, vh.docroot)]
	}
	return sets
}

// siteNames is every domain the site answers to: the one the inventory
// recorded plus its docroot peers.
func (c vpCoverage) siteNames(account, domain string) map[string]bool {
	names := map[string]bool{strings.ToLower(strings.TrimSpace(domain)): true}
	for _, peer := range c.aliases[aliasKey(account, domain)] {
		names[strings.ToLower(strings.TrimSpace(peer))] = true
	}
	delete(names, "")
	return names
}

// inertReason explains why CSM's virtual patches do not filter this site, or
// returns an empty reason when they do.
func (c vpCoverage) inertReason(account, domain string) (reason, source string) {
	switch strings.ToLower(strings.TrimSpace(c.engineMode)) {
	case "off":
		return "the ModSecurity engine is off host-wide", ""
	case "detectiononly":
		return "the ModSecurity engine runs in DetectionOnly mode host-wide", ""
	}

	names := c.siteNames(account, domain)
	for _, s := range c.disabled {
		if s.Domain == "" {
			if account != "" && strings.EqualFold(s.User, account) {
				return "ModSecurity is disabled for account " + s.User + " (all domains)", s.Source
			}
			continue
		}
		if !names[strings.ToLower(strings.TrimSpace(s.Domain))] {
			continue
		}
		if strings.EqualFold(s.Domain, domain) {
			return "ModSecurity is disabled for " + s.Domain, s.Source
		}
		return fmt.Sprintf("ModSecurity is disabled for %s, an alias of %s serving the same docroot", s.Domain, domain), s.Source
	}
	return "", ""
}

// annotateUnprotected rewrites vulnerable-plugin findings whose traffic no
// longer passes through ModSecurity, so the alert itself carries the fact that
// nothing stands between the vulnerability and the internet.
func annotateUnprotected(findings []alert.Finding, cov vpCoverage) []alert.Finding {
	for i := range findings {
		reason, source := cov.inertReason(findings[i].TenantID, findings[i].Domain)
		if reason == "" {
			continue
		}
		findings[i].Severity = alert.Critical
		findings[i].Message += " -- unprotected: " + reason
		located := reason
		if source != "" {
			located += " (" + source + ")"
		}
		findings[i].Details += "\n\nUnprotected: " + located + ".\n" +
			"CSM's shipped virtual patches never run on this traffic and no modsec\n" +
			"audit record is written for it, so this vulnerability is directly\n" +
			"reachable and an attempt to exploit it leaves no WAF evidence.\n" +
			"Patch the plugin now, or restore filtering for this scope first."
	}
	return findings
}

// vpCoverageForHost is the seam the wiring is tested through: the snapshot it
// returns is assembled from platform detection and host config that a unit
// test cannot stage.
var vpCoverageForHost = currentVPCoverage

// currentVPCoverage reads the live ModSecurity state. Only cPanel receives
// CSM's virtual patches and only cPanel expresses per-vhost ModSecurity
// state, so on every other platform the question has no answer and the
// findings are left untouched.
func currentVPCoverage() vpCoverage {
	info := platform.Detect()
	if !info.IsCPanel() {
		return vpCoverage{}
	}
	cov := vpCoverage{
		engineMode: checkEngineMode(info),
		disabled:   modsecDisabledScopes(info),
	}
	if data, err := osFS.ReadFile(userdataDomainsPath); err == nil {
		cov.aliases = vhostAliasSets(string(data))
	}
	return cov
}
