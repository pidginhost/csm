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
	// aliases maps an account's addon domain to its unambiguous cPanel-associated
	// subdomain (and vice versa). A per-vhost disabled flag can be recorded
	// against that servername while the plugin inventory knows the public name.
	aliases map[string][]string
}

// aliasKey scopes an alias set to one account: unrelated accounts may name the
// same docroot path, and one account's disabled flag says nothing about
// another's traffic.
func aliasKey(user, domain string) string {
	return strings.ToLower(strings.TrimSpace(user)) + "\x00" + strings.ToLower(strings.TrimSpace(domain))
}

// vhostAliasSets links only an unambiguous addon/subdomain pair: the docroot
// group must contain exactly those two records and the subdomain must be the
// exact cPanel association <addon-domain>.<main-domain>. A shared docroot is
// not itself proof that two hostnames are aliases: parked domains, a main
// domain, and an addon can all intentionally route different sites from
// /home/<user>/public_html.
func vhostAliasSets(userdataDomains string) map[string][]string {
	vhosts, complete := parseUserdataDomainRootsChecked(userdataDomains)
	if !complete {
		return nil
	}
	byRoot := make(map[string][]vhost, len(vhosts))
	for _, vh := range vhosts {
		root := aliasKey(vh.user, vh.docroot)
		byRoot[root] = append(byRoot[root], vh)
	}
	sets := make(map[string][]string, len(vhosts))
	for _, group := range byRoot {
		if len(group) != 2 {
			continue
		}
		firstType := strings.ToLower(strings.TrimSpace(group[0].typ))
		secondType := strings.ToLower(strings.TrimSpace(group[1].typ))
		var addon, sub vhost
		switch {
		case firstType == "addon" && secondType == "sub":
			addon, sub = group[0], group[1]
		case firstType == "sub" && secondType == "addon":
			addon, sub = group[1], group[0]
		default:
			continue
		}
		mainDomain := cleanDomlogDomain(addon.mainDomain)
		if mainDomain == "" ||
			!strings.EqualFold(cleanDomlogDomain(sub.mainDomain), mainDomain) ||
			!strings.EqualFold(sub.domain, addon.domain+"."+mainDomain) {
			continue
		}
		for _, vh := range group {
			sets[aliasKey(vh.user, vh.domain)] = []string{group[0].domain, group[1].domain}
		}
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

	if strings.TrimSpace(account) == "" {
		return "", ""
	}
	names := c.siteNames(account, domain)
	var accountWide, exact, alias *modsecDisabledScope
	for _, s := range c.disabled {
		if !strings.EqualFold(strings.TrimSpace(s.User), strings.TrimSpace(account)) {
			continue
		}
		if s.Domain == "" {
			if accountWide == nil {
				scope := s
				accountWide = &scope
			}
			continue
		}
		if !names[strings.ToLower(strings.TrimSpace(s.Domain))] {
			continue
		}
		if strings.EqualFold(s.Domain, domain) {
			if exact == nil {
				scope := s
				exact = &scope
			}
			continue
		}
		if alias == nil {
			scope := s
			alias = &scope
		}
	}
	if accountWide != nil {
		return "ModSecurity is disabled for account " + accountWide.User + " (all domains)", accountWide.Source
	}
	if exact != nil {
		return "ModSecurity is disabled for " + exact.Domain, exact.Source
	}
	if alias != nil {
		return fmt.Sprintf("ModSecurity is disabled for %s, the cPanel-associated subdomain of %s", alias.Domain, domain), alias.Source
	}
	return "", ""
}

// annotateUnprotected rewrites vulnerable-plugin findings whose traffic no
// longer passes through ModSecurity, so the alert itself carries the fact that
// nothing stands between the vulnerability and the internet.
//
// Only an active install is rewritten: an inactive plugin is a finding because
// its files sit in the docroot, not because WordPress will run the vulnerable
// code path, so a missing request filter says nothing about its reachability.
// What the annotation claims depends on whether CSM ships a virtual patch for
// the CVE -- naming a patch that was never written would misdescribe the gap.
func annotateUnprotected(matches []vulnMatch, cov vpCoverage) {
	for i := range matches {
		if !matches[i].active {
			continue
		}
		f := &matches[i].finding
		// The production caller passes freshly built findings, but keeping this
		// helper idempotent prevents a retrying caller from changing the alert
		// identity and appending the same operator guidance repeatedly.
		if strings.Contains(f.Message, " -- unprotected: ") ||
			strings.Contains(f.Details, "\n\nUnprotected: ") {
			continue
		}
		reason, source := cov.inertReason(f.TenantID, f.Domain)
		if reason == "" {
			continue
		}
		f.Severity = alert.Critical
		f.Message += " -- unprotected: " + reason
		located := reason
		if source != "" {
			located += " (" + source + ")"
		}
		gap := "No ModSecurity rule filters this traffic and no modsec audit record\n" +
			"is written for it, so an attempt to exploit this leaves no WAF evidence.\n"
		if matches[i].vpCovered {
			gap = "CSM ships a virtual patch for this CVE and it cannot run here, and no\n" +
				"modsec audit record is written for this traffic either, so the\n" +
				"vulnerability is directly reachable and an attempt to exploit it\n" +
				"leaves no WAF evidence.\n"
		}
		f.Details += "\n\nUnprotected: " + located + ".\n" + gap +
			"Patch the plugin now, or restore filtering for this scope first."
	}
}

// vpCoverageForHost is the seam the wiring is tested through: the snapshot it
// returns is assembled from platform detection and host config that a unit
// test cannot stage.
var vpCoverageForHost = currentVPCoverage

// currentVPCoverage reads the live ModSecurity state. Only cPanel receives
// CSM's virtual patches and only cPanel expresses per-vhost ModSecurity
// state, so on every other platform the question has no answer and the
// findings are left untouched.
func currentVPCoverage(findings []alert.Finding) vpCoverage {
	info := platform.Detect()
	if !info.IsCPanel() {
		return vpCoverage{}
	}
	cov := vpCoverage{engineMode: checkEngineMode(info)}
	if data, err := osFS.ReadFile(userdataDomainsPath); err == nil {
		cov.aliases = vhostAliasSets(string(data))
	}
	// CheckWAFStatus already walks every userdata record in this scan tier.
	// Correlation needs only the vulnerable sites, so read their account,
	// domain, and unambiguous associated-subdomain paths instead of repeating the
	// host-wide O(number of vhosts) traversal.
	cov.disabled = modsecDisabledScopesForFindings(info, findings, cov.aliases)
	return cov
}
