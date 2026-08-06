package checks

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/platform"
)

// modsecDisabledScope is one place where ModSecurity is switched off for
// customer traffic. Domain is empty when the scope covers every vhost of
// the account.
type modsecDisabledScope struct {
	User   string
	Domain string
	Source string
}

// modsecDisabledScopes reports every vhost or account with ModSecurity
// turned off. A disabled scope voids every CSM virtual patch for that
// traffic and writes nothing to the modsec audit log, so an attack there
// is both unblocked and invisible.
//
// cPanel expresses "off" through several independent mechanisms and an
// audit of any one of them badly understates the exposure, so all of them
// are walked:
//
//   - secruleengineoff in /var/cpanel/userdata (per domain)
//   - modsec.conf under conf.d/userdata (per account, and per domain)
//
// The conf.d tree is mirrored into std and ssl. Because virtually all
// traffic is HTTPS, a scope present only under ssl still leaves the site
// unfiltered, so both trees carry equal weight here.
func modsecDisabledScopes(info platform.Info) []modsecDisabledScope {
	if !info.IsCPanel() {
		return nil
	}

	var scopes []modsecDisabledScope
	scopes = append(scopes, userdataDisabledScopes()...)
	scopes = append(scopes, confTreeDisabledScopes(info)...)
	return dedupeScopes(scopes)
}

// userdataDisabledScopes walks the per-domain userdata flag. cPanel keeps
// <domain>, <domain>_SSL and <domain>.cache copies of the same record, so
// the domain name is normalised and duplicates collapse later.
func userdataDisabledScopes() []modsecDisabledScope {
	var scopes []modsecDisabledScope
	for _, path := range globPaths("/var/cpanel/userdata/*/*") {
		name := filepath.Base(path)
		if strings.HasSuffix(name, ".cache") {
			continue
		}
		data, err := osFS.ReadFile(path)
		if err != nil || !userdataSecRuleEngineOff(string(data)) {
			continue
		}
		scopes = append(scopes, modsecDisabledScope{
			User:   filepath.Base(filepath.Dir(path)),
			Domain: strings.TrimSuffix(name, "_SSL"),
			Source: path,
		})
	}
	return scopes
}

// confTreeDisabledScopes walks the Apache userdata include tree, where a
// modsec.conf directly under the account directory disables every vhost
// the account owns and one a level deeper disables a single domain.
func confTreeDisabledScopes(info platform.Info) []modsecDisabledScope {
	if info.ApacheConfigDir == "" {
		return nil
	}

	var scopes []modsecDisabledScope
	for _, tree := range []string{"std", "ssl"} {
		base := filepath.Join(info.ApacheConfigDir, "conf.d", "userdata", tree, "2_4")

		for _, path := range globPaths(filepath.Join(base, "*", "modsec.conf")) {
			if !confSecRuleEngineOff(path) {
				continue
			}
			scopes = append(scopes, modsecDisabledScope{
				User:   filepath.Base(filepath.Dir(path)),
				Source: path,
			})
		}

		for _, path := range globPaths(filepath.Join(base, "*", "*", "modsec.conf")) {
			if !confSecRuleEngineOff(path) {
				continue
			}
			domainDir := filepath.Dir(path)
			scopes = append(scopes, modsecDisabledScope{
				User:   filepath.Base(filepath.Dir(domainDir)),
				Domain: filepath.Base(domainDir),
				Source: path,
			})
		}
	}
	return scopes
}

func confSecRuleEngineOff(path string) bool {
	data, err := osFS.ReadFile(path)
	if err != nil {
		return false
	}
	return secRuleEngineOffDirective(string(data))
}

// dedupeScopes collapses the several files that can describe one scope
// into a single entry, keeping the lowest-sorting source so the reported
// path is stable across runs.
func dedupeScopes(scopes []modsecDisabledScope) []modsecDisabledScope {
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].User != scopes[j].User {
			return scopes[i].User < scopes[j].User
		}
		if scopes[i].Domain != scopes[j].Domain {
			return scopes[i].Domain < scopes[j].Domain
		}
		return scopes[i].Source < scopes[j].Source
	})

	var out []modsecDisabledScope
	seen := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		key := s.User + "\x00" + s.Domain
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

// globPaths expands a pattern, discarding the error: a malformed pattern
// is a programming bug and an unreadable directory simply yields nothing.
func globPaths(pattern string) []string {
	matches, err := osFS.Glob(pattern)
	if err != nil {
		return nil
	}
	return matches
}

// userdataSecRuleEngineOff reports whether a cPanel userdata file carries
// the per-domain "ModSecurity off" flag. cPanel writes secruleengineoff: 0
// for the enabled state, so presence of the key is not enough.
func userdataSecRuleEngineOff(contents string) bool {
	for _, line := range strings.Split(contents, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || strings.TrimSpace(key) != "secruleengineoff" {
			continue
		}
		if strings.TrimSpace(value) == "1" {
			return true
		}
	}
	return false
}

// secRuleEngineOffDirective reports whether an Apache config fragment
// turns the engine off. Files that only carry SecRuleRemoveById lines are
// legitimate false-positive workarounds and leave the engine running.
func secRuleEngineOffDirective(contents string) bool {
	for _, line := range strings.Split(contents, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if strings.EqualFold(fields[0], "SecRuleEngine") && strings.EqualFold(fields[1], "Off") {
			return true
		}
	}
	return false
}

// modsecDisabledDetailCap bounds how many scopes are named in the finding
// details. The count in the message always reflects the true total.
const modsecDisabledDetailCap = 20

// modsecDisabledFindings reports disabled ModSecurity scopes as a single
// aggregated finding. Hosts routinely accumulate hundreds of these over
// the years, so one finding per scope would drown every other alert.
func modsecDisabledFindings(info platform.Info) []alert.Finding {
	scopes := modsecDisabledScopes(info)
	if len(scopes) == 0 {
		return nil
	}

	var accounts, domains int
	var b strings.Builder
	for i, s := range scopes {
		if s.Domain == "" {
			accounts++
		} else {
			domains++
		}
		if i < modsecDisabledDetailCap {
			target := s.Domain
			if target == "" {
				target = "account " + s.User + " (all domains)"
			}
			b.WriteString("  " + target + " -- " + s.Source + "\n")
		}
	}
	if len(scopes) > modsecDisabledDetailCap {
		fmt.Fprintf(&b, "  ... and %d more\n", len(scopes)-modsecDisabledDetailCap)
	}

	return []alert.Finding{{
		Severity: alert.High,
		Check:    "modsec_disabled_vhost",
		Message: fmt.Sprintf("ModSecurity is disabled for %d scopes (%d account-wide, %d single-domain)",
			len(scopes), accounts, domains),
		Details: "Every CSM virtual patch is inert on this traffic and no modsec audit\n" +
			"record is written, so attacks there are both unblocked and invisible.\n\n" +
			b.String() +
			"\nRe-enable per domain with:\n" +
			"  /usr/local/cpanel/bin/modsecuritydomains enable --domain=<domain>\n" +
			"That tool only rewrites the userdata flag. Account-wide and per-domain\n" +
			"modsec.conf files must be edited directly in BOTH the std and ssl\n" +
			"userdata trees, then rebuild the web server config. Keep any\n" +
			"SecRuleRemoveById lines already present -- those are rule exclusions,\n" +
			"not an engine switch.",
	}}
}
