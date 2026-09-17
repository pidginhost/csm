package checks

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// externalScriptHosts returns the hosts of every <script src> in content
// that is neither a known-safe service nor structurally malicious. The
// structural classifier already reports the latter as Critical; the former
// are pre-approved. What remains is an unremarkable external host, which is
// exactly the shape a careful injection takes and which no other signal
// covers.
func externalScriptHosts(content string) []string {
	var hosts []string
	seen := map[string]bool{}
	// A payload stored as JSON carries escaped slashes, which the src
	// grammar does not match; normalise before extracting.
	content = unescapeStoredSlashes(content)
	for _, match := range scriptSrcRe.FindAllStringSubmatch(content, -1) {
		if len(match) < 2 {
			continue
		}
		raw := match[1]
		if isSafeScriptDomain(raw) {
			continue
		}
		if bad, _ := scriptSrcMaliciousReason(raw); bad {
			continue
		}
		normalised := raw
		if strings.HasPrefix(normalised, "//") {
			normalised = "https:" + normalised
		}
		u, err := url.Parse(normalised)
		if err != nil || u == nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	return hosts
}

// newExternalScriptFindings reports, as a Warning, each external script host
// in an option value that firstSeen has not recorded before. Severity stays
// below the auto-response threshold: this is a "look at this" signal, not
// proof of injection.
func newExternalScriptFindings(user string, creds wpDBCreds, prefix, option, value string, firstSeen func(option, host string) bool) []alert.Finding {
	var findings []alert.Finding
	for _, host := range externalScriptHosts(value) {
		if !firstSeen(option, host) {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: alert.Warning,
			Check:    "db_options_new_external_script",
			Message:  fmt.Sprintf("New external script host in wp_options '%s' (account: %s): %s", option, user, host),
			Details: dbContentFindingDetails(creds, prefix,
				fmt.Sprintf("Option: %s", option),
				fmt.Sprintf("Script host: %s", host),
				fmt.Sprintf("Content preview: %s", truncateDB(value, 200)),
				"First appearance of this host since the site's baseline; verify it is a service the site owner added."),
			DedupKey: dbContentDedupKey(user, creds, prefix,
				fmt.Sprintf("Option: %s", option),
				fmt.Sprintf("Script host: %s", host),
				fmt.Sprintf("Content preview: %s", truncateDB(value, 200)),
				"First appearance of this host since the site's baseline; verify it is a service the site owner added."),
		})
	}
	return findings
}

// externalScriptSiteKey identifies one WordPress install's options table in
// the first-seen store.
func externalScriptSiteKey(dbName, prefix string) string {
	return dbName + "|" + prefix
}

// storeFirstSeen adapts the bbolt store to the firstSeen callback; without a
// store nothing is ever new, so the scan stays silent rather than reporting
// every host on every cycle.
func storeFirstSeen(site string) func(option, host string) bool {
	db := store.Global()
	if db == nil {
		return func(string, string) bool { return false }
	}
	return func(option, host string) bool {
		isNew, err := db.MarkExternalScriptSeen(site, option, host, time.Now())
		return err == nil && isNew
	}
}
