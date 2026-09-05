package checks

import (
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

// cmsScanRowLimit bounds every non-WordPress CMS content, settings and
// admin query. The WordPress scanner caps each of its selects; these
// adapters used to pull whole tables through the mysql client.
const cmsScanRowLimit = 200

// withRowLimit appends the scan cap to a query that has none.
func withRowLimit(query string) string {
	if strings.Contains(strings.ToUpper(query), " LIMIT ") {
		return query
	}
	return fmt.Sprintf("%s LIMIT %d", strings.TrimSpace(query), cmsScanRowLimit)
}

// cmsDiscover globs every pattern under every account root and returns the
// unique matches. Installs live under public_html and under addon-domain
// document roots (<home>/<domain>/...), so callers pass both shapes.
func cmsDiscover(patterns ...string) []string {
	var out []string
	for _, p := range patterns {
		matches, _ := accountHomeGlob(p)
		out = append(out, matches...)
	}
	return uniqueStrings(out)
}

// cmsAdminFindings reports CMS administrator rows. With a store, the first
// complete pass records every admin id for the install and stays quiet;
// from then on only an id not seen before is reported, once, as a High
// finding. Without a store (ad-hoc runs, tests) it keeps the historical
// per-row visibility Warning. describe renders the message tail and the
// details for one row's tab-separated fields; fields[0] is the id.
func cmsAdminFindings(store *state.Store, cms, check, account string, creds wpDBCreds, rows []string, describe func(fields []string) (message, details string)) []alert.Finding {
	if len(rows) == 0 {
		return nil
	}
	var findings []alert.Finding
	// Account-wide keys cannot establish which installation supplied an id.
	// Each database and prefix gets a fresh baseline after the key migration.
	siteKey := dbContentDedupKey(account, creds, creds.tablePrefix, "cms-admin="+cms)
	baselineKey := "_cmsadmin_baseline:v2:" + siteKey
	baselined := false
	if store != nil {
		_, baselined = store.GetRaw(baselineKey)
	}
	for _, row := range rows {
		fields := strings.Split(row, "\t")
		if len(fields) < 1 || fields[0] == "" {
			continue
		}
		message, details := describe(fields)
		details = dbContentFindingDetails(creds, creds.tablePrefix,
			"Database host: "+creds.dbHost, details)
		dedupKey := dbContentDedupKey(account, creds, creds.tablePrefix, "cms-admin="+cms, "id="+fields[0])
		if store == nil {
			findings = append(findings, alert.Finding{
				Severity: alert.Warning,
				Check:    check,
				Message:  message,
				Details:  details,
				DedupKey: dedupKey,
			})
			continue
		}
		key := "_cmsadmin:v2:" + dedupKey
		if _, seen := store.GetRaw(key); seen {
			continue
		}
		store.SetRaw(key, "seen")
		if !baselined {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    check,
			Message:  "New " + message,
			Details:  details + "\nThis administrator was not present when the install was baselined.",
			DedupKey: dedupKey,
		})
	}
	if store != nil && !baselined {
		store.SetRaw(baselineKey, "1")
	}
	return findings
}
