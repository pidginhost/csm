package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

// cmsScanRowLimit bounds every non-WordPress CMS content, settings and
// admin query. The WordPress scanner caps each of its selects; these
// adapters used to pull whole tables through the mysql client.
const cmsScanRowLimit = 200

// One extra row distinguishes a complete result at the cap from a truncated
// query. Failed or partial queries must not establish an administrator baseline.
func runCMSQuery(creds wpDBCreds, query string) ([]string, bool) {
	if creds.queryState == nil {
		creds.queryState = new(dbQueryState)
	}
	markIncomplete := func() {
		creds.queryState.failed = true
		creds.queryState.halted = true
		markCheckIncomplete(creds.queryCtx, creds.queryCheck())
	}
	if creds.queryCtx != nil && creds.queryCtx.Err() != nil {
		markIncomplete()
		return nil, false
	}
	rows := runMySQLQuery(creds, fmt.Sprintf("%s LIMIT %d", query, cmsScanRowLimit+1))
	if creds.queryCtx != nil && creds.queryCtx.Err() != nil {
		markIncomplete()
		return nil, false
	}
	if len(rows) > cmsScanRowLimit {
		rows = rows[:cmsScanRowLimit]
		markIncomplete()
	}
	return rows, !creds.queryState.failed
}

// cmsDiscover globs every pattern under every account root and returns the
// unique matches. Installs live under public_html and under addon-domain
// document roots (<home>/<domain>/...), so callers pass both shapes.
func cmsDiscover(ctx context.Context, owner string, patterns ...string) []string {
	var out []string
	for _, p := range patterns {
		for _, root := range accountHomeRoots() {
			if ctx.Err() != nil {
				markCheckIncomplete(ctx, owner)
				return uniqueStrings(out)
			}
			// One root's matches cannot cover another root's discovery error.
			matches, err := osFS.Glob(filepath.Join(root, p))
			if err != nil {
				markCheckIncomplete(ctx, owner)
			}
			out = append(out, matches...)
		}
	}
	return uniqueStrings(out)
}

func rankCMSConfigs(ctx context.Context, owner string, paths []string, maxFiles int) []string {
	ranked := rankPathsByMtimeDesc(ctx, paths, maxFiles)
	if len(ranked) < len(paths) || ctx.Err() != nil {
		markCheckIncomplete(ctx, owner)
	}
	return ranked
}

// cmsAdminFindings reports CMS administrator rows. With a store, the first
// complete pass records every admin id for the install and stays quiet;
// from then on only an id not seen before is reported, once, as a High
// finding. Without a store (ad-hoc runs, tests) it keeps the historical
// per-row visibility Warning. describe renders the message tail and the
// details for one row's tab-separated fields; fields[0] is the id.
func cmsAdminFindings(store *state.Store, cms, check, account string, creds wpDBCreds, rows []string, complete bool, describe func(fields []string) (message, details string)) []alert.Finding {
	for _, row := range rows {
		id, _, _ := strings.Cut(row, "\t")
		if !isAllDigits(id) {
			complete = false
			markCheckIncomplete(creds.queryCtx, creds.queryCheck())
		}
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
	seenIDs := make(map[string]bool, len(rows))
	for _, row := range rows {
		fields := strings.Split(row, "\t")
		if !isAllDigits(fields[0]) || seenIDs[fields[0]] {
			continue
		}
		seenIDs[fields[0]] = true
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
		if complete {
			store.SetRaw(key, "seen")
		}
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
	if store != nil && !baselined && complete {
		store.SetRaw(baselineKey, "1")
	}
	return findings
}
