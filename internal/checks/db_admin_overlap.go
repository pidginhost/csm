package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// adminEmailRetention bounds how far back an admin observation stays
// relevant for overlap detection. A contractor email seen six months
// ago on one account and never since is not actionable signal -- the
// access likely lapsed. The window is a deliberate balance against the
// alternative of evicting on every scan, which would lose overlaps when
// scans run asynchronously across customer accounts.
const adminEmailRetention = 90 * 24 * time.Hour

// adminEmailDefaultMinAccounts is the default threshold for emitting
// the cross-account overlap finding. Matches the most common
// compromise pattern on shared hosting: a contractor administering two
// or more customer cPanels.
const adminEmailDefaultMinAccounts = 2

// CheckAdminEmailOverlap records every WordPress administrator email
// encountered during an account scan into a server-wide bbolt bucket,
// then emits a Warning finding for each email whose owner list now
// spans the configured minimum number of distinct accounts. The
// detection surface is shared-hosting credential leakage: a single
// compromised contractor account is one credential disclosure away
// from administrator access on every site they touch.
//
// The check is silent when the bbolt store is unavailable (early
// daemon startup, test harness without state injection) -- it can't
// observe overlap without persistence between scans, and falling
// silent is better than a misleading partial result.
func CheckAdminEmailOverlap(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	db := store.Global()
	if db == nil {
		return nil
	}
	now := time.Now()

	wpConfigs, _ := osFS.Glob("/home/*/public_html/wp-config.php")
	for _, wpConfig := range wpConfigs {
		if ctx.Err() != nil {
			return nil
		}
		account := extractUser(filepath.Dir(wpConfig))
		creds := parseWPConfig(wpConfig)
		if creds.dbName == "" {
			continue
		}
		prefix := creds.tablePrefix
		if prefix == "" {
			prefix = "wp_"
		}
		if !validTablePrefix.MatchString(prefix) {
			continue
		}
		for _, email := range adminEmailsForSite(creds, prefix) {
			_ = db.RecordAdminEmail(email, account, creds.dbName, now)
		}
	}

	min := adminEmailDefaultMinAccounts
	if cfg != nil && cfg.Detection.AdminOverlapMinAccounts > 0 {
		min = cfg.Detection.AdminOverlapMinAccounts
	}
	overlaps, err := db.OverlappingAdminEmails(min, adminEmailRetention)
	if err != nil || len(overlaps) == 0 {
		return nil
	}
	return buildAdminOverlapFindings(overlaps)
}

// adminEmailsForSite returns the lowercase admin emails currently
// configured on the WordPress site. Uses the existing root-MySQL
// helper so it works on cPanel hosts where wp-config passwords drift.
func adminEmailsForSite(creds wpDBCreds, prefix string) []string {
	query := fmt.Sprintf(
		"SELECT DISTINCT LOWER(u.user_email) FROM `%susers` u "+
			"JOIN `%susermeta` um ON u.ID = um.user_id "+
			"WHERE um.meta_key = '%scapabilities' AND um.meta_value LIKE '%%administrator%%'",
		prefix, prefix, prefix,
	)
	rows := runMySQLQueryRoot(creds.dbName, query)
	var out []string
	for _, row := range rows {
		row = strings.TrimSpace(row)
		if row != "" {
			out = append(out, row)
		}
	}
	return out
}

// buildAdminOverlapFindings collapses each overlap entry into a single
// Warning finding. Account lists are sorted for deterministic message
// content so the dedup layer downstream treats two identical overlaps
// emitted across scans as the same finding.
func buildAdminOverlapFindings(overlaps map[string][]store.AdminEmailEntry) []alert.Finding {
	emails := make([]string, 0, len(overlaps))
	for email := range overlaps {
		emails = append(emails, email)
	}
	sort.Strings(emails)
	out := make([]alert.Finding, 0, len(emails))
	for _, email := range emails {
		owners := overlaps[email]
		accountSet := make(map[string]struct{}, len(owners))
		for _, o := range owners {
			accountSet[o.Account] = struct{}{}
		}
		accounts := make([]string, 0, len(accountSet))
		for a := range accountSet {
			accounts = append(accounts, a)
		}
		sort.Strings(accounts)
		details := strings.Builder{}
		fmt.Fprintf(&details, "Email: %s\nAccounts: %s\n", email, strings.Join(accounts, ", "))
		for _, o := range owners {
			fmt.Fprintf(&details, "- %s (schema %s, last seen %s)\n", o.Account, o.Schema, o.LastSeen.Format(time.RFC3339))
		}
		out = append(out, alert.Finding{
			Severity:  alert.Warning,
			Check:     "admin_cross_account_overlap",
			Message:   fmt.Sprintf("Admin email %s appears on %d accounts: %s", email, len(accounts), strings.Join(accounts, ", ")),
			Details:   details.String(),
			Timestamp: time.Now(),
		})
	}
	return out
}
