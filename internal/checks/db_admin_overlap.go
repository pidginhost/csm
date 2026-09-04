package checks

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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

	wpConfigs := adminOverlapWPConfigs(ctx)
	for _, wpConfig := range wpConfigs {
		if ctx.Err() != nil {
			return nil
		}
		account := wpConfigUser(filepath.Dir(wpConfig))
		creds, complete := parseWPConfigChecked(wpConfig)
		if !complete {
			markCheckIncomplete(ctx, "admin_overlap")
			continue
		}
		if creds.dbName == "" {
			markCheckIncomplete(ctx, "admin_overlap")
			continue
		}
		prefix, ok := resolveTablePrefix(creds)
		if !ok {
			markCheckIncomplete(ctx, "admin_overlap")
			continue
		}
		creds.tablePrefix = prefix
		emails, err := adminEmailsForSite(creds, prefix)
		if err != nil {
			markCheckIncomplete(ctx, "admin_overlap")
			continue
		}
		for _, email := range emails {
			if err := db.RecordAdminEmail(email, account, creds.dbName, now); err != nil {
				markCheckIncomplete(ctx, "admin_overlap")
			}
		}
	}

	min := adminEmailDefaultMinAccounts
	if cfg != nil && cfg.Detection.AdminOverlapMinAccounts > 0 {
		min = cfg.Detection.AdminOverlapMinAccounts
	}
	overlaps, err := db.OverlappingAdminEmails(min, adminEmailRetention)
	if err != nil {
		markCheckIncomplete(ctx, "admin_overlap")
		return nil
	}
	if len(overlaps) == 0 {
		return nil
	}
	overlaps = filterTrustedAdminOverlaps(overlaps, cfg)
	return buildAdminOverlapFindings(overlaps)
}

// adminEmailsForSite returns the lowercase admin emails currently
// configured on the WordPress site. Uses the existing root-MySQL
// helper so it works on cPanel hosts where wp-config passwords drift.
func adminEmailsForSite(creds wpDBCreds, prefix string) ([]string, error) {
	query := fmt.Sprintf(
		"SELECT DISTINCT LOWER(u.user_email) FROM `%susers` u "+
			"JOIN `%susermeta` um ON u.ID = um.user_id "+
			"WHERE um.meta_key = '%scapabilities' AND um.meta_value LIKE '%%administrator%%'",
		prefix, prefix, prefix,
	)
	rows, err := runMySQLQueryRootWithError(creds.dbName, query)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, row := range rows {
		row = strings.TrimSpace(row)
		if row != "" {
			out = append(out, row)
		}
	}
	return out, nil
}

// buildAdminOverlapFindings collapses each overlap entry into a single
// Warning finding. Account lists are sorted so the message reads the same
// way every scan and so the finding's dedup identity is stable.
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
			Severity: alert.Warning,
			Check:    "admin_cross_account_overlap",
			Message:  fmt.Sprintf("Admin email %s appears on %d accounts: %s", email, len(accounts), strings.Join(accounts, ", ")),
			Details:  details.String(),
			// Details carry the per-observation LastSeen stamp, which every
			// scan refreshes. Without an explicit identity the default key
			// hashes those details and each scan stores another copy of an
			// overlap that has not changed.
			DedupKey:  adminOverlapDedupKey(email, accounts),
			Timestamp: time.Now(),
		})
	}
	return out
}

// adminOverlapDedupKey pins the finding identity to the fact the message
// states: this email administers this set of accounts. Account membership
// changing is a new fact; the observation timestamps moving is not. Length
// prefixes keep arbitrary field contents unambiguous, while the digest keeps
// a large shared-admin set from turning into an unbounded state-map key.
func adminOverlapDedupKey(email string, sortedAccounts []string) string {
	identity := make([]byte, 0, len(email)+len(sortedAccounts)*16)
	appendField := func(value string) {
		identity = binary.BigEndian.AppendUint64(identity, uint64(len(value)))
		identity = append(identity, value...)
	}
	appendField(email)
	for _, account := range sortedAccounts {
		appendField(account)
	}
	digest := sha256.Sum256(identity)
	return fmt.Sprintf("admin-overlap:%x", digest[:12])
}

func filterTrustedAdminOverlaps(overlaps map[string][]store.AdminEmailEntry, cfg *config.Config) map[string][]store.AdminEmailEntry {
	if cfg == nil || (len(cfg.Detection.AdminOverlapTrustedEmails) == 0 && len(cfg.Detection.AdminOverlapTrustedDomains) == 0) {
		return overlaps
	}
	out := make(map[string][]store.AdminEmailEntry, len(overlaps))
	for email, owners := range overlaps {
		if trustedAdminOverlapEmail(email, cfg) {
			continue
		}
		out[email] = owners
	}
	return out
}

func trustedAdminOverlapEmail(email string, cfg *config.Config) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	for _, trusted := range cfg.Detection.AdminOverlapTrustedEmails {
		if email == strings.ToLower(strings.TrimSpace(trusted)) {
			return true
		}
	}
	domain := adminEmailDomain(email)
	if domain == "" {
		return false
	}
	for _, trusted := range cfg.Detection.AdminOverlapTrustedDomains {
		if domain == strings.ToLower(strings.TrimSpace(trusted)) {
			return true
		}
	}
	return false
}

func adminEmailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

// adminOverlapWPConfigs lists the WordPress installs this check compares.
// Overlap between a primary site and a subdomain install is the shape this
// check exists to catch, so both must be discovered.
func adminOverlapWPConfigs(ctx context.Context) []string {
	installs := wpInstalls(ctx, "admin_overlap")
	out := make([]string, 0, len(installs))
	for _, in := range installs {
		out = append(out, in.ConfigPath)
	}
	return out
}
