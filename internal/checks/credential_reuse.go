package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// credentialReuseMinAccounts is the threshold for emitting the
// password-reuse finding: the same WordPress admin password hash present
// on this many or more distinct accounts. Two is the common shared-hosting
// pattern (an agency reusing one admin password across client sites) where
// a single credential disclosure compromises every site at once.
const credentialReuseMinAccounts = 2

// CheckCredentialReuse flags WordPress administrator accounts that share
// an identical password hash across two or more distinct hosting accounts.
// Password hashes are salted on modern WordPress installs, so this is an
// exact at-rest hash reuse signal, not a weak-password detector.
//
// Privacy: the raw password hash is never stored, logged, or emitted. Only
// a truncated one-way fingerprint is used to group identical hashes, and
// findings report the affected accounts and a count -- not the hash.
func CheckCredentialReuse(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	wpConfigs, _ := osFS.Glob("/home/*/public_html/wp-config.php")

	// fingerprint -> set of distinct accounts carrying that admin hash.
	byFingerprint := map[string]map[string]struct{}{}
	for _, wpConfig := range wpConfigs {
		if ctx.Err() != nil {
			return nil
		}
		account := extractUser(filepath.Dir(wpConfig))
		if account == "" {
			continue
		}
		creds := parseWPConfig(wpConfig)
		if creds.dbName == "" {
			continue
		}
		prefix, ok := resolveTablePrefix(creds)
		if !ok {
			continue
		}
		creds.tablePrefix = prefix
		for _, fp := range adminPasswordFingerprintsForSite(creds, prefix) {
			if fp == "" {
				continue
			}
			if byFingerprint[fp] == nil {
				byFingerprint[fp] = map[string]struct{}{}
			}
			byFingerprint[fp][account] = struct{}{}
		}
	}

	return buildCredentialReuseFindings(byFingerprint, credentialReuseMinAccounts)
}

// adminPasswordFingerprintsForSite returns fingerprints for the admin
// user_pass hashes currently stored on the WordPress site. Uses root MySQL
// because wp-config passwords drift on cPanel hosts (same rationale as
// adminEmailsForSite).
func adminPasswordFingerprintsForSite(creds wpDBCreds, prefix string) []string {
	query := fmt.Sprintf(
		"SELECT DISTINCT u.user_pass FROM `%susers` u "+
			"JOIN `%susermeta` um ON u.ID = um.user_id "+
			"WHERE um.meta_key = '%scapabilities' AND um.meta_value LIKE '%%administrator%%'",
		prefix, prefix, prefix,
	)
	rows := runMySQLQueryRoot(creds.dbName, query)
	var out []string
	for _, row := range rows {
		fp := credentialHashFingerprint(strings.TrimSpace(row))
		if fp != "" {
			out = append(out, fp)
		}
	}
	return out
}

// credentialHashFingerprint maps a raw password hash to a short,
// non-reversible grouping key. Two identical hashes map to the same
// fingerprint without returning the raw hash. Empty input yields "".
func credentialHashFingerprint(rawHash string) string {
	if rawHash == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(rawHash))
	return "fp:" + hex.EncodeToString(sum[:])[:16]
}

// buildCredentialReuseFindings emits one Warning per fingerprint shared by
// at least minAccounts distinct accounts. The finding never includes the
// hash or fingerprint-as-secret -- only the affected account list and a
// count, so an operator can rotate the shared credential.
func buildCredentialReuseFindings(byFingerprint map[string]map[string]struct{}, minAccounts int) []alert.Finding {
	if minAccounts < 2 {
		minAccounts = 2
	}

	type credentialReuseGroup struct {
		accounts []string
	}
	groups := make([]credentialReuseGroup, 0, len(byFingerprint))
	for _, accountSet := range byFingerprint {
		if len(accountSet) < minAccounts {
			continue
		}
		accounts := make([]string, 0, len(accountSet))
		for a := range accountSet {
			accounts = append(accounts, a)
		}
		sort.Strings(accounts)
		groups = append(groups, credentialReuseGroup{accounts: accounts})
	}
	sort.Slice(groups, func(i, j int) bool {
		return strings.Join(groups[i].accounts, "\x00") < strings.Join(groups[j].accounts, "\x00")
	})

	var out []alert.Finding
	for _, group := range groups {
		accounts := group.accounts
		out = append(out, alert.Finding{
			Severity: alert.Warning,
			Check:    "credential_reuse",
			Message: fmt.Sprintf("Identical WordPress admin password hash reused across %d accounts: %s",
				len(accounts), strings.Join(accounts, ", ")),
			Details: fmt.Sprintf("Accounts sharing one admin password hash: %s\n"+
				"Rotate the shared credential: a single disclosure compromises every listed site.",
				strings.Join(accounts, ", ")),
			Timestamp: time.Now(),
		})
	}
	return out
}
