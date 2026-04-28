package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Drupal database content scanner.
//
// v1 covers Drupal 8 and later (the unified-table layout: config /
// node_field_data / users_field_data). Drupal 7 uses a different
// schema (variable / node / users) and reached EOL in January 2025;
// scanning it lands as a follow-up if any operator reports D7 sites
// still in production.
//
// Discovery: glob /home/*/public_html/sites/default/settings.php
// and confirm core/lib/Drupal.php exists in the site root --
// that file is the canonical D8+ marker (D7 has bootstrap.inc /
// modules/ but no core/ directory).
//
// Credentials: parsed by regex over the canonical $databases
// array literal. Drupal allows both array() and short [] syntax;
// the regex accepts either.
//
// Scanned tables (all unprefixed -- D8+ does not use a per-site
// table prefix in standard installs):
//
//   config                       name + data; data is a
//                                serialized PHP array carrying
//                                site name, slogan, theme, etc.
//                                Common hijack target.
//   node_revision__body          entity_id + body_value; the
//                                actual article body. Scanned for
//                                any pattern in dbMalwarePatterns
//                                with the same external-script
//                                post-filter the WP and Joomla
//                                scanners use.
//   users_field_data             user table; joined with
//   user__roles                  on entity_id = uid. Rows where
//                                roles_target_id = 'administrator'
//                                surface as drupal_admin_injection.
//
// Three new finding categories with CMS-explicit names:
// drupal_settings_injection, drupal_content_injection,
// drupal_admin_injection.

// drupalAdminRoleID is the canonical role identifier for Drupal
// site administrators in vanilla D8+. Operators on hardened
// installs may have renumbered or renamed; v1 narrows to this.
const drupalAdminRoleID = "administrator"

// drupalSettingsRe pulls credentials out of the $databases array
// literal. Each field is matched independently rather than
// trying to parse the array structure -- attackers occasionally
// reorder keys, and a key-only regex ignores layout differences.
var (
	drupalDBNameRe = regexp.MustCompile(`'database'\s*=>\s*['"]([^'"]+)['"]`)
	drupalDBUserRe = regexp.MustCompile(`'username'\s*=>\s*['"]([^'"]+)['"]`)
	drupalDBPassRe = regexp.MustCompile(`'password'\s*=>\s*['"]([^'"]+)['"]`)
	drupalDBHostRe = regexp.MustCompile(`'host'\s*=>\s*['"]([^'"]+)['"]`)
)

// drupalCreds carries the parsed connection details. Mirrors the
// jConfigCreds shape so existing helpers (runMySQLQuery,
// asWPDBCreds) work uniformly.
type drupalCreds struct {
	dbName string
	dbUser string
	dbPass string
	dbHost string
	path   string
}

func (c drupalCreds) asWPDBCreds() wpDBCreds {
	return wpDBCreds{
		dbName: c.dbName,
		dbUser: c.dbUser,
		dbPass: c.dbPass,
		dbHost: c.dbHost,
	}
}

// CheckDrupalContent discovers Drupal 8+ sites and scans the three
// canonical attacker-touched tables. Mirrors CheckJoomlaContent
// without sharing code -- the credential layout and table set are
// distinct enough that a generic dispatcher would be more
// abstraction than a 4-CMS pipeline calls for.
func CheckDrupalContent(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	settings, _ := osFS.Glob("/home/*/public_html/sites/default/settings.php")
	if len(settings) == 0 {
		return nil
	}

	for _, path := range settings {
		// public_html is three dirs up from sites/default/settings.php.
		publicHTML := filepath.Dir(filepath.Dir(filepath.Dir(path)))
		if !looksLikeDrupal8Plus(publicHTML) {
			continue
		}
		// /home/<account> is one level above public_html.
		account := extractUser(filepath.Dir(publicHTML))
		creds := parseDrupalSettings(path)
		if creds.dbName == "" || creds.dbUser == "" {
			continue
		}

		findings = append(findings, scanDrupalConfig(account, creds)...)
		findings = append(findings, scanDrupalContent(account, creds)...)
		findings = append(findings, scanDrupalAdmins(account, creds)...)
	}
	return findings
}

// looksLikeDrupal8Plus checks for the core/lib/Drupal.php marker
// that distinguishes D8+ from D7. Stat (not Open) so we don't
// pull file content into memory just to check existence.
func looksLikeDrupal8Plus(publicHTML string) bool {
	marker := filepath.Join(publicHTML, "core", "lib", "Drupal.php")
	_, err := osFS.Stat(marker)
	return err == nil
}

// parseDrupalSettings reads settings.php and returns the database
// credentials from the $databases['default']['default'] entry. If
// settings.php uses split-DB or per-environment overrides, only
// the first 'default' connection is reported -- the rest are
// followed by the same regex on subsequent calls.
func parseDrupalSettings(path string) drupalCreds {
	creds := drupalCreds{path: path}
	// #nosec G304 -- path resolved via osFS.Glob over /home/*/public_html; not attacker-controlled.
	data, err := osFS.ReadFile(path)
	if err != nil {
		return creds
	}
	body := string(data)

	if m := drupalDBNameRe.FindStringSubmatch(body); m != nil {
		creds.dbName = m[1]
	}
	if m := drupalDBUserRe.FindStringSubmatch(body); m != nil {
		creds.dbUser = m[1]
	}
	if m := drupalDBPassRe.FindStringSubmatch(body); m != nil {
		creds.dbPass = m[1]
	}
	if m := drupalDBHostRe.FindStringSubmatch(body); m != nil {
		creds.dbHost = m[1]
	}
	if creds.dbHost == "" {
		creds.dbHost = "localhost"
	}
	return creds
}

// scanDrupalConfig pulls rows from the config table whose data
// blob matches any malware pattern, then refines via
// classifyMalwareRow (strict / config-storage variant).
func scanDrupalConfig(account string, creds drupalCreds) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT name, data FROM config WHERE %s",
		paramsLikeClause("data"))
	rows := runMySQLQuery(creds.asWPDBCreds(), query)
	var findings []alert.Finding
	for _, row := range rows {
		name, body := splitTabRow(row)
		if name == "" {
			continue
		}
		sev, desc, ok := classifyMalwareRow(body, false)
		if !ok {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: sev,
			Check:    "drupal_settings_injection",
			Message:  fmt.Sprintf("Drupal config injection on %s: %s (%s)", account, name, desc),
			Details:  fmt.Sprintf("Account: %s\nConfig name: %s\nMatch: %s", account, name, desc),
		})
	}
	return findings
}

// scanDrupalContent walks node_revision__body for malware-pattern
// matches in article bodies. The looser post-filter
// (hasMaliciousExternalScriptInPost) applies because article
// content is author-written and may carry pre-TLS-era embeds.
func scanDrupalContent(account string, creds drupalCreds) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT entity_id, body_value FROM node_revision__body WHERE %s",
		paramsLikeClause("body_value"))
	rows := runMySQLQuery(creds.asWPDBCreds(), query)
	var findings []alert.Finding
	for _, row := range rows {
		entityID, body := splitTabRow(row)
		if entityID == "" {
			continue
		}
		sev, desc, ok := classifyMalwareRow(body, true)
		if !ok {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: sev,
			Check:    "drupal_content_injection",
			Message:  fmt.Sprintf("Drupal article content injection on %s: node %s (%s)", account, entityID, desc),
			Details:  fmt.Sprintf("Account: %s\nNode entity_id: %s\nMatch: %s", account, entityID, desc),
		})
	}
	return findings
}

// scanDrupalAdmins joins users_field_data with user__roles to
// surface every account in the administrator role. Same Warning
// severity / per-row emission as the Joomla equivalent --
// legitimate site admin shows up here too, so this is operator
// review territory rather than auto-actionable.
func scanDrupalAdmins(account string, creds drupalCreds) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT u.uid, u.name, u.mail FROM users_field_data u JOIN user__roles r ON u.uid = r.entity_id WHERE r.roles_target_id = '%s'",
		drupalAdminRoleID)
	rows := runMySQLQuery(creds.asWPDBCreds(), query)
	if len(rows) == 0 {
		return nil
	}
	var findings []alert.Finding
	for _, row := range rows {
		fields := strings.Split(row, "\t")
		if len(fields) < 1 {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: alert.Warning,
			Check:    "drupal_admin_injection",
			Message:  fmt.Sprintf("Drupal administrator account on %s: %s", account, fields[0]),
			Details:  fmt.Sprintf("Account: %s\nRow: %s\nReview: confirm this is the legitimate site administrator.", account, row),
		})
	}
	return findings
}
