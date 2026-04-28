package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// OpenCart database content scanner.
//
// Discovery: glob /home/*/public_html/config.php and confirm both
// it AND /home/*/public_html/admin/config.php contain
// `define('DB_DRIVER'`. The admin-side config.php pair is the
// canonical OpenCart marker -- plain PHP sites carry a config.php
// in the document root that's nothing to do with OpenCart.
//
// Credentials use PHP define() constants with OC-specific names:
//
//   DB_HOSTNAME  DB_USERNAME  DB_PASSWORD  DB_DATABASE  DB_PREFIX
//
// Reuses the existing extractDefine helper from dbscan.go (the WP
// scanner already understands this shape). DB_PREFIX defaults to
// "oc_" on vanilla installs.
//
// Scanned tables (all prefixed):
//
//   <prefix>setting                  k/v pairs; values are JSON
//                                    blobs. config_url / config_ssl
//                                    are the canonical hijack
//                                    targets for storefront redirect.
//   <prefix>product_description      product description text
//   <prefix>information_description  CMS-managed information pages
//   <prefix>user                     admin/staff accounts.
//                                    Customer accounts live in the
//                                    oc_customer table, not here;
//                                    every oc_user row is admin-shaped.
//
// Three new finding categories:
// opencart_settings_injection, opencart_content_injection,
// opencart_admin_injection.

type opencartCreds struct {
	dbName   string
	dbUser   string
	dbPass   string
	dbHost   string
	dbPrefix string
	path     string
}

func (c opencartCreds) asWPDBCreds() wpDBCreds {
	return wpDBCreds{
		dbName:      c.dbName,
		dbUser:      c.dbUser,
		dbPass:      c.dbPass,
		dbHost:      c.dbHost,
		tablePrefix: c.dbPrefix,
	}
}

// CheckOpenCartContent discovers OpenCart installs and scans the
// four canonical attacker-touched tables. Mirrors the other CMS
// scanners; the discovery and credentials parsing are the only
// OC-specific bits.
func CheckOpenCartContent(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	configs, _ := osFS.Glob("/home/*/public_html/config.php")
	if len(configs) == 0 {
		return nil
	}

	for _, path := range configs {
		if !looksLikeOpenCart(path) {
			continue
		}
		account := extractUser(filepath.Dir(path))
		creds := parseOpenCartConfig(path)
		if creds.dbName == "" {
			continue
		}
		prefix := creds.dbPrefix
		if prefix == "" {
			prefix = "oc_"
		}
		creds.dbPrefix = prefix

		findings = append(findings, scanOpenCartSettings(account, creds)...)
		findings = append(findings, scanOpenCartContentTable(account, creds, "product_description", "description")...)
		findings = append(findings, scanOpenCartContentTable(account, creds, "information_description", "description")...)
		findings = append(findings, scanOpenCartAdmins(account, creds)...)
	}
	return findings
}

// looksLikeOpenCart confirms both config.php files exist and both
// reference DB_DRIVER. The admin-side file is what distinguishes
// OpenCart from arbitrary PHP sites that happen to ship a
// config.php at the document root.
func looksLikeOpenCart(rootConfig string) bool {
	if !configContainsDBDriver(rootConfig) {
		return false
	}
	publicHTML := filepath.Dir(rootConfig)
	adminConfig := filepath.Join(publicHTML, "admin", "config.php")
	return configContainsDBDriver(adminConfig)
}

func configContainsDBDriver(path string) bool {
	// #nosec G304 -- path resolved via osFS.Glob over /home/*/public_html or its admin/ subdir; not attacker-controlled.
	data, err := osFS.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "DB_DRIVER")
}

// parseOpenCartConfig extracts the DB_* defines from a config.php.
// Reuses the WP scanner's extractDefine helper -- the OC defines
// have the same `define('KEY', 'value')` shape WP uses, and the
// helper already strips comments and walks past the key's closing
// quote correctly.
func parseOpenCartConfig(path string) opencartCreds {
	creds := opencartCreds{path: path}
	// #nosec G304 -- same Glob-resolved path.
	data, err := osFS.ReadFile(path)
	if err != nil {
		return creds
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v := extractDefine(line, "DB_HOSTNAME"); v != "" {
			creds.dbHost = v
		}
		if v := extractDefine(line, "DB_USERNAME"); v != "" {
			creds.dbUser = v
		}
		if v := extractDefine(line, "DB_PASSWORD"); v != "" {
			creds.dbPass = v
		}
		if v := extractDefine(line, "DB_DATABASE"); v != "" {
			creds.dbName = v
		}
		if v := extractDefine(line, "DB_PREFIX"); v != "" {
			creds.dbPrefix = v
		}
	}
	if creds.dbHost == "" {
		creds.dbHost = "localhost"
	}
	return creds
}

// scanOpenCartSettings walks oc_setting k/v rows. The value column
// is a JSON-serialized blob; same external-script post-filter as
// the other CMS settings scanners (strict variant -- this is
// config storage, not author-written content).
func scanOpenCartSettings(account string, creds opencartCreds) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT `key`, value FROM %ssetting WHERE %s",
		creds.dbPrefix, paramsLikeClause("value"))
	rows := runMySQLQuery(creds.asWPDBCreds(), query)
	var findings []alert.Finding
	for _, row := range rows {
		key, body := splitTabRow(row)
		if key == "" {
			continue
		}
		sev, desc, ok := classifyMalwareRow(body, false)
		if !ok {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: sev,
			Check:    "opencart_settings_injection",
			Message:  fmt.Sprintf("OpenCart settings injection on %s: %s (%s)", account, key, desc),
			Details:  fmt.Sprintf("Account: %s\nSetting key: %s\nMatch: %s", account, key, desc),
		})
	}
	return findings
}

// scanOpenCartContentTable walks one of the description tables
// (product_description, information_description). Both have an id
// column and a description column; the id-column name varies but
// the schema is consistent enough that we accept it as a parameter.
//
// Looser post-filter (hasMaliciousExternalScriptInPost) because
// these tables carry author-written content.
//
// Both description tables carry one row per language per product
// or page. Without filtering, a multilingual storefront emits N
// findings per malware-injected row (one per installed language).
// language_id = 1 is English / the vanilla default; non-English
// monolingual sites and genuine multilingual coverage need a
// follow-up that reads config_language_id from oc_setting first.
func scanOpenCartContentTable(account string, creds opencartCreds, table, valueCol string) []alert.Finding {
	idCol := "product_id"
	if table == "information_description" {
		idCol = "information_id"
	}
	query := fmt.Sprintf(
		"SELECT %s, %s FROM %s%s WHERE language_id = 1 AND %s",
		idCol, valueCol, creds.dbPrefix, table, paramsLikeClause(valueCol))
	rows := runMySQLQuery(creds.asWPDBCreds(), query)
	var findings []alert.Finding
	for _, row := range rows {
		id, body := splitTabRow(row)
		if id == "" {
			continue
		}
		sev, desc, ok := classifyMalwareRow(body, true)
		if !ok {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: sev,
			Check:    "opencart_content_injection",
			Message:  fmt.Sprintf("OpenCart content injection on %s: %s id=%s (%s)", account, table, id, desc),
			Details:  fmt.Sprintf("Account: %s\nTable: %s\nRow id: %s\nMatch: %s", account, table, id, desc),
		})
	}
	return findings
}

// scanOpenCartAdmins enumerates the oc_user table (admins/staff,
// not customers -- customers live in oc_customer). Same Warning
// per row as the other CMS adapters.
func scanOpenCartAdmins(account string, creds opencartCreds) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT user_id, username, email FROM %suser",
		creds.dbPrefix)
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
			Check:    "opencart_admin_injection",
			Message:  fmt.Sprintf("OpenCart admin account on %s: user_id=%s", account, fields[0]),
			Details:  fmt.Sprintf("Account: %s\nRow: %s\nReview: confirm this is the legitimate site administrator.", account, row),
		})
	}
	return findings
}
