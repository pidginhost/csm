package checks

import (
	"context"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Magento database content scanner.
//
// Single file covering both major versions: M1 (Magento 1.x, EOL'd
// June 2020 but still found on legacy hosts) and M2 (Magento 2.x).
// The two versions share table names and content shape but disagree
// on configuration file format -- M1 stores credentials in
// app/etc/local.xml as XML, M2 stores them in app/etc/env.php as
// PHP arrays.
//
// Discovery is mutually exclusive: a host either has app/etc/env.php
// (M2) or app/etc/local.xml (M1), never both. We probe in that order
// because M2 is the actively maintained version and we want fresh
// installs to be picked up first.
//
// Scanned tables (identical between M1 and M2):
//
//   core_config_data                  (path, value) -- settings.
//                                     web/unsecure/base_url is the
//                                     canonical hijack target;
//                                     attackers redirect the storefront
//                                     by overwriting it.
//   catalog_product_entity_text       product description text;
//                                     spam-injection vector for SEO
//   cms_block + cms_page              CMS-managed content; same
//                                     pattern as the product text scan
//   admin_user                        backend administrator accounts.
//                                     One Warning per row -- legitimate
//                                     admin shows up too.
//
// Three new finding categories with CMS-explicit names:
// magento_settings_injection, magento_content_injection,
// magento_admin_injection.

// magentoCreds carries the parsed connection details. Mirrors
// jConfigCreds / drupalCreds; the version field tells the scanner
// which discovery path produced the creds (useful for messages).
type magentoCreds struct {
	// ctx ties every query for this install to the runner's deadline.
	ctx         context.Context
	dbName      string
	dbUser      string
	dbPass      string
	dbHost      string
	dbPrefix    string
	version     string // "M1" | "M2"
	path        string
	queryFailed *bool
}

func (c magentoCreds) asWPDBCreds() wpDBCreds {
	return wpDBCreds{
		dbName:      c.dbName,
		dbUser:      c.dbUser,
		dbPass:      c.dbPass,
		dbHost:      c.dbHost,
		tablePrefix: c.dbPrefix,
		queryCtx:    c.ctx,
		queryOwner:  "db_content_magento",
		queryFailed: c.queryFailed,
	}
}

// magentoM1XMLRoot is the minimum struct surface encoding/xml needs
// to extract the connection block out of a Magento 1.x local.xml.
// CDATA wrapping is transparent to the decoder; both the bare and
// CDATA-wrapped forms produce the same string value.
type magentoM1XMLRoot struct {
	XMLName    xml.Name              `xml:"config"`
	Connection magentoM1XMLConnBlock `xml:"global>resources>default_setup>connection"`
	Resources  magentoM1XMLResources `xml:"global>resources>db"`
}

type magentoM1XMLConnBlock struct {
	Host     string `xml:"host"`
	Username string `xml:"username"`
	Password string `xml:"password"`
	DBName   string `xml:"dbname"`
}

type magentoM1XMLResources struct {
	TablePrefix string `xml:"table_prefix"`
}

// M2 env.php is a PHP file returning an array; we extract by regex
// rather than wiring a PHP parser. The patterns match the canonical
// nested-array layout that vendor/magento installers produce; hand-
// rolled env.php files with reordered keys still parse because
// each pattern matches independently.
var (
	magentoM2HostRe   = regexp.MustCompile(`['"]host['"]\s*=>\s*['"]([^'"]+)['"]`)
	magentoM2UserRe   = regexp.MustCompile(`['"]username['"]\s*=>\s*['"]([^'"]+)['"]`)
	magentoM2PassRe   = regexp.MustCompile(`['"]password['"]\s*=>\s*['"]([^'"]+)['"]`)
	magentoM2DBRe     = regexp.MustCompile(`['"]dbname['"]\s*=>\s*['"]([^'"]+)['"]`)
	magentoM2PrefixRe = regexp.MustCompile(`['"]table_prefix['"]\s*=>\s*['"]([^'"]*)['"]`)
)

// CheckMagentoContent discovers Magento installs (M1 + M2) and
// scans the four canonical tables. Mirrors CheckJoomlaContent and
// CheckDrupalContent without sharing code -- the version-branching
// is local to this scanner.
//
// Accounts that produced creds via the M2 (env.php) path are
// tracked in seenAccounts so the M1 fallback doesn't re-scan a
// host that's already been processed -- including the common case
// where M2 found zero malware findings (a clean install). Without
// this, a half-migrated host with both env.php and stale local.xml
// would scan the database twice with different credential sets.
func CheckMagentoContent(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	var findings []alert.Finding
	seenAccounts := map[string]bool{}

	// M2 discovery first (active version). Rank by mtime desc so recently
	// touched installs are processed first when the check timeout cuts
	// iteration short.
	m2Files := cmsDiscover(ctx, "db_content_magento", "*/public_html/app/etc/env.php", "*/*/app/etc/env.php")
	for _, path := range rankCMSConfigs(ctx, "db_content_magento", m2Files, accountScanMaxFiles(ctx, cfg)) {
		if ctx.Err() != nil {
			return findings
		}
		account := magentoAccountFromPath(path)
		creds, err := parseMagentoM2(ctx, path)
		if err != nil || creds.dbName == "" || creds.dbUser == "" {
			markCheckIncomplete(ctx, "db_content_magento")
			continue
		}
		creds.ctx = ctx
		creds.queryFailed = new(bool)
		seenAccounts[account] = true
		findings = append(findings, scanMagentoAll(store, account, creds)...)
	}

	// M1 fallback for hosts where env.php is absent or unparseable.
	m1Files := cmsDiscover(ctx, "db_content_magento", "*/public_html/app/etc/local.xml", "*/*/app/etc/local.xml")
	for _, path := range rankCMSConfigs(ctx, "db_content_magento", m1Files, accountScanMaxFiles(ctx, cfg)) {
		if ctx.Err() != nil {
			return findings
		}
		account := magentoAccountFromPath(path)
		if seenAccounts[account] {
			continue
		}
		creds, err := parseMagentoM1(ctx, path)
		if err != nil || creds.dbName == "" || creds.dbUser == "" {
			markCheckIncomplete(ctx, "db_content_magento")
			continue
		}
		creds.ctx = ctx
		creds.queryFailed = new(bool)
		findings = append(findings, scanMagentoAll(store, account, creds)...)
	}
	return findings
}

// magentoAccountFromPath strips the conventional cPanel prefix
// (/home/<account>/public_html/app/etc/...) down to the account
// component.
func magentoAccountFromPath(path string) string {
	// /home/<account>/public_html/app/etc/<file> -- four Dirs up.
	cur := path
	for i := 0; i < 4; i++ {
		cur = filepath.Dir(cur)
	}
	return extractUser(cur)
}

// parseMagentoM1 reads local.xml and extracts the connection block.
// A read or XML error keeps the installation out of the completed scan.
func parseMagentoM1(ctx context.Context, path string) (magentoCreds, error) {
	creds := magentoCreds{path: path, version: "M1"}
	data, err := readCMSConfig(ctx, path)
	if err != nil {
		return creds, err
	}
	var root magentoM1XMLRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return creds, err
	}
	creds.dbHost = strings.TrimSpace(root.Connection.Host)
	creds.dbUser = strings.TrimSpace(root.Connection.Username)
	creds.dbPass = strings.TrimSpace(root.Connection.Password)
	creds.dbName = strings.TrimSpace(root.Connection.DBName)
	creds.dbPrefix = strings.TrimSpace(root.Resources.TablePrefix)
	if creds.dbHost == "" {
		creds.dbHost = "localhost"
	}
	return creds, nil
}

// parseMagentoM2 reads env.php and pulls credentials out via the
// field-level regexes. Unlike Drupal we have a stable nested-array
// layout to match against (the one Magento Setup writes), but to
// stay robust against operator-edited env.php files we match each
// key independently.
func parseMagentoM2(ctx context.Context, path string) (magentoCreds, error) {
	creds := magentoCreds{path: path, version: "M2"}
	data, err := readCMSConfig(ctx, path)
	if err != nil {
		return creds, err
	}
	body := string(data)

	if m := magentoM2HostRe.FindStringSubmatch(body); m != nil {
		creds.dbHost = m[1]
	}
	if m := magentoM2UserRe.FindStringSubmatch(body); m != nil {
		creds.dbUser = m[1]
	}
	if m := magentoM2PassRe.FindStringSubmatch(body); m != nil {
		creds.dbPass = m[1]
	}
	if m := magentoM2DBRe.FindStringSubmatch(body); m != nil {
		creds.dbName = m[1]
	}
	if m := magentoM2PrefixRe.FindStringSubmatch(body); m != nil {
		creds.dbPrefix = m[1]
	}
	if creds.dbHost == "" {
		creds.dbHost = "localhost"
	}
	return creds, nil
}

// scanMagentoAll runs the four scan paths against one Magento
// install. Helper exists so M1 and M2 dispatch through the same
// post-creds code path.
func scanMagentoAll(store *state.Store, account string, creds magentoCreds) []alert.Finding {
	var findings []alert.Finding
	findings = append(findings, scanMagentoSettings(account, creds)...)
	findings = append(findings, scanMagentoContent(account, creds, "catalog_product_entity_text", "value")...)
	findings = append(findings, scanMagentoContent(account, creds, "cms_block", "content")...)
	findings = append(findings, scanMagentoContent(account, creds, "cms_page", "content")...)
	findings = append(findings, scanMagentoAdmins(store, account, creds)...)
	return findings
}

// scanMagentoSettings looks for malware patterns in core_config_data
// values. The path column carries dotted-namespace identifiers
// (web/unsecure/base_url, design/header/welcome, etc.) so we keep
// it in the finding details for triage.
func scanMagentoSettings(account string, creds magentoCreds) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT path, value FROM %score_config_data WHERE %s",
		creds.dbPrefix, paramsLikeClause("value"))
	rows, _ := runCMSQuery(creds.asWPDBCreds(), query)
	var findings []alert.Finding
	for _, row := range rows {
		cfgPath, body := splitTabRow(row)
		if cfgPath == "" {
			continue
		}
		sev, desc, ok := classifyMalwareRow(body, false)
		if !ok {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: sev,
			Check:    "magento_settings_injection",
			Message:  fmt.Sprintf("Magento %s settings injection on %s: %s (%s)", creds.version, account, cfgPath, desc),
			Details:  fmt.Sprintf("Account: %s\nConfig path: %s\nMatch: %s", account, cfgPath, desc),
		})
	}
	return findings
}

// scanMagentoContent walks one CMS table (catalog_product_entity_text,
// cms_block, cms_page) for malware patterns. The looser
// hasMaliciousExternalScriptInPost predicate applies because the
// tables carry author-written content.
func scanMagentoContent(account string, creds magentoCreds, table, valueCol string) []alert.Finding {
	idCol := "row_id"
	switch table {
	case "catalog_product_entity_text":
		idCol = "entity_id"
	case "cms_block":
		idCol = "block_id"
	case "cms_page":
		idCol = "page_id"
	}
	query := fmt.Sprintf(
		"SELECT %s, %s FROM %s%s WHERE %s",
		idCol, valueCol, creds.dbPrefix, table, paramsLikeClause(valueCol))
	rows, _ := runCMSQuery(creds.asWPDBCreds(), query)
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
			Check:    "magento_content_injection",
			Message:  fmt.Sprintf("Magento %s content injection on %s: %s id=%s (%s)", creds.version, account, table, id, desc),
			Details:  fmt.Sprintf("Account: %s\nTable: %s\nRow id: %s\nMatch: %s", account, table, id, desc),
		})
	}
	return findings
}

// scanMagentoAdmins enumerates the admin_user table. Rows include
// the legitimate site admin -- one Warning per row, operator
// review territory.
func scanMagentoAdmins(store *state.Store, account string, creds magentoCreds) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT user_id, username, email FROM %sadmin_user",
		creds.dbPrefix)
	rows, complete := runCMSQuery(creds.asWPDBCreds(), query)
	return cmsAdminFindings(store, "magento", "magento_admin_injection", account, creds.asWPDBCreds(), rows, complete, func(fields []string) (string, string) {
		return fmt.Sprintf("Magento %s admin account on %s: user_id=%s", creds.version, account, fields[0]),
			fmt.Sprintf("Account: %s\nRow: %s\nReview: confirm this is the legitimate site administrator.", account, strings.Join(fields, "\t"))
	})
}
