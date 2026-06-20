package checks

import (
	"fmt"
	"path/filepath"
)

// Per-finding Re-check for the non-WordPress CMS database-content findings
// (Drupal, Joomla, Magento, OpenCart). Each verifier re-discovers the single
// canonical install under /home/<account>/public_html, re-reads the one flagged
// row as root against that install's schema, and re-runs the SAME malware
// classifier the detector used. It resolves only when the row is gone or no
// longer classifies as malware; any query failure or undiscoverable install
// returns Checked:false so a live injection is never auto-cleared.

// dbVerifyRowMalware re-queries a single value column for one entity and
// resolves the finding when no returned row still classifies as malware.
// inPostContext selects the looser external-script predicate the detector uses
// for author-written content (article/product bodies) versus config storage.
func dbVerifyRowMalware(schema, query string, inPostContext bool, args ...any) VerifyResult {
	rows, err := runDBVerifyQueryRoot(schema, query, args...)
	if err != nil {
		return dbVerifyQueryError()
	}
	for _, row := range rows {
		if _, _, ok := classifyMalwareRow(row, inPostContext); ok {
			return VerifyResult{Checked: true, Resolved: false, Detail: "the flagged row still contains injected content"}
		}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: "the flagged row no longer contains injected content"}
}

// --- Drupal ---------------------------------------------------------------

func discoverDrupalSchema(account string) (schema string, ok bool) {
	if !validAccountName.MatchString(account) {
		return "", false
	}
	publicHTML := fmt.Sprintf("/home/%s/public_html", account)
	if !looksLikeDrupal8Plus(publicHTML) {
		return "", false
	}
	creds := parseDrupalSettings(filepath.Join(publicHTML, "sites", "default", "settings.php"))
	if creds.dbName == "" {
		return "", false
	}
	return creds.dbName, true
}

func verifyDrupalSettingsInjection(message, details string) VerifyResult {
	name := detailField(details, "Config name")
	if name == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the config name from the finding"}
	}
	schema, ok := discoverDrupalSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Drupal site")
	}
	return dbVerifyRowMalware(schema, "SELECT data FROM config WHERE name = ?", false, name)
}

func verifyDrupalContentInjection(message, details string) VerifyResult {
	entityID := detailField(details, "Node entity_id")
	if entityID == "" || !isAllDigits(entityID) {
		return VerifyResult{Checked: false, Detail: "could not parse the node id from the finding"}
	}
	schema, ok := discoverDrupalSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Drupal site")
	}
	return dbVerifyRowMalware(schema, "SELECT body_value FROM node_revision__body WHERE entity_id = ?", true, entityID)
}

// --- Joomla ---------------------------------------------------------------

func discoverJoomlaSchema(account string) (schema, prefix string, ok bool) {
	if !validAccountName.MatchString(account) {
		return "", "", false
	}
	path := fmt.Sprintf("/home/%s/public_html/configuration.php", account)
	if !looksLikeJoomlaConfig(path) {
		return "", "", false
	}
	creds := parseJConfig(path)
	if creds.dbName == "" {
		return "", "", false
	}
	prefix = creds.dbPrefix
	if prefix == "" {
		prefix = "jos_"
	}
	if !validTablePrefix.MatchString(prefix) {
		return "", "", false
	}
	return creds.dbName, prefix, true
}

func verifyJoomlaExtensionsInjection(message, details string) VerifyResult {
	name := detailField(details, "Extension")
	if name == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the extension name from the finding"}
	}
	schema, prefix, ok := discoverJoomlaSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Joomla site")
	}
	return dbVerifyRowMalware(schema,
		fmt.Sprintf("SELECT params FROM `%sextensions` WHERE name = ?", prefix), false, name)
}

func verifyJoomlaContentInjection(message, details string) VerifyResult {
	id := detailField(details, "Article ID")
	if id == "" || !isAllDigits(id) {
		return VerifyResult{Checked: false, Detail: "could not parse the article id from the finding"}
	}
	schema, prefix, ok := discoverJoomlaSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Joomla site")
	}
	return dbVerifyRowMalware(schema,
		fmt.Sprintf("SELECT introtext FROM `%scontent` WHERE id = ?", prefix), true, id)
}

// --- Magento --------------------------------------------------------------

func discoverMagentoSchema(account string) (schema, prefix string, ok bool) {
	if !validAccountName.MatchString(account) {
		return "", "", false
	}
	base := fmt.Sprintf("/home/%s/public_html/app/etc", account)
	if creds := parseMagentoM2(filepath.Join(base, "env.php")); creds.dbName != "" {
		return magentoVerifyFinalize(creds)
	}
	if creds := parseMagentoM1(filepath.Join(base, "local.xml")); creds.dbName != "" {
		return magentoVerifyFinalize(creds)
	}
	return "", "", false
}

// magentoVerifyFinalize validates the parsed prefix. Magento's default table
// prefix is empty (no prefix); a non-empty prefix must pass validTablePrefix
// before it is interpolated into a table name.
func magentoVerifyFinalize(creds magentoCreds) (string, string, bool) {
	if creds.dbPrefix != "" && !validTablePrefix.MatchString(creds.dbPrefix) {
		return "", "", false
	}
	return creds.dbName, creds.dbPrefix, true
}

func verifyMagentoSettingsInjection(message, details string) VerifyResult {
	cfgPath := detailField(details, "Config path")
	if cfgPath == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the config path from the finding"}
	}
	schema, prefix, ok := discoverMagentoSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Magento site")
	}
	return dbVerifyRowMalware(schema,
		fmt.Sprintf("SELECT value FROM `%score_config_data` WHERE path = ?", prefix), false, cfgPath)
}

// magentoContentTableCols maps a Magento content table to its (idColumn,
// valueColumn). Only the three tables the detector scans are accepted; anything
// else returns ok=false so a malformed finding can never name an arbitrary
// table in the re-query.
func magentoContentTableCols(table string) (idCol, valueCol string, ok bool) {
	switch table {
	case "catalog_product_entity_text":
		return "entity_id", "value", true
	case "cms_block":
		return "block_id", "content", true
	case "cms_page":
		return "page_id", "content", true
	}
	return "", "", false
}

func verifyMagentoContentInjection(message, details string) VerifyResult {
	table := detailField(details, "Table")
	rowID := detailField(details, "Row id")
	idCol, valueCol, ok := magentoContentTableCols(table)
	if !ok || rowID == "" || !isAllDigits(rowID) {
		return VerifyResult{Checked: false, Detail: "could not parse the affected row from the finding"}
	}
	schema, prefix, ok := discoverMagentoSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Magento site")
	}
	return dbVerifyRowMalware(schema,
		fmt.Sprintf("SELECT %s FROM `%s%s` WHERE %s = ?", valueCol, prefix, table, idCol), true, rowID)
}

// --- OpenCart -------------------------------------------------------------

func discoverOpenCartSchema(account string) (schema, prefix string, ok bool) {
	if !validAccountName.MatchString(account) {
		return "", "", false
	}
	path := fmt.Sprintf("/home/%s/public_html/config.php", account)
	if !looksLikeOpenCart(path) {
		return "", "", false
	}
	creds := parseOpenCartConfig(path)
	if creds.dbName == "" {
		return "", "", false
	}
	prefix = creds.dbPrefix
	if prefix == "" {
		prefix = "oc_"
	}
	if !validTablePrefix.MatchString(prefix) {
		return "", "", false
	}
	return creds.dbName, prefix, true
}

func verifyOpenCartSettingsInjection(message, details string) VerifyResult {
	key := detailField(details, "Setting key")
	if key == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the setting key from the finding"}
	}
	schema, prefix, ok := discoverOpenCartSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("OpenCart site")
	}
	return dbVerifyRowMalware(schema,
		fmt.Sprintf("SELECT value FROM `%ssetting` WHERE `key` = ?", prefix), false, key)
}

// openCartContentTableCols maps an OpenCart content table to its id column. Both
// description tables share the "description" value column. Unknown tables are
// rejected.
func openCartContentTableCols(table string) (idCol string, ok bool) {
	switch table {
	case "product_description":
		return "product_id", true
	case "information_description":
		return "information_id", true
	}
	return "", false
}

func verifyOpenCartContentInjection(message, details string) VerifyResult {
	table := detailField(details, "Table")
	rowID := detailField(details, "Row id")
	idCol, ok := openCartContentTableCols(table)
	if !ok || rowID == "" || !isAllDigits(rowID) {
		return VerifyResult{Checked: false, Detail: "could not parse the affected row from the finding"}
	}
	schema, prefix, ok := discoverOpenCartSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("OpenCart site")
	}
	return dbVerifyRowMalware(schema,
		fmt.Sprintf("SELECT description FROM `%s%s` WHERE %s = ? AND language_id = 1", prefix, table, idCol), true, rowID)
}
