package checks

import (
	"fmt"
	"strings"
)

// Per-finding Re-check for the non-WordPress CMS database-content findings
// (Drupal, Joomla, Magento, OpenCart, PrestaShop). Each verifier re-discovers
// the account's installs (verify_db_cms_installs.go), re-reads the flagged row
// with each install's own database login, and re-runs the SAME malware
// classifier the detector used. It resolves only when the row is gone or no
// longer classifies as malware; any query failure or uninspectable install
// returns Checked:false so a live injection is never auto-cleared.

// --- Drupal ---------------------------------------------------------------

func verifyDrupalSettingsInjection(message, details string) VerifyResult {
	name := detailField(details, "Config name")
	if name == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the config name from the finding"}
	}
	installs, ok := drupalVerifyInstalls(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Drupal site")
	}
	return cmsVerifyEveryInstall(installs, false, func(string) (string, error) {
		return "SELECT data FROM config WHERE name = ?", nil
	}, name)
}

func verifyDrupalContentInjection(message, details string) VerifyResult {
	entityID := detailField(details, "Node entity_id")
	if entityID == "" || !isAllDigits(entityID) {
		return VerifyResult{Checked: false, Detail: "could not parse the node id from the finding"}
	}
	installs, ok := drupalVerifyInstalls(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Drupal site")
	}
	return cmsVerifyEveryInstall(installs, true, func(string) (string, error) {
		return "SELECT body_value FROM node_revision__body WHERE entity_id = ?", nil
	}, entityID)
}

// --- Joomla ---------------------------------------------------------------

func verifyJoomlaExtensionsInjection(message, details string) VerifyResult {
	name := detailField(details, "Extension")
	if name == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the extension name from the finding"}
	}
	installs, ok := joomlaVerifyInstalls(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Joomla site")
	}
	return cmsVerifyEveryInstall(installs, false, func(prefix string) (string, error) {
		table, err := QuoteIdent(prefix + "extensions")
		return fmt.Sprintf("SELECT params FROM %s WHERE name = ?", table), err
	}, name)
}

func verifyJoomlaContentInjection(message, details string) VerifyResult {
	id := detailField(details, "Article ID")
	if id == "" || !isAllDigits(id) {
		return VerifyResult{Checked: false, Detail: "could not parse the article id from the finding"}
	}
	installs, ok := joomlaVerifyInstalls(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Joomla site")
	}
	return cmsVerifyEveryInstall(installs, true, func(prefix string) (string, error) {
		table, err := QuoteIdent(prefix + "content")
		return fmt.Sprintf("SELECT introtext FROM %s WHERE id = ?", table), err
	}, id)
}

// --- Magento --------------------------------------------------------------

func verifyMagentoSettingsInjection(message, details string) VerifyResult {
	cfgPath := detailField(details, "Config path")
	if cfgPath == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the config path from the finding"}
	}
	installs, ok := magentoVerifyInstalls(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Magento site")
	}
	return cmsVerifyEveryInstall(installs, false, func(prefix string) (string, error) {
		table, err := QuoteIdent(prefix + "core_config_data")
		return fmt.Sprintf("SELECT value FROM %s WHERE path = ?", table), err
	}, cfgPath)
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
	installs, ok := magentoVerifyInstalls(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Magento site")
	}
	return cmsVerifyEveryInstall(installs, true, func(prefix string) (string, error) {
		quoted, err := QuoteIdent(prefix + table)
		return fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", valueCol, quoted, idCol), err
	}, rowID)
}

// --- OpenCart -------------------------------------------------------------

func verifyOpenCartSettingsInjection(message, details string) VerifyResult {
	key := detailField(details, "Setting key")
	if key == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the setting key from the finding"}
	}
	installs, ok := openCartVerifyInstalls(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("OpenCart site")
	}
	return cmsVerifyEveryInstall(installs, false, func(prefix string) (string, error) {
		table, err := QuoteIdent(prefix + "setting")
		return fmt.Sprintf("SELECT value FROM %s WHERE `key` = ?", table), err
	}, key)
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
	installs, ok := openCartVerifyInstalls(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("OpenCart site")
	}
	return cmsVerifyEveryInstall(installs, true, func(prefix string) (string, error) {
		quoted, err := QuoteIdent(prefix + table)
		return fmt.Sprintf("SELECT description FROM %s WHERE %s = ? AND language_id = 1", quoted, idCol), err
	}, rowID)
}

// --- PrestaShop -------------------------------------------------------------

// prestashopRecordedInstall finds the shop whose database the finding records.
// An addon shop or a changed configuration can name a different database with
// the same row ids; a finding is never cleared against another shop.
func prestashopRecordedInstall(message, details string) (wpDBCreds, bool) {
	installs, ok := prestashopVerifyInstalls(dbFindingAccount(message, details))
	if !ok {
		return wpDBCreds{}, false
	}
	return cmsVerifyRecordedInstall(installs, details)
}

func verifyPrestaShopSettingsInjection(message, details string) VerifyResult {
	id := detailField(details, "Setting id")
	if !isAllDigits(id) {
		return VerifyResult{Checked: false, Detail: "could not parse the setting id from the finding"}
	}
	creds, ok := prestashopRecordedInstall(message, details)
	if !ok {
		return dbVerifyNotLocatable("PrestaShop site")
	}
	return cmsVerifyEveryInstall([]wpDBCreds{creds}, false, func(prefix string) (string, error) {
		base, err := QuoteIdent(prefix + "configuration")
		if err != nil {
			return "", err
		}
		lang, err := QuoteIdent(prefix + "configuration_lang")
		return fmt.Sprintf("SELECT value FROM %s WHERE id_configuration = ? UNION ALL SELECT value FROM %s WHERE id_configuration = ?",
			base, lang), err
	}, id, id)
}

// verifyPrestaShopContentInjection re-reads every language, shop and column
// of the flagged row: the finding stands for all of them.
func verifyPrestaShopContentInjection(message, details string) VerifyResult {
	tableName := detailField(details, "Table")
	id := detailField(details, "Row id")
	var spec *prestashopContentTable
	for i := range prestashopContentTables {
		if prestashopContentTables[i].table == tableName {
			spec = &prestashopContentTables[i]
		}
	}
	if spec == nil || !isAllDigits(id) {
		return VerifyResult{Checked: false, Detail: "could not parse the table and row id from the finding"}
	}
	creds, ok := prestashopRecordedInstall(message, details)
	if !ok {
		return dbVerifyNotLocatable("PrestaShop site")
	}
	var args []any
	for range spec.cols {
		args = append(args, id)
	}
	return cmsVerifyEveryInstall([]wpDBCreds{creds}, true, func(prefix string) (string, error) {
		table, err := QuoteIdent(prefix + spec.table)
		var selects []string
		for _, col := range spec.cols {
			selects = append(selects, fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", col, table, spec.idCol))
		}
		return strings.Join(selects, " UNION ALL "), err
	}, args...)
}
