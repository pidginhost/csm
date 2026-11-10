package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/state"
)

// PrestaShop database content scanner.
//
// Discovery: <root>/config/defines.inc.php containing _PS_ROOT_DIR_ marks a
// PrestaShop tree (1.6 through 9.x). Credentials come from
// app/config/parameters.php (1.7.4 and later). A root with only
// app/config/parameters.yml is 1.7.0 to 1.7.3 and is not read; a root with
// neither falls back to the 1.6 config/settings.inc.php defines.
//
// parameters.php also holds the mailer password, the application secret,
// cookie keys and an API private key. Only the six database_* entries are
// ever looked up.
//
// Scanned tables (all prefixed): configuration and configuration_lang
// (settings), cms_lang, product_lang and category_lang (content), and
// employee (back-office accounts). Findings:
// prestashop_settings_injection, prestashop_content_injection,
// prestashop_admin_injection.

const prestashopOwner = "db_content_prestashop"

var (
	errPrestaShopYAMLConfig = errors.New("PrestaShop 1.7.0-1.7.3 configuration is not read")
	errPrestaShopCreds      = errors.New("PrestaShop database credentials are incomplete or invalid")
)

type prestashopCreds struct {
	// ctx ties every query for this install to the runner's deadline.
	ctx      context.Context
	dbName   string
	dbUser   string
	dbPass   string
	dbHost   string
	dbPrefix string
	// path is the configuration file the values came from.
	path       string
	queryState *dbQueryState
}

// CheckPrestaShopContent discovers PrestaShop installs under every account
// root and scans their settings, content and back-office employees.
func CheckPrestaShopContent(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	markers := cmsDiscover(ctx, prestashopOwner, "*/public_html/config/defines.inc.php", "*/*/config/defines.inc.php")
	var kept []string
	for _, marker := range markers {
		// Staging and backup copies query a database the site does not serve.
		if !wpSkipDirNames[filepath.Base(prestashopRoot(marker))] {
			kept = append(kept, marker)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	var findings []alert.Finding
	// Rank by mtime desc so recently touched installs are scanned first when
	// the check timeout cuts iteration short.
	for _, marker := range rankCMSConfigs(ctx, prestashopOwner, kept, accountScanMaxFiles(ctx, cfg)) {
		if ctx.Err() != nil {
			return findings
		}
		findings = append(findings, scanPrestaShopInstall(ctx, prestashopRoot(marker), store)...)
	}
	return findings
}

func prestashopRoot(marker string) string {
	return filepath.Dir(filepath.Dir(marker))
}

// scanPrestaShopInstall scans one install and stamps its findings with the
// owner resolved from the configuration path.
func scanPrestaShopInstall(ctx context.Context, root string, store *state.Store) []alert.Finding {
	creds, isShop, err := readPrestaShopCreds(ctx, root)
	if err != nil {
		markCheckIncomplete(ctx, prestashopOwner)
		return nil
	}
	if !isShop {
		return nil
	}
	owner, owned := installOwner(creds.path)
	// A suspended account's database user is locked: scanning it would only
	// leave the check incomplete.
	if owned && accountSuspended(owner) {
		return nil
	}
	account := extractUser(root)
	creds.ctx = ctx
	creds.queryState = new(dbQueryState)
	var findings []alert.Finding
	findings = append(findings, scanPrestaShopSettings(account, creds)...)
	findings = append(findings, scanPrestaShopContent(account, creds)...)
	findings = append(findings, scanPrestaShopEmployees(store, account, creds)...)
	if owned {
		findings = stampTenantIDIfEmpty(findings, owner)
	}
	return findings
}

func (c prestashopCreds) asWPDBCreds() wpDBCreds {
	return wpDBCreds{
		dbName:      c.dbName,
		dbUser:      c.dbUser,
		dbPass:      c.dbPass,
		dbHost:      c.dbHost,
		tablePrefix: c.dbPrefix,
		queryCtx:    c.ctx,
		queryOwner:  prestashopOwner,
		queryState:  c.queryState,
	}
}

// prestashopMarker reports whether defines.inc.php is PrestaShop's: without
// it, app/config/parameters.php alone could belong to any Symfony app.
func prestashopMarker(ctx context.Context, definesPath string) (bool, error) {
	data, err := readCMSConfig(ctx, definesPath)
	if err != nil {
		return false, err
	}
	return strings.Contains(string(data), "_PS_ROOT_DIR_"), nil
}

// readPrestaShopCreds reads the live database credentials of the install at
// root. isShop is false when root is not a PrestaShop install, or is one with
// no configuration yet; an error with isShop true leaves the scan incomplete.
func readPrestaShopCreds(ctx context.Context, root string) (prestashopCreds, bool, error) {
	matched, err := prestashopMarker(ctx, filepath.Join(root, "config", "defines.inc.php"))
	if errors.Is(err, os.ErrNotExist) {
		return prestashopCreds{}, false, nil
	}
	if err != nil {
		return prestashopCreds{}, false, err
	}
	if !matched {
		return prestashopCreds{}, false, nil
	}
	creds, err := parsePrestaShopParameters(ctx, filepath.Join(root, "app", "config", "parameters.php"))
	if errors.Is(err, os.ErrNotExist) {
		// parameters.yml is the live config on 1.7.0 to 1.7.3; a settings.inc.php
		// beside it is a 1.6 leftover that may name a stale database.
		_, yamlErr := readCMSConfig(ctx, filepath.Join(root, "app", "config", "parameters.yml"))
		if yamlErr == nil {
			return prestashopCreds{}, true, errPrestaShopYAMLConfig
		}
		if !errors.Is(yamlErr, os.ErrNotExist) {
			return prestashopCreds{}, true, yamlErr
		}
		creds, err = parsePrestaShopSettingsInc(ctx, filepath.Join(root, "config", "settings.inc.php"))
		if errors.Is(err, os.ErrNotExist) {
			return prestashopCreds{}, false, nil
		}
	}
	if err != nil {
		return prestashopCreds{}, true, err
	}
	if creds.dbName == "" || creds.dbUser == "" || (creds.dbPrefix != "" && !validTablePrefix.MatchString(creds.dbPrefix)) {
		return prestashopCreds{}, true, errPrestaShopCreds
	}
	return creds, true, nil
}

// prestashopParamKeys are the only parameters.php entries ever looked up.
var prestashopParamKeys = []string{
	"database_host", "database_port", "database_name",
	"database_user", "database_password", "database_prefix",
}

type prestashopParamValue struct {
	value  string
	quoted bool
	found  bool
}

// parsePrestaShopParameters reads the database entries of parameters.php.
// PrestaShop writes the file with var_export after doubling every %, and its
// bootstrap halves them again, so the same is done here.
func parsePrestaShopParameters(ctx context.Context, path string) (prestashopCreds, error) {
	data, err := readCMSConfig(ctx, path)
	if err != nil {
		return prestashopCreds{}, err
	}
	vals, err := parsePrestaShopParameterValues(string(data))
	if err != nil {
		return prestashopCreds{}, err
	}
	for _, key := range []string{"database_name", "database_user", "database_prefix"} {
		if !vals[key].found || !vals[key].quoted {
			return prestashopCreds{}, fmt.Errorf("%w: %s", errPrestaShopCreds, key)
		}
	}
	for _, key := range []string{"database_host", "database_password"} {
		if vals[key].found && !vals[key].quoted {
			return prestashopCreds{}, fmt.Errorf("%w: %s", errPrestaShopCreds, key)
		}
	}
	value := func(key string) string { return strings.ReplaceAll(vals[key].value, "%%", "%") }
	host := value("database_host")
	if host == "" {
		host = "localhost"
	}
	// PrestaShop appends any port PHP does not treat as empty; the installer
	// stores a socket path here when the host was given as localhost:/path.
	if port := value("database_port"); port != "" && port != "0" {
		if !isAllDigits(port) && !strings.HasPrefix(port, "/") {
			return prestashopCreds{}, fmt.Errorf("%w: database_port", errPrestaShopCreds)
		}
		host += ":" + port
	}
	return prestashopCreds{
		dbName:   value("database_name"),
		dbUser:   value("database_user"),
		dbPass:   value("database_password"),
		dbHost:   host,
		dbPrefix: value("database_prefix"),
		path:     path,
	}, nil
}

// parsePrestaShopParameterValues accepts the returned parameters array only.
// Unrelated values stay opaque, including strings that resemble database keys.
func parsePrestaShopParameterValues(body string) (map[string]prestashopParamValue, error) {
	p := prestashopPHPParser{rest: body}
	if !p.take("<?php") || len(p.rest) == 0 || !strings.ContainsRune(" \t\r\n", rune(p.rest[0])) || !p.keyword("return") {
		return nil, errPrestaShopCreds
	}
	vals, ok := p.array(false)
	if !ok || !p.take(";") {
		return nil, errPrestaShopCreds
	}
	p.take("?>")
	if !p.space() || p.rest != "" {
		return nil, errPrestaShopCreds
	}
	return vals, nil
}

type prestashopPHPParser struct {
	rest string
}

func (p *prestashopPHPParser) space() bool {
	for {
		p.rest = strings.TrimLeft(p.rest, " \t\r\n\v\f")
		switch {
		case strings.HasPrefix(p.rest, "/*"):
			end := strings.Index(p.rest[2:], "*/")
			if end < 0 {
				return false
			}
			p.rest = p.rest[end+4:]
		case strings.HasPrefix(p.rest, "//"), strings.HasPrefix(p.rest, "#"):
			end := strings.IndexAny(p.rest, "\r\n")
			if end < 0 {
				p.rest = ""
			} else {
				p.rest = p.rest[end:]
			}
		default:
			return true
		}
	}
}

func (p *prestashopPHPParser) take(token string) bool {
	if !p.space() || !strings.HasPrefix(p.rest, token) {
		return false
	}
	p.rest = p.rest[len(token):]
	return true
}

func (p *prestashopPHPParser) keyword(word string) bool {
	if !p.space() || len(p.rest) < len(word) || !strings.EqualFold(p.rest[:len(word)], word) {
		return false
	}
	if len(p.rest) > len(word) {
		c := p.rest[len(word)]
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80 {
			return false
		}
	}
	p.rest = p.rest[len(word):]
	return true
}

func (p *prestashopPHPParser) arrayEnd() (string, bool) {
	if p.take("[") {
		return "]", true
	}
	if p.keyword("array") && p.take("(") {
		return ")", true
	}
	return "", false
}

func (p *prestashopPHPParser) array(parameters bool) (map[string]prestashopParamValue, bool) {
	end, ok := p.arrayEnd()
	if !ok {
		return nil, false
	}
	vals := make(map[string]prestashopParamValue)
	for !p.take(end) {
		key, quoted, rest, valid := parsePHPScalarLiteral(p.rest)
		if !valid || !quoted {
			return nil, false
		}
		p.rest = rest
		if !p.take("=>") || !p.space() {
			return nil, false
		}
		switch {
		case !parameters && key == "parameters":
			// A later parameters entry replaces the whole earlier array.
			vals, ok = p.array(true)
		case parameters && slices.Contains(prestashopParamKeys, key):
			var v prestashopParamValue
			v, ok = p.databaseValue(key)
			vals[key] = v
		default:
			ok = p.skipValue()
		}
		if !ok {
			return nil, false
		}
		if p.take(end) {
			return vals, true
		}
		if !p.take(",") {
			return nil, false
		}
	}
	return vals, true
}

func (p *prestashopPHPParser) databaseValue(key string) (prestashopParamValue, bool) {
	// PHP empty() also accepts an empty array for the port. No array values
	// are decoded or retained.
	if key == "database_port" && (strings.HasPrefix(p.rest, "[") || len(p.rest) >= 5 && strings.EqualFold(p.rest[:5], "array")) {
		end, ok := p.arrayEnd()
		return prestashopParamValue{found: true}, ok && p.take(end)
	}
	value, quoted, rest, ok := parsePHPScalarLiteral(p.rest)
	if !ok {
		return prestashopParamValue{}, false
	}
	p.rest = rest
	return prestashopParamValue{value: value, quoted: quoted, found: true}, true
}

// skipString walks a quoted token without decoding or retaining its value.
func (p *prestashopPHPParser) skipString() bool {
	if len(p.rest) == 0 || (p.rest[0] != '\'' && p.rest[0] != '"') {
		return false
	}
	quote := p.rest[0]
	for i := 1; i < len(p.rest); i++ {
		switch p.rest[i] {
		case '\\':
			i++
		case quote:
			p.rest = p.rest[i+1:]
			return true
		}
	}
	return false
}

// skipValue tracks delimiters iteratively so deeply nested unrelated values
// cannot exhaust the stack. Only the returned array and parameters recurse.
func (p *prestashopPHPParser) skipValue() bool {
	var ends []byte
	consumed := false
	for p.space() && len(p.rest) > 0 {
		c := p.rest[0]
		switch c {
		case '\'', '"':
			if !p.skipString() {
				return false
			}
			consumed = true
			continue
		case '(':
			ends = append(ends, ')')
		case '[':
			ends = append(ends, ']')
		case ')', ']':
			if len(ends) == 0 {
				return consumed
			}
			if ends[len(ends)-1] != c {
				return false
			}
			ends = ends[:len(ends)-1]
		case ',':
			if len(ends) == 0 {
				return consumed
			}
		case '=':
			if strings.HasPrefix(p.rest, "=>") {
				p.rest = p.rest[2:]
				consumed = true
				continue
			}
		case ';', '{', '}', '`', '<', '>':
			return false
		}
		consumed = true
		p.rest = p.rest[1:]
	}
	return false
}

// parsePHPScalarLiteral reads a string, a nonnegative PHP integer,
// or a PHP-empty scalar. It never evaluates an expression or interpolation.
func parsePHPScalarLiteral(s string) (value string, quoted bool, rest string, ok bool) {
	if s == "" {
		return "", false, "", false
	}
	switch quote := s[0]; quote {
	case '\'', '"':
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			c := s[i]
			switch {
			case c == quote:
				return b.String(), true, s[i+1:], true
			case c == '\\' && i+1 < len(s) && (s[i+1] == quote || s[i+1] == '\\'):
				i++
				b.WriteByte(s[i])
			case quote == '"' && (c == '\\' || c == '$'):
				return "", false, "", false
			default:
				b.WriteByte(c)
			}
		}
		return "", false, "", false
	}
	end := strings.IndexAny(s, " \t\r\n\v\f,)]/#")
	if end < 0 {
		end = len(s)
	}
	token := s[:end]
	switch {
	case strings.EqualFold(token, "null"), len(token) == len("false") && strings.EqualFold(token, "false"):
		return "", false, s[end:], true
	case isAllDigits(token):
		// PHP interprets a leading zero as octal and overflowing integers as
		// floats. Do not silently turn either into a different decimal port.
		base := 10
		if len(token) > 1 && token[0] == '0' {
			base = 8
		}
		if v, err := strconv.ParseUint(token, base, 63); err == nil {
			return strconv.FormatUint(v, 10), false, s[end:], true
		}
	case strings.Trim(token, "+-0123456789.eE") == "":
		if v, err := strconv.ParseFloat(token, 64); err == nil && v == 0 {
			return "", false, s[end:], true
		}
	}
	return "", false, "", false
}

// parsePrestaShopSettingsInc reads the 1.6 settings.inc.php defines. An empty
// prefix cannot be told apart from a missing one here, so it becomes ps_.
func parsePrestaShopSettingsInc(ctx context.Context, path string) (prestashopCreds, error) {
	creds := prestashopCreds{path: path}
	data, err := readCMSConfig(ctx, path)
	if err != nil {
		return prestashopCreds{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v := extractDefine(line, "_DB_SERVER_"); v != "" {
			creds.dbHost = v
		}
		if v := extractDefine(line, "_DB_NAME_"); v != "" {
			creds.dbName = v
		}
		if v := extractDefine(line, "_DB_USER_"); v != "" {
			creds.dbUser = v
		}
		if v := extractDefine(line, "_DB_PASSWD_"); v != "" {
			creds.dbPass = v
		}
		if v := extractDefine(line, "_DB_PREFIX_"); v != "" {
			creds.dbPrefix = v
		}
	}
	if creds.dbHost == "" {
		creds.dbHost = "localhost"
	}
	if creds.dbPrefix == "" {
		creds.dbPrefix = "ps_"
	}
	return creds, nil
}

// prestashopContentTable is one author-content table: one row per language
// and shop, keyed by idCol.
type prestashopContentTable struct {
	table, idCol string
	cols         []string
}

var prestashopContentTables = []prestashopContentTable{
	{"cms_lang", "id_cms", []string{"content"}},
	{"product_lang", "id_product", []string{"description", "description_short"}},
	// additional_description exists only from 8.x on, so it is not queried.
	{"category_lang", "id_category", []string{"description"}},
}

// prestashopFindingSet keeps one finding per identity, the most severe match
// winning, in first-seen order: a product injected in every language and shop
// is one finding.
type prestashopFindingSet struct {
	order []string
	byKey map[string]alert.Finding
}

func (s *prestashopFindingSet) add(key string, f alert.Finding) {
	if s.byKey == nil {
		s.byKey = map[string]alert.Finding{}
	}
	prev, seen := s.byKey[key]
	if !seen {
		s.order = append(s.order, key)
	}
	if !seen || f.Severity > prev.Severity {
		s.byKey[key] = f
	}
}

func (s *prestashopFindingSet) findings() []alert.Finding {
	out := make([]alert.Finding, 0, len(s.order))
	for _, key := range s.order {
		out = append(out, s.byKey[key])
	}
	return out
}

func prestashopFindingDetails(creds wpDBCreds, lines ...string) string {
	return dbContentFindingDetails(creds, creds.tablePrefix, append([]string{"Database host: " + creds.dbHost}, lines...)...)
}

// scanPrestaShopSettings scans configuration and configuration_lang values
// with the strict config-storage rules. Values are classified, never output:
// PS_MAIL_PASSWD is stored here in plain text.
func scanPrestaShopSettings(account string, creds prestashopCreds) []alert.Finding {
	w := creds.asWPDBCreds()
	p := creds.dbPrefix
	queries := []string{
		fmt.Sprintf("SELECT id_configuration, name, value FROM %sconfiguration WHERE %s", p, paramsLikeClause("value")),
		fmt.Sprintf("SELECT c.id_configuration, c.name, l.value FROM %sconfiguration_lang l JOIN %sconfiguration c ON c.id_configuration = l.id_configuration WHERE %s",
			p, p, paramsLikeClause("l.value")),
	}
	var set prestashopFindingSet
	for _, query := range queries {
		rows, _ := runCMSQuery(w, query)
		for _, row := range rows {
			fields := strings.SplitN(row, "\t", 3)
			if len(fields) < 3 || !isAllDigits(fields[0]) {
				continue
			}
			id, name := fields[0], fields[1]
			// Rows arrive batch-escaped; classify the stored value, or a tab
			// or newline inside a script tag hides it.
			sev, desc, ok := classifyMalwareRow(mysqlclient.BatchUnescape(fields[2]), false)
			if !ok {
				continue
			}
			set.add(id, alert.Finding{
				Severity: sev,
				Check:    "prestashop_settings_injection",
				Message:  fmt.Sprintf("PrestaShop settings injection on %s: %s (%s)", account, name, desc),
				Details: prestashopFindingDetails(w, "Account: "+account, "Setting key: "+name,
					"Setting id: "+id, "Match: "+desc),
				DedupKey: dbContentDedupKey(account, w, p, "prestashop-setting", "id="+id),
			})
		}
	}
	return set.findings()
}

// scanPrestaShopContent scans page, product and category text in every
// language and shop with the looser author-content rules.
func scanPrestaShopContent(account string, creds prestashopCreds) []alert.Finding {
	w := creds.asWPDBCreds()
	p := creds.dbPrefix
	var set prestashopFindingSet
	for _, t := range prestashopContentTables {
		for _, col := range t.cols {
			rows, _ := runCMSQuery(w, fmt.Sprintf("SELECT %s, %s FROM %s%s WHERE %s",
				t.idCol, col, p, t.table, paramsLikeClause(col)))
			for _, row := range rows {
				id, body := splitTabRow(row)
				if !isAllDigits(id) {
					continue
				}
				sev, desc, ok := classifyMalwareRow(mysqlclient.BatchUnescape(body), true)
				if !ok {
					continue
				}
				set.add(t.table+"\x00"+id, alert.Finding{
					Severity: sev,
					Check:    "prestashop_content_injection",
					Message:  fmt.Sprintf("PrestaShop content injection on %s: %s id=%s (%s)", account, t.table, id, desc),
					Details: prestashopFindingDetails(w, "Account: "+account, "Table: "+t.table,
						"Row id: "+id, "Match: "+desc),
					DedupKey: dbContentDedupKey(account, w, p, "prestashop-content", "table="+t.table, "id="+id),
				})
			}
		}
	}
	return set.findings()
}

const (
	// prestashopSuperAdminProfile is _PS_ADMIN_PROFILE_, unchanged from 1.6 to
	// 9.2. Profile names are localised, so the id is what identifies it.
	prestashopSuperAdminProfile  = "1"
	prestashopEventNewSuperAdmin = "new SuperAdmin"
	prestashopEventPromoted      = "promoted to SuperAdmin"
)

// scanPrestaShopEmployees baselines back-office employees like the other shop
// scanners and reports a new or promoted SuperAdmin as Critical. Password
// hashes are never selected.
func scanPrestaShopEmployees(store *state.Store, account string, creds prestashopCreds) []alert.Finding {
	w := creds.asWPDBCreds()
	rows, complete := runCMSQuery(w, fmt.Sprintf("SELECT id_employee, id_profile, email FROM %semployee", creds.dbPrefix))
	describe := func(fields []string) (string, string) {
		return fmt.Sprintf("PrestaShop employee on %s: id_employee=%s", account, fields[0]),
			fmt.Sprintf("Account: %s\nRow: %s\nReview: confirm this is a legitimate back-office employee.", account, strings.Join(fields, "\t"))
	}
	// Promotions are judged before the shared baseline records this pass's
	// new ids, so a new SuperAdmin is reported once, by the new-employee path.
	findings := prestashopPromotions(store, account, w, rows, complete, describe)
	return append(findings, cmsAdminFindingsEscalated(store, "prestashop", "prestashop_admin_injection", account, w, rows, complete, describe,
		func(fields []string) (alert.Severity, string, bool) {
			if len(fields) > 1 && fields[1] == prestashopSuperAdminProfile {
				return alert.Critical, prestashopEventNewSuperAdmin, true
			}
			return 0, "", false
		})...)
}

// prestashopPromotions reports known employees that moved to the SuperAdmin
// profile since the recorded set. The set changes only after a complete
// result; a demotion drops the id, so a later re-promotion alerts again.
func prestashopPromotions(store *state.Store, account string, w wpDBCreds, rows []string, complete bool,
	describe func(fields []string) (string, string)) []alert.Finding {
	if store == nil {
		return nil
	}
	setKey := "_pssuperadmin:v1:" + dbContentDedupKey(account, w, w.tablePrefix, "cms-admin=prestashop", "superadmins")
	stored, recorded := store.GetRaw(setKey)
	known := map[string]bool{}
	for _, id := range strings.Split(stored, ",") {
		known[id] = id != ""
	}
	var current []string
	seen := map[string]bool{}
	var findings []alert.Finding
	for _, row := range rows {
		fields := strings.Split(row, "\t")
		id := fields[0]
		if !isAllDigits(id) {
			complete = false
			continue
		}
		if len(fields) < 2 || fields[1] != prestashopSuperAdminProfile || seen[id] {
			continue
		}
		seen[id] = true
		current = append(current, id)
		if !recorded || known[id] {
			continue
		}
		if _, existing := store.GetRaw(cmsAdminSeenKey(account, w, "prestashop", id)); !existing {
			continue
		}
		message, details := describe(fields)
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "prestashop_admin_injection",
			Message:  message + " (" + prestashopEventPromoted + ")",
			Details:  prestashopFindingDetails(w, details) + "\nEvent: " + prestashopEventPromoted,
			DedupKey: dbContentDedupKey(account, w, w.tablePrefix, "cms-admin=prestashop", "id="+id, "event="+prestashopEventPromoted),
		})
	}
	if complete {
		sort.Strings(current)
		store.SetRaw(setKey, strings.Join(current, ","))
	}
	return findings
}
