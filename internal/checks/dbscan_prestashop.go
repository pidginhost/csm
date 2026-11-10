package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

var prestashopParamRes = func() map[string]*regexp.Regexp {
	out := make(map[string]*regexp.Regexp, len(prestashopParamKeys))
	for _, key := range prestashopParamKeys {
		out[key] = regexp.MustCompile(`(?:'` + key + `'|"` + key + `")\s*=>\s*`)
	}
	return out
}()

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
	body := string(data)
	vals := make(map[string]prestashopParamValue, len(prestashopParamKeys))
	for _, key := range prestashopParamKeys {
		v, err := prestashopParam(body, key)
		if err != nil {
			return prestashopCreds{}, err
		}
		vals[key] = v
	}
	for _, key := range []string{"database_name", "database_user", "database_prefix"} {
		if !vals[key].found || !vals[key].quoted {
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

// prestashopParam returns the last `'key' => literal` entry in body, as PHP
// keeps the last of duplicate array keys. Comments are not interpreted;
// var_export writes none.
func prestashopParam(body, key string) (prestashopParamValue, error) {
	matches := prestashopParamRes[key].FindAllStringIndex(body, -1)
	if len(matches) == 0 {
		return prestashopParamValue{}, nil
	}
	value, quoted, rest, ok := parsePHPScalarLiteral(body[matches[len(matches)-1][1]:])
	rest = strings.TrimLeft(rest, " \t\r\n")
	if !ok || rest == "" || !strings.ContainsRune(",)]", rune(rest[0])) {
		return prestashopParamValue{}, fmt.Errorf("%w: %s", errPrestaShopCreds, key)
	}
	return prestashopParamValue{value: value, quoted: quoted, found: true}, nil
}

// parsePHPScalarLiteral reads one literal at the start of s: a single-quoted
// string, a double-quoted string without interpolation or escapes other than
// \" and \\, NULL, or a run of digits.
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
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] >= 'A' && s[end] <= 'Z' || s[end] >= 'a' && s[end] <= 'z' || s[end] == '_') {
		end++
	}
	token := s[:end]
	switch {
	case strings.EqualFold(token, "null"):
		return "", false, s[end:], true
	case isAllDigits(token):
		return token, false, s[end:], true
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
