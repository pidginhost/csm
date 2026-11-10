package checks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// psOmit drops a key from psParamsBody.
const psOmit = "\x00omit"

var psParamOrder = []string{
	"database_host", "database_port", "database_name", "database_user",
	"database_password", "database_prefix", "database_engine",
}

var psParamDefaults = map[string]string{
	"database_host":     "'localhost'",
	"database_port":     "''",
	"database_name":     "'shop_db'",
	"database_user":     "'shop_user'",
	"database_password": "'fixture-db-pass'",
	"database_prefix":   "'ps_'",
	"database_engine":   "'InnoDB'",
}

// psParamsBody renders a parameters.php shaped like PrestaShop's var_export
// output. Values are raw PHP literal text; psOmit removes a key. The trailing
// entries carry fake secrets that must never be extracted.
func psParamsBody(over map[string]string) string {
	var b strings.Builder
	b.WriteString("<?php return array (\n  'parameters' => \n  array (\n")
	for _, key := range psParamOrder {
		lit, ok := over[key]
		if !ok {
			lit = psParamDefaults[key]
		}
		if lit == psOmit {
			continue
		}
		fmt.Fprintf(&b, "    '%s' => %s,\n", key, lit)
	}
	b.WriteString("    'mailer_password' => 'fixture-secret-mailer',\n")
	b.WriteString("    'secret' => 'fixture-secret-app',\n")
	b.WriteString("    'cookie_key' => 'fixture-secret-cookie',\n")
	b.WriteString("    'api_private_key' => '-----BEGIN FIXTURE KEY-----\nfixture-secret-pem-line-one\nfixture-secret-pem-line-two\n-----END FIXTURE KEY-----',\n")
	b.WriteString("    'database_password_old' => 'fixture-secret-decoy',\n")
	b.WriteString("  ),\n);\n")
	return b.String()
}

func prestashopParametersPHP(prefix string) string {
	return psParamsBody(map[string]string{"database_prefix": "'" + prefix + "'"})
}

func prestashopDefinesPHP() string {
	return "<?php\n$currentDir = dirname(__FILE__);\nif (!defined('_PS_ROOT_DIR_')) {\n    define('_PS_ROOT_DIR_', realpath($currentDir.'/..'));\n}\ndefine('_PS_ADMIN_PROFILE_', 1);\n"
}

func prestashopSettingsIncPHP(dbName, prefix string) string {
	return "<?php\ndefine('_DB_SERVER_', 'localhost');\ndefine('_DB_NAME_', '" + dbName + "');\ndefine('_DB_USER_', 'old_user');\ndefine('_DB_PASSWD_', 'fixture-old-pass');\ndefine('_DB_PREFIX_', '" + prefix + "');\n"
}

func prestashopInstallFiles(root, prefix string) map[string]string {
	return map[string]string{
		root + "/config/defines.inc.php":    prestashopDefinesPHP(),
		root + "/app/config/parameters.php": prestashopParametersPHP(prefix),
	}
}

const psTestRoot = "/home/alice/public_html"

func parsePSParamsBody(t *testing.T, body string) (prestashopCreds, error) {
	t.Helper()
	path := psTestRoot + "/app/config/parameters.php"
	withCMSConfigOS(t, &twoOwnerCMSOS{files: map[string]string{path: body}})
	return parsePrestaShopParameters(context.Background(), path)
}

func readPSRoot(t *testing.T, files map[string]string) (prestashopCreds, bool, error) {
	t.Helper()
	withCMSConfigOS(t, &twoOwnerCMSOS{files: files})
	return readPrestaShopCreds(context.Background(), psTestRoot)
}

func TestParsePrestaShopParametersReadsSixKeys(t *testing.T) {
	creds, err := parsePSParamsBody(t, prestashopParametersPHP("ps_"))
	if err != nil {
		t.Fatal(err)
	}
	if creds.dbName != "shop_db" || creds.dbUser != "shop_user" || creds.dbPass != "fixture-db-pass" ||
		creds.dbHost != "localhost" || creds.dbPrefix != "ps_" {
		t.Fatalf("creds = name %q user %q host %q prefix %q", creds.dbName, creds.dbUser, creds.dbHost, creds.dbPrefix)
	}
}

func TestParsePrestaShopParametersIgnoresOtherKeys(t *testing.T) {
	creds, err := parsePSParamsBody(t, prestashopParametersPHP("ps_"))
	if err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%+v", creds)
	for _, leak := range []string{"fixture-secret-", "FIXTURE KEY"} {
		if strings.Contains(dump, leak) {
			t.Fatalf("credentials carry a value from another key (%s)", leak)
		}
	}
}

func TestParsePrestaShopParametersEscapes(t *testing.T) {
	for _, tc := range []struct {
		key, lit, want string
	}{
		{"database_password", `'pa\'ss\\wo%%rd'`, `pa'ss\wo%rd`},
		{"database_password", `"dq\"pw"`, `dq"pw`},
		{"database_password", `'back\slash'`, `back\slash`},
		{"database_name", `'shop%%db'`, `shop%db`},
	} {
		creds, err := parsePSParamsBody(t, psParamsBody(map[string]string{tc.key: tc.lit}))
		if err != nil {
			t.Fatalf("%s %s: %v", tc.key, tc.lit, err)
		}
		got := creds.dbPass
		if tc.key == "database_name" {
			got = creds.dbName
		}
		if got != tc.want {
			t.Errorf("%s %s = %q, want %q", tc.key, tc.lit, got, tc.want)
		}
	}
}

func TestParsePrestaShopParametersRejectsUnsupportedLiterals(t *testing.T) {
	for _, tc := range []struct {
		name, key, lit string
	}{
		{"interpolation", "database_password", `"pw$x"`},
		{"other escape", "database_password", `"a\nb"`},
		{"concatenation", "database_password", `'a' . 'b'`},
		{"unterminated", "database_password", `'abc`},
		{"name missing", "database_name", psOmit},
		{"prefix missing", "database_prefix", psOmit},
		{"prefix null", "database_prefix", "NULL"},
		{"name integer", "database_name", "42"},
		{"port word", "database_port", "'abc'"},
		{"port suffix", "database_port", "'3307x'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePSParamsBody(t, psParamsBody(map[string]string{tc.key: tc.lit}))
			if err == nil {
				t.Fatalf("%s %s accepted", tc.key, tc.lit)
			}
			for _, part := range []string{"pw$x", "a.b", "abc", "3307x"} {
				if strings.Contains(err.Error(), part) {
					t.Errorf("error %q quotes a configuration value", err)
				}
			}
		})
	}
}

func TestParsePrestaShopParametersPort(t *testing.T) {
	for _, tc := range []struct {
		host, port, want string
	}{
		{"'localhost'", "''", "localhost"},
		{"'localhost'", "NULL", "localhost"},
		{"'localhost'", psOmit, "localhost"},
		{"'localhost'", "'0'", "localhost"},
		{"'localhost'", "0", "localhost"},
		{"'localhost'", "'3307'", "localhost:3307"},
		{"'localhost'", "3307", "localhost:3307"},
		{"'localhost'", "'/var/lib/mysql/mysql.sock'", "localhost:/var/lib/mysql/mysql.sock"},
		{"''", "'3307'", "localhost:3307"},
		{"'db.example.test'", "'3307'", "db.example.test:3307"},
	} {
		creds, err := parsePSParamsBody(t, psParamsBody(map[string]string{"database_host": tc.host, "database_port": tc.port}))
		if err != nil {
			t.Fatalf("host %s port %q: %v", tc.host, tc.port, err)
		}
		if creds.dbHost != tc.want {
			t.Errorf("host %s port %q = %q, want %q", tc.host, tc.port, creds.dbHost, tc.want)
		}
	}
}

func TestParsePrestaShopParametersEmptyPrefixMeansUnprefixed(t *testing.T) {
	creds, err := parsePSParamsBody(t, prestashopParametersPHP(""))
	if err != nil || creds.dbPrefix != "" {
		t.Fatalf("empty prefix = %q, %v; want unprefixed", creds.dbPrefix, err)
	}
}

func TestParsePrestaShopParametersShortArrayAndCRLF(t *testing.T) {
	body := "<?php return [\r\n  'parameters' => [\r\n" +
		"    'database_host' => 'localhost',\r\n    'database_port' => '',\r\n" +
		"    'database_name' => 'shop_db',\r\n    'database_user' => 'shop_user',\r\n" +
		"    'database_password' => 'fixture-db-pass',\r\n    'database_prefix' => 'ps_'\r\n  ]\r\n];\r\n"
	creds, err := parsePSParamsBody(t, body)
	if err != nil {
		t.Fatal(err)
	}
	if creds.dbName != "shop_db" || creds.dbUser != "shop_user" || creds.dbPass != "fixture-db-pass" ||
		creds.dbHost != "localhost" || creds.dbPrefix != "ps_" {
		t.Fatalf("short-array CRLF config parsed to name %q user %q host %q prefix %q", creds.dbName, creds.dbUser, creds.dbHost, creds.dbPrefix)
	}
}

func TestParsePrestaShopParametersHostAlreadyHasPort(t *testing.T) {
	creds, err := parsePSParamsBody(t, psParamsBody(map[string]string{"database_host": "'localhost:3307'"}))
	if err != nil || creds.dbHost != "localhost:3307" {
		t.Fatalf("host = %q, %v; want localhost:3307 unchanged", creds.dbHost, err)
	}
}

func TestParsePrestaShopSettingsInc(t *testing.T) {
	path := psTestRoot + "/config/settings.inc.php"
	body := prestashopSettingsIncPHP("old_db", "") + "define('_DB_PASSWD_', 'a%%b');\n"
	withCMSConfigOS(t, &twoOwnerCMSOS{files: map[string]string{path: body}})
	creds, err := parsePrestaShopSettingsInc(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if creds.dbName != "old_db" || creds.dbUser != "old_user" || creds.dbHost != "localhost" || creds.dbPrefix != "ps_" {
		t.Fatalf("settings.inc.php creds = name %q user %q host %q prefix %q", creds.dbName, creds.dbUser, creds.dbHost, creds.dbPrefix)
	}
	if creds.dbPass != "a%%b" {
		t.Errorf("settings.inc.php password = %q, want a%%%%b unchanged", creds.dbPass)
	}
}

func TestReadPrestaShopCredsPrefersParametersPHP(t *testing.T) {
	files := prestashopInstallFiles(psTestRoot, "ps_")
	files[psTestRoot+"/config/settings.inc.php"] = prestashopSettingsIncPHP("old_db", "ps_")
	creds, isShop, err := readPSRoot(t, files)
	if err != nil || !isShop {
		t.Fatalf("isShop %v err %v", isShop, err)
	}
	if creds.dbName != "shop_db" || !strings.HasSuffix(creds.path, "app/config/parameters.php") {
		t.Fatalf("read %q from %s, want shop_db from parameters.php", creds.dbName, creds.path)
	}
}

func TestReadPrestaShopCredsYAMLOnlyIsIncomplete(t *testing.T) {
	_, isShop, err := readPSRoot(t, map[string]string{
		psTestRoot + "/config/defines.inc.php":    prestashopDefinesPHP(),
		psTestRoot + "/app/config/parameters.yml": "parameters:\n    database_name: shop_db\n",
		psTestRoot + "/config/settings.inc.php":   prestashopSettingsIncPHP("old_db", "ps_"),
	})
	if !isShop || !errors.Is(err, errPrestaShopYAMLConfig) {
		t.Fatalf("isShop %v err %v; want the YAML-config error", isShop, err)
	}
}

func TestReadPrestaShopCredsFallsBackToSettingsInc(t *testing.T) {
	creds, isShop, err := readPSRoot(t, map[string]string{
		psTestRoot + "/config/defines.inc.php":  prestashopDefinesPHP(),
		psTestRoot + "/config/settings.inc.php": prestashopSettingsIncPHP("old_db", "ps_"),
	})
	if err != nil || !isShop || creds.dbName != "old_db" {
		t.Fatalf("creds %q isShop %v err %v; want old_db from settings.inc.php", creds.dbName, isShop, err)
	}
}

func TestReadPrestaShopCredsRequiresMarker(t *testing.T) {
	files := prestashopInstallFiles(psTestRoot, "ps_")
	files[psTestRoot+"/config/defines.inc.php"] = "<?php\ndefine('APP_ROOT', __DIR__);\n"
	if _, isShop, err := readPSRoot(t, files); isShop || err != nil {
		t.Fatalf("defines without the marker: isShop %v err %v", isShop, err)
	}
	delete(files, psTestRoot+"/config/defines.inc.php")
	if _, isShop, err := readPSRoot(t, files); isShop || err != nil {
		t.Fatalf("no defines file: isShop %v err %v", isShop, err)
	}
}

func TestReadPrestaShopCredsNoConfigIsNotAShop(t *testing.T) {
	_, isShop, err := readPSRoot(t, map[string]string{psTestRoot + "/config/defines.inc.php": prestashopDefinesPHP()})
	if isShop || err != nil {
		t.Fatalf("marker without config: isShop %v err %v", isShop, err)
	}
}

func TestReadPrestaShopCredsRejectsBadPrefix(t *testing.T) {
	files := prestashopInstallFiles(psTestRoot, "ps-x")
	if _, isShop, err := readPSRoot(t, files); !isShop || !errors.Is(err, errPrestaShopCreds) {
		t.Fatalf("bad prefix: isShop %v err %v", isShop, err)
	}
}

func TestReadPrestaShopCredsMissingUser(t *testing.T) {
	files := prestashopInstallFiles(psTestRoot, "ps_")
	files[psTestRoot+"/app/config/parameters.php"] = psParamsBody(map[string]string{"database_user": "''"})
	if _, isShop, err := readPSRoot(t, files); !isShop || !errors.Is(err, errPrestaShopCreds) {
		t.Fatalf("empty user: isShop %v err %v", isShop, err)
	}
}
