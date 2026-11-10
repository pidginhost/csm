package checks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
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

func psScanCreds(prefix string) prestashopCreds {
	return prestashopCreds{dbHost: "localhost", dbName: "shop_db", dbUser: "shop_user", dbPrefix: prefix}
}

func psPayload() string { return evalToken + "(base64_decode('cGF5bG9hZA=='));" }

func psFindings(findings []alert.Finding, check string) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func TestPrestaShopSettingsScanBothTables(t *testing.T) {
	withCapturedQueries(t, func(q string) []string {
		switch {
		case strings.Contains(q, "configuration_lang"):
			return []string{"12\tPS_HEAD_JS\t" + psPayload(), "13\tPS_FOOTER\t" + psPayload()}
		case strings.Contains(q, "FROM ps_configuration"):
			return []string{"12\tPS_HEAD_JS\t" + psPayload()}
		}
		return nil
	})
	got := scanPrestaShopSettings("alice", psScanCreds("ps_"))
	if len(got) != 2 {
		t.Fatalf("findings = %d, want one per setting id: %+v", len(got), got)
	}
	all := got[0].Details + "\n" + got[1].Details
	for _, want := range []string{"Setting key: PS_HEAD_JS", "Setting id: 12", "Setting id: 13", "Database: shop_db", "Table prefix: ps_", "Account: alice"} {
		if !strings.Contains(all, want) {
			t.Errorf("details missing %q:\n%s", want, all)
		}
	}
	for _, f := range got {
		if f.Check != "prestashop_settings_injection" || f.DedupKey == "" {
			t.Errorf("finding = %+v", f)
		}
	}
}

func TestPrestaShopSettingsNeverOutputsValue(t *testing.T) {
	const marker = "fixture-config-value-5521"
	withCapturedQueries(t, func(q string) []string {
		if strings.Contains(q, "configuration") {
			return []string{"12\tPS_MAIL_PASSWD\t" + marker + " " + psPayload()}
		}
		return nil
	})
	got := scanPrestaShopSettings("alice", psScanCreds("ps_"))
	if len(got) == 0 {
		t.Fatal("injected setting not reported")
	}
	for _, f := range got {
		if strings.Contains(f.Message+f.Details+f.DedupKey, marker) {
			t.Fatalf("setting value reached the finding: %+v", f)
		}
	}
}

func TestPrestaShopSettingsLangQueryJoinsName(t *testing.T) {
	queries := withCapturedQueries(t, func(string) []string { return nil })
	scanPrestaShopSettings("alice", psScanCreds("ps_"))
	for _, q := range *queries {
		if strings.Contains(q, "configuration_lang") {
			if !strings.Contains(q, "ps_configuration_lang l JOIN ps_configuration c") {
				t.Errorf("lang query does not join the setting name: %s", q)
			}
			return
		}
	}
	t.Fatal("configuration_lang was not queried")
}

func TestPrestaShopSettingsValueWithTab(t *testing.T) {
	withCapturedQueries(t, func(q string) []string {
		if strings.Contains(q, "FROM ps_configuration WHERE") {
			return []string{"14\tPS_X\tcol1\tcol2 " + psPayload()}
		}
		return nil
	})
	got := scanPrestaShopSettings("alice", psScanCreds("ps_"))
	if len(got) != 1 || !strings.Contains(got[0].Details, "Setting key: PS_X\n") || !strings.Contains(got[0].Details, "Setting id: 14\n") {
		t.Fatalf("tabbed value = %+v", got)
	}
}

func TestPrestaShopSettingsSuppressesScriptOnlyFP(t *testing.T) {
	withCapturedQueries(t, func(q string) []string {
		if strings.Contains(q, "configuration") {
			return []string{"20\tPS_HEAD_JS\t<script src=\"https://www.googletagmanager.com/gtag/js?id=G-XYZ\"></script>"}
		}
		return nil
	})
	if got := scanPrestaShopSettings("alice", psScanCreds("ps_")); len(got) != 0 {
		t.Fatalf("Tag Manager embed classified as malicious: %+v", got)
	}
}

func TestPrestaShopContentOneFindingPerProduct(t *testing.T) {
	withCapturedQueries(t, func(q string) []string {
		if !strings.Contains(q, "FROM ps_product_lang") {
			return nil
		}
		if strings.Contains(q, "description_short") {
			return []string{"42\t" + psPayload()}
		}
		return []string{"42\t" + psPayload(), "42\t" + psPayload(), "42\t" + psPayload()}
	})
	got := scanPrestaShopContent("alice", psScanCreds("ps_"))
	if len(got) != 1 || got[0].Check != "prestashop_content_injection" ||
		!strings.Contains(got[0].Details, "Table: product_lang\n") || !strings.Contains(got[0].Details, "Row id: 42\n") {
		t.Fatalf("findings = %+v, want one for product_lang 42", got)
	}
}

func TestPrestaShopContentCoversAllTables(t *testing.T) {
	queries := withCapturedQueries(t, func(string) []string { return nil })
	scanPrestaShopContent("alice", psScanCreds("ps_"))
	joined := strings.Join(*queries, "\n")
	for _, want := range []string{"id_cms, content FROM ps_cms_lang", "id_product, description FROM ps_product_lang", "id_product, description_short FROM ps_product_lang", "id_category, description FROM ps_category_lang"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing query %q in:\n%s", want, joined)
		}
	}
	for _, banned := range []string{"additional_description", "id_lang", "id_shop"} {
		if strings.Contains(joined, banned) {
			t.Errorf("content query names %s", banned)
		}
	}
}

func TestPrestaShopContentIdentityIsStable(t *testing.T) {
	withCapturedQueries(t, func(q string) []string {
		if strings.Contains(q, "FROM ps_product_lang") && !strings.Contains(q, "description_short") ||
			strings.Contains(q, "FROM ps_cms_lang") {
			return []string{"42\t" + psPayload()}
		}
		return nil
	})
	first := scanPrestaShopContent("alice", psScanCreds("ps_"))
	second := scanPrestaShopContent("alice", psScanCreds("ps_"))
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("findings = %d then %d, want 2", len(first), len(second))
	}
	if first[0].DedupKey != second[0].DedupKey || first[1].DedupKey != second[1].DedupKey {
		t.Error("identity changed between identical scans")
	}
	if first[0].DedupKey == first[1].DedupKey {
		t.Error("cms_lang 42 and product_lang 42 share an identity")
	}
}

func TestPrestaShopScansUnprefixedTables(t *testing.T) {
	queries := withCapturedQueries(t, func(string) []string { return nil })
	scanPrestaShopSettings("alice", psScanCreds(""))
	scanPrestaShopContent("alice", psScanCreds(""))
	joined := strings.Join(*queries, "\n")
	for _, want := range []string{"FROM configuration ", "FROM product_lang "} {
		if !strings.Contains(joined, want) {
			t.Errorf("unprefixed query %q missing in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "FROM _") {
		t.Error("an empty prefix produced an underscore table name")
	}
}

// psEmployeeRows returns ids 1..n with profile 4, except the listed ids with
// the SuperAdmin profile.
func psEmployeeRows(n int, superAdmins ...int) []string {
	super := map[int]bool{}
	for _, id := range superAdmins {
		super[id] = true
	}
	rows := make([]string, 0, n)
	for id := 1; id <= n; id++ {
		profile := "4"
		if super[id] {
			profile = "1"
		}
		rows = append(rows, fmt.Sprintf("%d\t%s\temployee%d@example.test", id, profile, id))
	}
	return rows
}

func psCritical(findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Severity == alert.Critical {
			out = append(out, f)
		}
	}
	return out
}

type psEmployeeHarness struct {
	t     *testing.T
	store *state.Store
	rows  []string
}

func newPSEmployeeHarness(t *testing.T) *psEmployeeHarness {
	h := &psEmployeeHarness{t: t, store: newCrontabTestStore(t)}
	withCapturedQueries(t, func(string) []string { return h.rows })
	return h
}

func (h *psEmployeeHarness) scan(rows ...string) []alert.Finding {
	h.rows = rows
	return scanPrestaShopEmployees(h.store, "alice", psScanCreds("ps_"))
}

var psBaselineRows = []string{"1\t1\towner@example.test", "2\t4\tstaff@example.test"}

func TestPrestaShopEmployeesBaselineIsQuiet(t *testing.T) {
	h := newPSEmployeeHarness(t)
	if got := h.scan(psBaselineRows...); len(got) != 0 {
		t.Fatalf("baseline pass reported %+v", got)
	}
}

func TestPrestaShopNewEmployeeIsHigh(t *testing.T) {
	h := newPSEmployeeHarness(t)
	h.scan(psBaselineRows...)
	rows := append(append([]string(nil), psBaselineRows...), "3\t4\tnew@example.test")
	got := h.scan(rows...)
	if len(got) != 1 || got[0].Severity != alert.High || !strings.Contains(got[0].Message, "id_employee=3") || strings.Contains(got[0].Details, "Event:") {
		t.Fatalf("new employee = %+v, want one High without an event", got)
	}
	if again := h.scan(rows...); len(again) != 0 {
		t.Fatalf("new employee repeated: %+v", again)
	}
}

func TestPrestaShopNewSuperAdminIsOneCritical(t *testing.T) {
	h := newPSEmployeeHarness(t)
	h.scan(psBaselineRows...)
	rows := append(append([]string(nil), psBaselineRows...), "5\t1\tx@example.test")
	got := h.scan(rows...)
	if len(got) != 1 || got[0].Severity != alert.Critical || got[0].Check != "prestashop_admin_injection" ||
		!strings.Contains(got[0].Details, "Event: new SuperAdmin") || !strings.Contains(got[0].Details, "Row: 5\t1\t") {
		t.Fatalf("new SuperAdmin = %+v, want exactly one Critical", got)
	}
	if again := h.scan(rows...); len(again) != 0 {
		t.Fatalf("new SuperAdmin repeated: %+v", again)
	}
}

func TestPrestaShopPromotionIsCritical(t *testing.T) {
	h := newPSEmployeeHarness(t)
	h.scan(psBaselineRows...)
	promoted := []string{"1\t1\towner@example.test", "2\t1\tstaff@example.test"}
	got := h.scan(promoted...)
	if len(got) != 1 || got[0].Severity != alert.Critical || !strings.Contains(got[0].Details, "Event: promoted to SuperAdmin") {
		t.Fatalf("promotion = %+v, want one Critical", got)
	}
	plain := dbContentDedupKey("alice", psScanCreds("ps_").asWPDBCreds(), "ps_", "cms-admin=prestashop", "id=2")
	if got[0].DedupKey == "" || got[0].DedupKey == plain {
		t.Errorf("promotion shares the new-employee identity %q", plain)
	}
	if again := h.scan(promoted...); len(again) != 0 {
		t.Fatalf("promotion repeated: %+v", again)
	}
}

func TestPrestaShopRepromotionAfterDemotionAlertsAgain(t *testing.T) {
	h := newPSEmployeeHarness(t)
	h.scan(psBaselineRows...)
	promoted := []string{"1\t1\towner@example.test", "2\t1\tstaff@example.test"}
	if got := psCritical(h.scan(promoted...)); len(got) != 1 {
		t.Fatalf("first promotion = %+v", got)
	}
	if got := h.scan(psBaselineRows...); len(got) != 0 {
		t.Fatalf("demotion reported %+v", got)
	}
	if got := psCritical(h.scan(promoted...)); len(got) != 1 {
		t.Fatalf("re-promotion = %+v, want one Critical", got)
	}
}

func TestPrestaShopPartialResultDoesNotMoveSuperAdminSet(t *testing.T) {
	h := newPSEmployeeHarness(t)
	if got := h.scan(psEmployeeRows(200, 1)...); len(got) != 0 {
		t.Fatalf("baseline = %+v", got)
	}
	if got := psCritical(h.scan(psEmployeeRows(201, 1, 2)...)); len(got) != 1 || !strings.Contains(got[0].Message, "id_employee=2") {
		t.Fatalf("partial pass = %+v, want the promotion of id 2", got)
	}
	if got := psCritical(h.scan(psEmployeeRows(200, 1, 2)...)); len(got) != 1 {
		t.Fatalf("complete pass after a partial one = %+v, want the promotion again", got)
	}
	if got := psCritical(h.scan(psEmployeeRows(200, 1, 2)...)); len(got) != 0 {
		t.Fatalf("recorded promotion repeated: %+v", got)
	}
}

func TestPrestaShopEmptyEmployeeBaselineThenSuperAdmin(t *testing.T) {
	h := newPSEmployeeHarness(t)
	if got := h.scan(); len(got) != 0 {
		t.Fatalf("empty baseline = %+v", got)
	}
	got := h.scan("7\t1\tx@example.test")
	if len(got) != 1 || got[0].Severity != alert.Critical || !strings.Contains(got[0].Details, "Event: new SuperAdmin") {
		t.Fatalf("SuperAdmin after an empty baseline = %+v, want one Critical", got)
	}
}

func TestPrestaShopEmployeesWithoutStoreWarnPerRow(t *testing.T) {
	withCapturedQueries(t, func(string) []string { return psBaselineRows })
	got := scanPrestaShopEmployees(nil, "alice", psScanCreds("ps_"))
	if len(got) != 2 {
		t.Fatalf("findings = %+v, want one per row", got)
	}
	for _, f := range got {
		if f.Severity != alert.Warning {
			t.Errorf("storeless finding severity = %v, want Warning", f.Severity)
		}
	}
}

func TestPrestaShopEmployeeQuerySkipsPassword(t *testing.T) {
	queries := withCapturedQueries(t, func(string) []string { return nil })
	scanPrestaShopEmployees(nil, "alice", psScanCreds("ps_"))
	if len(*queries) != 1 || !strings.Contains((*queries)[0], "SELECT id_employee, id_profile, email FROM ps_employee") || strings.Contains((*queries)[0], "passwd") {
		t.Fatalf("employee queries = %v", *queries)
	}
}
