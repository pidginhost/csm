package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

func psVerifyDetails(details string) string {
	return "Database: shop_db\nTable prefix: ps_\nDatabase host: localhost\n" + details
}

func psVerifyCases() []cmsCase {
	return []cmsCase{
		{name: "settings", verify: verifyPrestaShopSettingsInjection, details: "Account: bob\nSetting id: 12"},
		{name: "page", verify: verifyPrestaShopContentInjection, details: "Account: bob\nTable: cms_lang\nRow id: 42"},
		{name: "product", verify: verifyPrestaShopContentInjection, details: "Account: bob\nTable: product_lang\nRow id: 42"},
		{name: "category", verify: verifyPrestaShopContentInjection, details: "Account: bob\nTable: category_lang\nRow id: 42"},
		{name: "employee", verify: verifyPrestaShopAdminInjection, details: "Account: bob\nRow: 9\t4\tstaff@example.test"},
		{name: "new SuperAdmin", verify: verifyPrestaShopAdminInjection, details: "Account: bob\nRow: 9\t1\tstaff@example.test\nEvent: new SuperAdmin"},
		{name: "promotion", verify: verifyPrestaShopAdminInjection, details: "Account: bob\nRow: 9\t1\tstaff@example.test\nEvent: promoted to SuperAdmin"},
	}
}

func withPSVerifyQuery(t *testing.T, fn func(schema, query string, args ...any) ([]string, error)) {
	t.Helper()
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, c mysqlclient.Creds, query string, args ...any) ([]string, error) {
		return fn(c.DBName, query, args...)
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
}

func TestPrestaShopRecheckRejectsDifferentDatabase(t *testing.T) {
	for _, c := range psVerifyCases() {
		for _, field := range []string{"Database: shop_db", "Table prefix: ps_", "Database host: localhost"} {
			for _, missing := range []bool{false, true} {
				name := c.name + "/" + field
				if missing {
					name += "/missing"
				}
				t.Run(name, func(t *testing.T) {
					withCMSVerifyOS(t, prestashopVerifyFiles(), nil)
					queries := 0
					query := func(string, string, ...any) ([]string, error) {
						queries++
						return nil, nil // The unrelated canonical database is clean.
					}
					withRootQuery(t, query)
					withPSVerifyQuery(t, query)
					replacement := field + "_other"
					if missing {
						replacement = ""
					}
					details := strings.Replace(psVerifyDetails(c.details), field, replacement, 1)
					res := c.verify("", details)
					if res.Checked || res.Resolved || queries != 0 {
						t.Fatalf("different or missing database identity: result=%+v queries=%d", res, queries)
					}
				})
			}
		}
	}
}

func TestPrestaShopRecheckUsesConfiguredEndpoint(t *testing.T) {
	for _, c := range psVerifyCases() {
		for _, host := range []string{"localhost", "192.0.2.40:3307", "localhost:/run/mysql/shop.sock"} {
			t.Run(c.name+"/"+host, func(t *testing.T) {
				files := prestashopVerifyFiles()
				files["/home/bob/public_html/app/config/parameters.php"] = psParamsBody(map[string]string{"database_host": "'" + host + "'"})
				withCMSVerifyOS(t, files, nil)
				rootQueries, shopQueries := 0, 0
				withRootQuery(t, func(string, string, ...any) ([]string, error) {
					rootQueries++
					return nil, nil // A local schema with the same name is clean.
				})
				mysqlclient.SetPerAccountQueryForTest(func(ctx context.Context, creds mysqlclient.Creds, _ string, _ ...any) ([]string, error) {
					shopQueries++
					if creds.Host != host || creds.DBName != "shop_db" || creds.User != "shop_user" {
						t.Fatal("re-check lost the configured endpoint or account")
					}
					if _, ok := ctx.Deadline(); !ok {
						t.Fatal("re-check has no deadline")
					}
					return []string{psPayload()}, nil
				})
				t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
				details := strings.Replace(psVerifyDetails(c.details), "Database host: localhost", "Database host: "+host, 1)
				res := c.verify("", details)
				if !res.Checked || res.Resolved || shopQueries != 1 || rootQueries != 0 {
					t.Fatalf("result=%+v shop queries=%d root queries=%d", res, shopQueries, rootQueries)
				}
			})
		}
	}
}

func TestPrestaShopRecheckQueryErrorsStayUnchecked(t *testing.T) {
	for _, c := range psVerifyCases() {
		t.Run(c.name, func(t *testing.T) {
			withCMSVerifyOS(t, prestashopVerifyFiles(), nil)
			calls := 0
			withPSVerifyQuery(t, func(string, string, ...any) ([]string, error) {
				calls++
				return []string{"clean partial result"}, context.DeadlineExceeded
			})
			res := c.verify("", psVerifyDetails(c.details))
			if res.Checked || res.Resolved || calls != 1 {
				t.Fatalf("query error: result=%+v calls=%d", res, calls)
			}
		})
	}
}

func TestPrestaShopRecheckCoversEveryValue(t *testing.T) {
	for _, tc := range []struct {
		name, details, query string
		verify               func(string, string) VerifyResult
		id                   string
		argCount             int
	}{
		{"settings", "Setting id: 12", "SELECT value FROM `ps_configuration` WHERE id_configuration = ? UNION ALL SELECT value FROM `ps_configuration_lang` WHERE id_configuration = ?", verifyPrestaShopSettingsInjection, "12", 2},
		{"page", "Table: cms_lang\nRow id: 42", "SELECT content FROM `ps_cms_lang` WHERE id_cms = ?", verifyPrestaShopContentInjection, "42", 1},
		{"product", "Table: product_lang\nRow id: 42", "SELECT description FROM `ps_product_lang` WHERE id_product = ? UNION ALL SELECT description_short FROM `ps_product_lang` WHERE id_product = ?", verifyPrestaShopContentInjection, "42", 2},
		{"category", "Table: category_lang\nRow id: 42", "SELECT description FROM `ps_category_lang` WHERE id_category = ?", verifyPrestaShopContentInjection, "42", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withCMSVerifyOS(t, prestashopVerifyFiles(), nil)
			// A later language, shop or product column must keep the finding open.
			rows := []string{"ordinary text", `<script src\t="https://192.0.2.40/fixture-loader.js"></script>`}
			calls := 0
			withPSVerifyQuery(t, func(schema, query string, args ...any) ([]string, error) {
				calls++
				if schema != "shop_db" || query != tc.query || len(args) != tc.argCount {
					t.Fatalf("schema=%q query=%q args=%v", schema, query, args)
				}
				for _, arg := range args {
					if arg != tc.id {
						t.Fatalf("row argument=%v, want %s", arg, tc.id)
					}
				}
				return rows, nil
			})
			details := psVerifyDetails("Account: bob\n" + tc.details)
			if res := tc.verify("", details); !res.Checked || res.Resolved {
				t.Fatalf("later injected row: %+v", res)
			}
			// Escaped literal backslashes must not be decoded twice into whitespace.
			rows[1] = `<script src\\t="https://192.0.2.40/fixture-loader.js"></script>`
			if res := tc.verify("", details); !res.Checked || !res.Resolved {
				t.Fatalf("all rows clean: %+v", res)
			}
			if calls != 2 {
				t.Fatalf("queries=%d, want 2", calls)
			}
		})
	}
}
