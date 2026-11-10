package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

func TestPrestaShopOverflowKeepsIndependentQueries(t *testing.T) {
	targets := []struct {
		query, row, check string
	}{
		{"FROM ps_employee", "", "prestashop_admin_injection"},
		{"FROM ps_configuration WHERE", "12\tPS_HEAD_JS\t", "prestashop_settings_injection"},
		{"FROM ps_configuration_lang l", "13\tPS_FOOTER_JS\t", "prestashop_settings_injection"},
		{"content FROM ps_cms_lang", "42\t", "prestashop_content_injection"},
		{"description FROM ps_product_lang", "42\t", "prestashop_content_injection"},
		{"description_short FROM ps_product_lang", "43\t", "prestashop_content_injection"},
		{"description FROM ps_category_lang", "42\t", "prestashop_content_injection"},
	}
	for _, overflow := range targets {
		t.Run(overflow.query, func(t *testing.T) {
			withAccountHomeRoots(t, "/home")
			withCMSConfigOS(t, &twoOwnerCMSOS{files: prestashopInstallFiles(psTestRoot, "ps_")})
			calls := 0
			// Keep the real query wrapper: replacing it would bypass the
			// installation's shared failure state and hide skipped queries.
			mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
				calls++
				if !strings.HasSuffix(query, fmt.Sprintf(" LIMIT %d", cmsScanRowLimit+1)) {
					t.Errorf("unbounded query: %s", query)
				}
				for _, target := range targets {
					if !strings.Contains(query, target.query) {
						continue
					}
					if target.query == overflow.query {
						if target.check == "prestashop_admin_injection" {
							return psEmployeeRows(cmsScanRowLimit + 1), nil
						}
						// Clean embeds pass the SQL prefilter. Filling this
						// result must not conceal injections in other tables.
						rows := make([]string, cmsScanRowLimit+1)
						for i := range rows {
							row := fmt.Sprintf("%d\t", i+100)
							if target.check == "prestashop_settings_injection" {
								row += fmt.Sprintf("PS_WIDGET_%d\t", i)
							}
							rows[i] = row + `<script src="https://www.googletagmanager.com/gtag/js?id=G-XYZ"></script>`
						}
						return rows, nil
					}
					if target.check == "prestashop_admin_injection" {
						return psBaselineRows, nil
					}
					return []string{target.row + psPayload()}, nil
				}
				t.Fatalf("unexpected query: %s", query)
				return nil, nil
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			ctx, coverage := withIncompleteCheckCollector(context.Background())
			got := CheckPrestaShopContent(ctx, &config.Config{}, newCrontabTestStore(t))
			for check, count := range map[string]int{
				"prestashop_admin_injection":    0,
				"prestashop_settings_injection": 2,
				"prestashop_content_injection":  4,
			} {
				if check == overflow.check && count > 0 {
					count--
				}
				if n := len(psFindings(got, check)); n != count {
					t.Errorf("%s findings = %d, want %d", check, n, count)
				}
			}
			if calls != len(targets) {
				t.Errorf("issued %d queries, want %d", calls, len(targets))
			}
			if !coverage.contains(prestashopOwner) || coverage.contains("db_content") {
				t.Error("overflow did not retain the PrestaShop coverage gap")
			}
		})
	}
}
