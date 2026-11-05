package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

func TestPHPRelayOrderListQuery(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		staff bool
	}{
		{"orders", "page=wc-orders", true},
		{"order edit", "page=wc-orders&action=edit&id=5", true},
		{"custom order type", "page=wc-orders--shop_subscription", true},
		{"encoded page", "%70age=wc%2Dorders", true},
		{"other array", "page=wc-orders&filters[]=pending", true},
		{"truncated tail", "page=wc-orders&" + strings.Repeat("x=&", 1000), true},
		{"nul name", "page=wc-orders&page%00=subscriber-dashboard", false},
		{"nul name suffix", "page=wc-orders&page%00ignored=subscriber-dashboard", false},
		{"space and nul name", "page=wc-orders&%20page%00ignored=subscriber-dashboard", false},
		{"nul before array", "page=wc-orders&page%00[]=subscriber-dashboard", false},
		{"encoded nul name", "page=wc-orders&%70age%00=subscriber-dashboard", false},
		{"truncated page", strings.Repeat("x=&", 1000) + "page=wc-orders", false},
		// PHP's input limit is site-specific. Only a leading page parameter
		// survives every positive limit, even when the rest is discarded.
		{"nonleading page", "status=all&page=wc-orders", false},
		{"duplicate page", "page=wc-orders&page=subscriber-dashboard", false},
		{"array page", "page=wc-orders&page[]=subscriber-dashboard", false},
		{"missing page", "status=all", false},
		{"bad escape", "page=wc-orders&x=%zz", false},
		{"semicolon separator", "page=wc-orders;page=subscriber-dashboard", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := checks.CrawlLogRecord{Method: "GET", Status: 200, Target: "/wp-admin/admin.php?" + tc.query}
			if got := isStaffAdminRequest(rec); got != tc.staff {
				t.Fatalf("staff = %v, want %v for query %q", got, tc.staff, tc.query)
			}
		})
	}
}
