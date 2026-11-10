package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Database rows arrive batch-escaped: a real tab or newline in a stored value
// reaches the scanner as the two characters `\t` or `\n`. A script tag split by
// such whitespace must still be recognised.
const (
	cmsDecodeRaw   = "<script src\t=\"https://192.0.2.40/fixture-loader.js\"></script>"
	cmsDecodeBatch = `<script src\t="https://192.0.2.40/fixture-loader.js"></script>`
)

func TestCMSScansDecodeBatchValues(t *testing.T) {
	for _, tc := range []struct {
		name, rowPrefix string
		inPost          bool
		scan            func() []alert.Finding
	}{
		{"opencart settings", "config_url\t", false, func() []alert.Finding {
			return scanOpenCartSettings("alice", opencartCreds{dbName: "oc", dbPrefix: "oc_"})
		}},
		{"opencart content", "42\t", true, func() []alert.Finding {
			return scanOpenCartContentTable("alice", opencartCreds{dbName: "oc", dbPrefix: "oc_"}, "product_description", "description")
		}},
		{"magento settings", "web/unsecure/base_url\t", false, func() []alert.Finding {
			return scanMagentoSettings("alice", magentoCreds{dbName: "m"})
		}},
		{"magento content", "42\t", true, func() []alert.Finding {
			return scanMagentoContent("alice", magentoCreds{dbName: "m"}, "cms_page", "content")
		}},
		{"joomla extensions", "plg_fixture\t", false, func() []alert.Finding {
			return scanJoomlaExtensions("alice", jConfigCreds{dbName: "j"}, "jos_")
		}},
		{"joomla content", "42\tFixture title\t", true, func() []alert.Finding {
			return scanJoomlaContent("alice", jConfigCreds{dbName: "j"}, "jos_")
		}},
		{"drupal config", "system.site\t", false, func() []alert.Finding {
			return scanDrupalConfig("alice", drupalCreds{dbName: "d"})
		}},
		{"drupal content", "42\t", true, func() []alert.Finding {
			return scanDrupalContent("alice", drupalCreds{dbName: "d"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := classifyMalwareRow(cmsDecodeRaw, tc.inPost); !ok {
				t.Fatal("fixture does not classify as its stored value")
			}
			withCapturedQueries(t, func(string) []string { return []string{tc.rowPrefix + cmsDecodeBatch} })
			if got := tc.scan(); len(got) != 1 {
				t.Fatalf("findings = %d, want 1 for the stored value", len(got))
			}
		})
	}
}

func TestCMSRecheckDecodesBatchRows(t *testing.T) {
	withRootQuery(t, func(string, string, ...any) ([]string, error) {
		return []string{cmsDecodeBatch}, nil
	})
	if res := dbVerifyRowMalware("shop_db", "SELECT 1", true); !res.Checked || res.Resolved {
		t.Fatalf("batch-escaped injection = %+v, want unresolved", res)
	}
}
