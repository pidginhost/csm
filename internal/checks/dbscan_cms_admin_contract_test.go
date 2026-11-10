package checks

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestCMSAdminLegacyContract(t *testing.T) {
	messages := map[string]string{
		"joomla":   "Joomla Super User account on alice: %s",
		"drupal":   "Drupal administrator account on alice: %s",
		"magento":  "Magento  admin account on alice: user_id=%s",
		"opencart": "OpenCart admin account on alice: user_id=%s",
	}
	for _, adapter := range cmsAdminScanners() {
		message, legacy := messages[adapter.name]
		if !legacy {
			continue
		}
		t.Run(adapter.name, func(t *testing.T) {
			s := newCrontabTestStore(t)
			creds := wpDBCreds{dbHost: "localhost", dbName: "site", tablePrefix: "cms_"}
			if adapter.name == "drupal" {
				creds.tablePrefix = ""
			}
			rows := []string{"1\tadmin\tadmin@example.test"}
			withCapturedQueries(t, func(string) []string { return rows })
			want := func(id, row string, sev alert.Severity) alert.Finding {
				f := alert.Finding{
					Severity: sev,
					Check:    adapter.name + "_admin_injection",
					Message:  fmt.Sprintf(message, id),
					Details: "Database: site\nTable prefix: " + creds.tablePrefix +
						"\nDatabase host: localhost\nAccount: alice\nRow: " + row +
						"\nReview: confirm this is the legitimate site administrator.",
					DedupKey: dbContentDedupKey("alice", creds, creds.tablePrefix, "cms-admin="+adapter.name, "id="+id),
				}
				if sev == alert.High {
					f.Message = "New " + f.Message
					f.Details += "\nThis administrator was not present when the install was baselined."
				}
				return f
			}
			if got := adapter.scan(nil, "alice", creds); !reflect.DeepEqual(got, []alert.Finding{want("1", rows[0], alert.Warning)}) {
				t.Fatalf("storeless finding changed: %+v", got)
			}
			if got := adapter.scan(s, "alice", creds); len(got) != 0 {
				t.Fatalf("baseline produced findings: %+v", got)
			}
			baselineKey := "_cmsadmin_baseline:v2:" + dbContentDedupKey("alice", creds, creds.tablePrefix, "cms-admin="+adapter.name)
			if value, ok := s.GetRaw(baselineKey); !ok || value != "1" {
				t.Fatalf("baseline state changed: %q, %v", value, ok)
			}
			rows = append(rows, "2\tstaff\tstaff@example.test")
			if got := adapter.scan(s, "alice", creds); !reflect.DeepEqual(got, []alert.Finding{want("2", rows[1], alert.High)}) {
				t.Fatalf("new administrator finding changed: %+v", got)
			}
			for i, id := range []string{"1", "2"} {
				key := "_cmsadmin:v2:" + want(id, rows[i], alert.High).DedupKey
				if value, ok := s.GetRaw(key); !ok || value != "seen" {
					t.Errorf("seen state for %s changed: %q, %v", id, value, ok)
				}
			}
			if got := adapter.scan(s, "alice", creds); len(got) != 0 {
				t.Fatalf("unchanged administrator findings repeated: %+v", got)
			}
		})
	}
}
