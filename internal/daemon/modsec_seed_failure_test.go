package daemon

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
	bolt "go.etcd.io/bbolt"
)

// A nonfatal seed failure must retain HTTP deny findings without treating an
// unreadable operator exclusion list as permission to ban visitors.
func TestParseModSec_UnreadableExclusionsDoNotBan(t *testing.T) {
	for _, server := range []string{"apache", "litespeed"} {
		for _, rule := range []int{900134, 900133, 942100} {
			t.Run(server+"/"+strconv.Itoa(rule), func(t *testing.T) {
				resetModSecState()
				t.Cleanup(resetModSecState)
				dir := t.TempDir()
				raw, err := bolt.Open(filepath.Join(dir, "csm.db"), 0600, &bolt.Options{Timeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				err = raw.Update(func(tx *bolt.Tx) error {
					meta, createErr := tx.CreateBucketIfNotExists([]byte("meta"))
					if createErr != nil {
						return createErr
					}
					return meta.Put([]byte("modsec:no_escalate_rules"), []byte(`[900500,`))
				})
				closeErr := raw.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("prepare unreadable exclusions: %v, close: %v", err, closeErr)
				}
				db, err := store.Open(dir)
				if err != nil {
					t.Fatalf("optional seed failure must not stop startup: %v", err)
				}
				previous := store.Global()
				store.SetGlobal(db)
				t.Cleanup(func() {
					store.SetGlobal(previous)
					_ = db.Close()
				})
				installModSecRegistryForTest(t, map[int]string{rule: "deny"})
				line := modsecApacheLine("203.0.113.68", strconv.Itoa(rule), "Denied request", "attack-sqli")
				if server == "litespeed" {
					line = strings.Replace(liteSpeedTriggerLine210710, `"210710"`, `"`+strconv.Itoa(rule)+`"`, 1)
					if rule == 942100 {
						line = strings.Replace(line, "02_Global_Generic.conf", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", 1)
					}
				}
				cfg := &config.Config{}
				cfg.Thresholds.ModSecEscalationHits = 3
				for hit := 0; hit < 6; hit++ {
					findings := parseModSecLogLineDeduped(line, cfg)
					if hit == 0 {
						if len(findings) != 1 || findings[0].Check != "modsec_block_realtime" {
							t.Errorf("first deny = %+v, want only HTTP deny finding", findings)
						}
					} else if len(findings) != 0 {
						t.Errorf("deny %d with unreadable exclusions emitted %+v", hit, findings)
					}
				}
				// Repair the list without restarting; no evidence collected while
				// exclusions were unreadable may count towards a later ban.
				if err := db.SetModSecNoEscalateRules(map[int]bool{}); err != nil {
					t.Fatal(err)
				}
				wantHits := cfg.Thresholds.ModSecEscalationHits
				if rule == 900133 {
					wantHits = 1
				}
				for hit := 1; hit <= wantHits; hit++ {
					findings := parseModSecLogLineDeduped(line, cfg)
					if hit < wantHits {
						if len(findings) != 0 {
							t.Errorf("retained unreadable-period evidence caused findings: %+v", findings)
						}
					} else {
						wantCheck := "modsec_csm_block_escalation"
						if rule == 942100 {
							wantCheck = "modsec_block_escalation"
						}
						if len(findings) != 1 || findings[0].Check != wantCheck {
							t.Errorf("repaired exclusions deny %d = %+v, want %s", hit, findings, wantCheck)
						}
					}
				}
			})
		}
	}
}
