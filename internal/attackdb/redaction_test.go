package attackdb

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func TestRecordFindingRedactsBeforePersistenceAndTruncation(t *testing.T) {
	for _, backend := range []string{"jsonl", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			store.SetGlobal(nil)
			t.Cleanup(func() { store.SetGlobal(nil) })
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			db := newTestDB(t)
			for _, text := range []struct{ in, want string }{
				{"password=message-fixture", "password=[REDACTED]"},
				// The service tag lies beyond the stored message limit. It must
				// still gate redaction before truncation removes that context.
				{"log: NEW shop:session-fixture " + strings.Repeat("x", 200) + " [cpaneld]",
					"log: NEW shop:[REDACTED] " + strings.Repeat("x", 175)},
			} {
				f := alert.Finding{
					Check: "ssh_login_realtime", Severity: alert.Warning, Timestamp: time.Now().UTC(),
					Message: text.in, Details: "Account: shop", SourceIP: "198.51.100.23",
				}
				db.RecordFinding(f)
				want := Event{
					Timestamp: f.Timestamp, IP: f.SourceIP, AttackType: checkToAttack[f.Check],
					CheckName: f.Check, Severity: int(f.Severity), Account: "shop", Message: text.want,
				}
				if !reflect.DeepEqual(db.pendingEvents, []Event{want}) {
					t.Errorf("queued events = %+v, want %+v", db.pendingEvents, want)
				}
				if err := db.Flush(); err != nil {
					t.Fatal(err)
				}
				if got := db.QueryEvents(f.SourceIP, 1); !reflect.DeepEqual(got, []Event{want}) {
					t.Errorf("persisted events = %+v, want %+v", got, want)
				}
			}
			if got := db.LookupIP("198.51.100.23"); got == nil || got.EventCount != 2 || got.Accounts["shop"] != 2 {
				t.Errorf("redaction changed attack attribution: %+v", got)
			}
		})
	}
}
