package daemon

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/attackdb"
)

// A broad infrastructure range must not trigger a full database scan for
// every matching record before the daemon can start its watchers.
func BenchmarkForgetInfraAttackRecords(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			records := make(map[string]*attackdb.IPRecord, count)
			for i := range count {
				ip := fmt.Sprintf("2001:db8::%x", i)
				records[ip] = &attackdb.IPRecord{IP: ip}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				db := attackdb.NewForTest(records)
				b.StartTimer()
				if got := forgetInfraAttackRecords(db, []string{"2001:db8::/32"}); got != count {
					b.Fatalf("removed %d records, want %d", got, count)
				}
				b.StopTimer()
				db.Stop()
				b.StartTimer()
			}
		})
	}
}
