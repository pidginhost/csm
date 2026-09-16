package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// The snapshot worker follows Export's local-file copy lifetime. It does not
// include compression or client I/O. Run with -cpu=4 -benchtime=2s -count=3.
func BenchmarkFirewallSnapshot(b *testing.B) {
	for _, count := range []int{100, 1000} {
		for _, mode := range []string{"serial", "contended", "snapshot"} {
			b.Run(fmt.Sprintf("rows=%d/%s", count, mode), func(b *testing.B) {
				dir := b.TempDir()
				db, openErr := Open(dir)
				if openErr != nil {
					b.Fatal(openErr)
				}
				defer func() { _ = db.Close() }()
				state := completeFirewallState()
				for i := len(state.Blocked); i < count; i++ {
					state.Blocked = append(state.Blocked, firewall.BlockedEntry{IP: fmt.Sprintf("2001:db8::%x", i), Reason: "benchmark", Source: "manual"})
				}
				if _, err := db.ReplaceFirewallState(0, state); err != nil {
					b.Fatal(err)
				}
				beforeWait := storageMetric(b, "csm_storage_firewall_write_wait_seconds_sum")
				beforeTx := storageMetric(b, "csm_storage_firewall_write_transaction_seconds_sum")
				beforeConflicts := storageMetric(b, "csm_storage_firewall_conflicts_total")
				var copies int
				var copyTotal, copyMax time.Duration
				stop := make(chan struct{})
				workerErrors := make(chan error, 1)
				var worker sync.WaitGroup
				if mode == "snapshot" {
					file, createErr := os.Create(filepath.Join(b.TempDir(), "snapshot"))
					if createErr != nil {
						b.Fatal(createErr)
					}
					worker.Go(func() {
						defer func() { _ = file.Close() }()
						for {
							select {
							case <-stop:
								return
							default:
							}
							if err := file.Truncate(0); err != nil {
								workerErrors <- err
								return
							}
							if _, err := file.Seek(0, 0); err != nil {
								workerErrors <- err
								return
							}
							start := time.Now()
							err := db.bolt.View(func(tx *bolt.Tx) error { _, err := tx.WriteTo(file); return err })
							if err != nil {
								workerErrors <- err
								return
							}
							duration := time.Since(start)
							copies++
							copyTotal += duration
							if duration > copyMax {
								copyMax = duration
							}
						}
					})
				}
				mutate := func() {
					for {
						next, revision, err := db.ReadFirewallState()
						if err != nil {
							b.Error(err)
							return
						}
						next.Blocked[0].Reason = fmt.Sprintf("revision %d", revision)
						if _, err := db.ReplaceFirewallState(revision, next); err == nil {
							return
						} else if !errors.Is(err, firewall.ErrStateConflict) {
							b.Error(err)
							return
						}
					}
				}
				b.ResetTimer()
				if mode == "serial" {
					for i := 0; i < b.N; i++ {
						mutate()
					}
				} else {
					b.RunParallel(func(pb *testing.PB) {
						for pb.Next() {
							mutate()
						}
					})
				}
				b.StopTimer()
				close(stop)
				worker.Wait()
				select {
				case err := <-workerErrors:
					b.Fatal(err)
				default:
				}
				b.ReportMetric((storageMetric(b, "csm_storage_firewall_write_wait_seconds_sum")-beforeWait)*1e6/float64(b.N), "wait-us/op")
				b.ReportMetric((storageMetric(b, "csm_storage_firewall_write_transaction_seconds_sum")-beforeTx)*1e6/float64(b.N), "tx-us/op")
				b.ReportMetric((storageMetric(b, "csm_storage_firewall_conflicts_total")-beforeConflicts)/float64(b.N), "conflicts/op")
				b.ReportMetric(float64(db.SizeBytes()), "db-bytes")
				if copies > 0 {
					b.ReportMetric(float64(copyTotal.Microseconds())/float64(copies), "copy-us")
					b.ReportMetric(float64(copyMax.Microseconds()), "copy-max-us")
				}
				got, revision, finalErr := db.ReadFirewallState()
				if finalErr != nil || revision != uint64(b.N)+1 || len(got.Blocked) != count {
					b.Fatalf("lost update: revision %d, blocks %d, error %v", revision, len(got.Blocked), finalErr)
				}
			})
		}
	}
}
