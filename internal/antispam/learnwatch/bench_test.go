//go:build linux

package learnwatch

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// s8Largest is the largest Spam folder S8 found on the production host.
const s8Largest = 51217

func floodFolder(b *testing.B, f *watchFixture, i, n int, tag string) {
	b.Helper()
	cur := filepath.Join(f.accounts[i].Home, "mail/.spam/cur")
	for j := range n {
		writeMsg(b, filepath.Join(cur, fmt.Sprintf("%d.M%d.%s:2,S", 1600000000+j, j, tag)), nil)
	}
}

func freshState(b *testing.B, f *watchFixture) {
	b.Helper()
	db, err := store.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	f.cfg.State = NewState(db, f.clock)
	f.restart()
}

// BenchmarkDiscoveryLargeFolder baselines S8's largest folder: one pass
// lists, stats and records every entry in DiscoveryChunk batches.
func BenchmarkDiscoveryLargeFolder(b *testing.B) {
	f := newWatch(b, 1)
	f.submit = false
	floodFolder(b, f, 0, s8Largest, "large")
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		freshState(b, f)
		b.StartTimer()
		if r := f.pass(); r.Unfinished {
			b.Fatalf("baseline pass unfinished: %+v", r)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/s8Largest, "ns/entry")
}

// BenchmarkSeenBytesPerEntry records seen identities for S8's largest
// folder and reports the logical bytes each one adds.
func BenchmarkSeenBytesPerEntry(b *testing.B) {
	k := FolderKey{UID: 1001, Folder: ".spam"}
	for range b.N {
		db, err := store.Open(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		st := NewState(db, time.Now)
		if err = st.Update(func(tx StateTx) error {
			if _, _, e := tx.Open(k, "cur", DirIdent{Dev: 1, Ino: 2}); e != nil {
				return e
			}
			return tx.FinishBaseline(k)
		}); err != nil {
			b.Fatal(err)
		}
		for start := 0; start < s8Largest; start += DiscoveryChunk {
			if err = st.Update(func(tx StateTx) error {
				for j := start; j < min(start+DiscoveryChunk, s8Largest); j++ {
					name := fmt.Sprintf("%d.M%d.host.example.com,S=4096:2,S", 1600000000+j, j)
					// #nosec G115 -- benchmark counter
					if _, _, e := tx.Observe(k, "cur", name, Meta{Dev: 1, Ino: uint64(j + 10), Size: 4096, MtimeNs: 1, CtimeNs: 1}); e != nil {
						return e
					}
				}
				return nil
			}); err != nil {
				b.Fatal(err)
			}
		}
		var size int64
		if err = db.LearnView(func(tx store.LearnTx) error {
			for _, name := range store.WatchBuckets {
				if e := tx.ForEach(name, func(key, val []byte) error {
					size += int64(len(key) + len(val))
					return nil
				}); e != nil {
					return e
				}
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(size)/s8Largest, "bytes/entry")
		_ = db.Close()
	}
}

// BenchmarkSchedulerFloodRotation measures how long a one-report account
// waits for its submission while another account lists S8's largest
// folder of new arrivals.
func BenchmarkSchedulerFloodRotation(b *testing.B) {
	f := newWatch(b, 2)
	for range b.N {
		b.StopTimer()
		freshState(b, f)
		f.pass()
		floodFolder(b, f, 0, s8Largest, fmt.Sprintf("flood%d", b.N))
		f.deliver(1, "new", 1, spamBody)
		var waited time.Duration
		start := time.Now()
		turnHook = func(uid int, kind string) {
			if uid == 1002 && kind == "submit" && waited == 0 {
				waited = time.Since(start)
			}
		}
		b.StartTimer()
		f.pass()
		b.StopTimer()
		if waited == 0 {
			b.Fatal("the second account was never submitted")
		}
		b.ReportMetric(float64(waited.Microseconds()), "us/second-account")
	}
}
