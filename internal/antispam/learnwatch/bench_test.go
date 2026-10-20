//go:build linux

package learnwatch

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// largeFolderEntries is the largest Spam folder spike S8 found on a
// production host.
const largeFolderEntries = 51217

func floodFolder(b *testing.B, f *watchFixture, i, n int, tag string) {
	b.Helper()
	cur := filepath.Join(f.accounts[i].Home, "mail/.spam/cur")
	for j := range n {
		writeMsg(b, filepath.Join(cur, fmt.Sprintf("%d.M%d.%s:2,S", 1600000000+j, j, tag)), nil)
	}
}

func freshState(b *testing.B, f *watchFixture) {
	b.Helper()
	if err := f.db.ResetLearnWatch(); err != nil {
		b.Fatal(err)
	}
	f.restart()
}

// BenchmarkDiscoveryLargeFolder baselines a large synthetic folder: one pass
// lists, stats and records every entry in DiscoveryChunk batches.
func BenchmarkDiscoveryLargeFolder(b *testing.B) {
	f := newWatch(b, 1)
	f.submit = false
	floodFolder(b, f, 0, largeFolderEntries, "large")
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		freshState(b, f)
		b.StartTimer()
		if r := f.pass(); r.Unfinished {
			b.Fatalf("baseline pass unfinished: %+v", r)
		}
		b.StopTimer()
		if err := f.cfg.State.View(func(tx StateTx) error {
			n, err := tx.CountSeen(f.accounts[0].UID)
			if err == nil && n != largeFolderEntries {
				b.Fatalf("baseline recorded %d entries, want %d", n, largeFolderEntries)
			}
			return err
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/largeFolderEntries, "ns/entry")
}

// BenchmarkSeenBytesPerEntry records pending identities for a large
// folder and reports the logical bytes each one adds.
func BenchmarkSeenBytesPerEntry(b *testing.B) {
	k := FolderKey{UID: 1001, Folder: ".spam"}
	db, err := store.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	st := NewState(db, time.Now)
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		if err = db.ResetLearnWatch(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if err = st.Update(func(tx StateTx) error {
			if _, _, e := tx.Open(k, "cur", DirIdent{Dev: 1, Ino: 2}); e != nil {
				return e
			}
			return tx.FinishBaseline(k)
		}); err != nil {
			b.Fatal(err)
		}
		for start := 0; start < largeFolderEntries; start += DiscoveryChunk {
			if err = st.Update(func(tx StateTx) error {
				for j := start; j < min(start+DiscoveryChunk, largeFolderEntries); j++ {
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
		b.StopTimer()
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
		b.ReportMetric(float64(size)/largeFolderEntries, "bytes/entry")
	}
}

// BenchmarkSchedulerFloodRotation measures how long a one-report account
// waits for its submission while another account lists a large synthetic
// folder of new arrivals.
func BenchmarkSchedulerFloodRotation(b *testing.B) {
	f := newWatch(b, 2)
	var totalWait time.Duration
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		freshState(b, f)
		// Rewriting a file neither changes its identity nor dirties its
		// directory. Each iteration needs arrivals after an empty baseline.
		for _, a := range f.accounts {
			spam := filepath.Join(a.Home, "mail/.spam")
			if err := os.RemoveAll(spam); err != nil {
				b.Fatal(err)
			}
			for _, sub := range Subdirs {
				if err := os.MkdirAll(filepath.Join(spam, sub), 0o700); err != nil {
					b.Fatal(err)
				}
			}
		}
		turnHook = func(int, string) {}
		f.engine.calls = nil
		if r := f.pass(); r.Unfinished || r.Submitted != 0 {
			b.Fatalf("empty baseline failed: %+v", r)
		}
		floodFolder(b, f, 0, largeFolderEntries, "flood")
		f.deliver(1, "new", 1, spamBody)
		var waited time.Duration
		chunks, chunksBeforeSubmit := 0, 0
		var start time.Time
		turnHook = func(uid int, kind string) {
			if uid == 1001 && kind == "chunk" {
				chunks++
			}
			if uid == 1002 && kind == "submit" && waited == 0 {
				waited = time.Since(start)
				chunksBeforeSubmit = chunks
			}
		}
		b.StartTimer()
		start = time.Now()
		r := f.pass()
		b.StopTimer()
		calls := f.engine.submitted()
		if waited == 0 || r.Unfinished || r.Submitted != MaxAttempts+1 || r.Pending != largeFolderEntries-MaxAttempts ||
			countUID(calls, 1001) != MaxAttempts || countUID(calls, 1002) != 1 {
			b.Fatalf("flood pass failed: %+v, second account waited %s", r, waited)
		}
		if chunksBeforeSubmit == 0 || chunksBeforeSubmit >= chunks || chunks < (largeFolderEntries+DiscoveryChunk-1)/DiscoveryChunk {
			b.Fatalf("flood was not listed: %d chunks before submission, %d total", chunksBeforeSubmit, chunks)
		}
		totalWait += waited
	}
	b.ReportMetric(float64(totalWait.Nanoseconds())/float64(b.N)/1000, "us/second-account")
}
