package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// writeSnapshot writes a stopped database at path holding a browser session,
// a pending firewall rollback and one firewall row, every bucket the snapshot
// readers visit, plus a bucket nested on a page of its own. Without a synced
// freelist, bbolt rebuilds it on open by walking the pages.
func writeSnapshot(t *testing.T, path string, noFreelistSync bool) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second, NoFreelistSync: noFreelistSync})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, row := range [][3]string{
			{browserSessionsBucket, "session", "verifier"},
			{fwRollbackBucket, fwRollbackKey, "{}"},
			{"fw:blocked", "192.0.2.1", "{}"},
		} {
			bucket, createErr := tx.CreateBucketIfNotExists([]byte(row[0]))
			if createErr != nil {
				return createErr
			}
			if putErr := bucket.Put([]byte(row[1]), []byte(row[2])); putErr != nil {
				return putErr
			}
		}
		parent, createErr := tx.CreateBucketIfNotExists([]byte("parent"))
		if createErr != nil {
			return createErr
		}
		nested, createErr := parent.CreateBucketIfNotExists([]byte("nested"))
		if createErr != nil {
			return createErr
		}
		for i := range 2 * os.Getpagesize() / 8 {
			if putErr := nested.Put(fmt.Appendf(nil, "%08d", i), []byte("row")); putErr != nil {
				return putErr
			}
		}
		return nil
	})
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
}

// truncatePages cuts the database at path after its two meta pages, so the
// mapped pages past the end fault instead of reading garbage.
func truncatePages(t *testing.T, path string) {
	t.Helper()
	if err := os.Truncate(path, int64(2*os.Getpagesize())); err != nil {
		t.Fatal(err)
	}
}

// lastPage returns the offset of the last page the database at path uses,
// which bbolt writes the freelist to on commit.
func lastPage(t *testing.T, path string) int64 {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var used int64
	err = db.View(func(tx *bolt.Tx) error {
		used = tx.Size()
		return nil
	})
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	return used - int64(os.Getpagesize())
}

// truncateLastPage cuts the freelist page and leaves the bucket pages whole.
func truncateLastPage(t *testing.T, path string) {
	t.Helper()
	if err := os.Truncate(path, lastPage(t, path)); err != nil {
		t.Fatal(err)
	}
}

// corruptLastPage damages the freelist page and leaves the bucket pages whole.
func corruptLastPage(t *testing.T, path string) {
	t.Helper()
	corruptPageAt(t, path, lastPage(t, path))
}

// corruptPageAt overwrites the page at offset in the database at path.
func corruptPageAt(t *testing.T, path string, offset int64) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := offset; i < offset+int64(os.Getpagesize()); i++ {
		data[i] = 0xa5
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// corruptNestedPage damages only the first page of the nested bucket, so
// the root and every top-level bucket still read cleanly.
func corruptNestedPage(t *testing.T, path string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var page int64
	err = db.View(func(tx *bolt.Tx) error {
		page = int64(tx.Bucket([]byte("parent")).Bucket([]byte("nested")).Root())
		return nil
	})
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	corruptPageAt(t, path, page*int64(os.Getpagesize()))
}

// A damaged snapshot reaches these readers from an archive being imported
// or restored, or from a damaged live database being exported. A firewall
// import also writes into the live database, which may itself be damaged.
// Each must refuse the damaged file with an error: no crash, no change to
// the snapshot or to the merge target, no file left beside it and no lock
// held.
func checkDamagedSnapshotReaders(t *testing.T, noFreelistSync bool, damage func(*testing.T, string)) {
	readers := []struct {
		name string
		// target damages the merge target's database instead of the snapshot.
		target bool
		read   func(snapshot, target string) error
	}{
		{"list buckets", false, func(snapshot, _ string) error {
			_, err := listSnapshotBuckets(snapshot)
			return err
		}},
		{"merge firewall buckets", false, func(snapshot, target string) error {
			_, err := mergeFirewallBucketsFromSnapshot(snapshot, target)
			return err
		}},
		{"merge into a damaged target", true, func(snapshot, target string) error {
			_, err := mergeFirewallBucketsFromSnapshot(snapshot, target)
			return err
		}},
		{"read ledger position", false, func(snapshot, _ string) error {
			_, _, err := readLedgerPosition(snapshot, true)
			return err
		}},
		{"disarm firewall rollback", false, func(snapshot, _ string) error {
			return DisarmFirewallRollbackSnapshot(snapshot)
		}},
		{"disarm login standing", false, func(snapshot, _ string) error {
			return DisarmLoginStandingSnapshot(snapshot)
		}},
		{"disarm browser sessions", false, func(snapshot, _ string) error {
			return DisarmBrowserSessionsSnapshot(snapshot)
		}},
	}
	for _, reader := range readers {
		t.Run(reader.name, func(t *testing.T) {
			dir := t.TempDir()
			snapshot := filepath.Join(dir, "snapshot.db")
			writeSnapshot(t, snapshot, noFreelistSync && !reader.target)
			target := filepath.Join(t.TempDir(), "state")
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			damaged := filepath.Join(target, "csm.db")
			writeSnapshot(t, damaged, noFreelistSync && reader.target)
			if !reader.target {
				damaged = snapshot
			}
			damage(t, damaged)
			before, beforeTarget := treeOf(t, dir), treeOf(t, target)

			err := func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("crashed on a damaged snapshot: %v", r)
					}
				}()
				return reader.read(snapshot, target)
			}()
			if err == nil {
				t.Fatal("read a damaged snapshot without an error")
			}
			if after := treeOf(t, dir); !sameTree(before, after) {
				t.Fatalf("refusal changed the snapshot directory: %v, was %v", after, before)
			}
			if after := treeOf(t, target); !sameTree(beforeTarget, after) {
				t.Fatal("refusal changed the merge target")
			}
			f, openErr := os.OpenFile(damaged, os.O_RDWR, 0)
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer func() { _ = f.Close() }()
			if lockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); lockErr != nil {
				t.Fatalf("refusal kept a lock on the damaged file: %v", lockErr)
			}
		})
	}
}

func TestSnapshotReadersRefuseDamagedPages(t *testing.T) {
	t.Run("every page", func(t *testing.T) { checkDamagedSnapshotReaders(t, false, corruptPages) })
	t.Run("freelist page", func(t *testing.T) { checkDamagedSnapshotReaders(t, false, corruptLastPage) })
}

// bbolt rebuilds a missing freelist on a goroutine of its own, where a
// damaged page cannot be recovered. Run in a child for the same reason as
// the truncated test.
func TestSnapshotReadersRefuseDamagedPagesWithoutFreelist(t *testing.T) {
	inChild(t, "TestSnapshotReadersRefuseDamagedPagesWithoutFreelist", func() {
		t.Run("every page", func(t *testing.T) { checkDamagedSnapshotReaders(t, true, corruptPages) })
		t.Run("nested bucket page", func(t *testing.T) { checkDamagedSnapshotReaders(t, true, corruptNestedPage) })
	})
}

// Reading a page past the end of a truncated file raises a memory fault,
// which kills the process. Run in a child so that shows as a failure
// instead of ending the test binary.
func TestSnapshotReadersRefuseTruncatedPages(t *testing.T) {
	inChild(t, "TestSnapshotReadersRefuseTruncatedPages", func() {
		t.Run("after the meta pages", func(t *testing.T) { checkDamagedSnapshotReaders(t, false, truncatePages) })
		t.Run("last page", func(t *testing.T) { checkDamagedSnapshotReaders(t, false, truncateLastPage) })
	})
}

// inChild runs check in a child test process, so a crash the process cannot
// recover from fails this test instead of ending the test binary.
func inChild(t *testing.T, name string, check func()) {
	t.Helper()
	if os.Getenv("CSM_TEST_SNAPSHOT_CHILD") == name {
		check()
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), "CSM_TEST_SNAPSHOT_CHILD="+name)
	output, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+name)) {
		t.Fatalf("%s in a child: %v\n%s", name, err, output)
	}
}

// Keep metadata checksums valid so these cases exercise page references,
// rather than being refused as an unreadable meta page.
func editSnapshotMeta(t *testing.T, path string, edit func([]byte)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, os.Getpagesize()} {
		meta := data[offset+16 : offset+80]
		edit(meta)
		h := fnv.New64a()
		_, _ = h.Write(meta[:56])
		binary.NativeEndian.PutUint64(meta[56:], h.Sum64())
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotReadersRefuseInvalidReferences(t *testing.T) {
	inChild(t, "TestSnapshotReadersRefuseInvalidReferences", func() {
		for _, noFreelist := range []bool{false, true} {
			t.Run(fmt.Sprintf("no freelist %t", noFreelist), func(t *testing.T) {
				for _, field := range []struct {
					name   string
					offset int
				}{{"root", 16}, {"freelist", 32}} {
					t.Run(field.name, func(t *testing.T) {
						checkDamagedSnapshotReaders(t, noFreelist, func(t *testing.T, path string) {
							info, err := os.Stat(path)
							if err != nil {
								t.Fatal(err)
							}
							editSnapshotMeta(t, path, func(meta []byte) {
								binary.NativeEndian.PutUint64(meta[field.offset:], uint64(info.Size()/int64(os.Getpagesize())+1))
							})
						})
					})
				}
			})
		}
	})
}

func TestSnapshotReadersRefuseInvalidPageLayout(t *testing.T) {
	inChild(t, "TestSnapshotReadersRefuseInvalidPageLayout", func() {
		for _, noFreelist := range []bool{false, true} {
			t.Run(fmt.Sprintf("no freelist %t", noFreelist), func(t *testing.T) {
				for _, damage := range []string{"cycle", "key offset", "freelist count"} {
					t.Run(damage, func(t *testing.T) {
						checkDamagedSnapshotReaders(t, noFreelist, func(t *testing.T, path string) {
							data, err := os.ReadFile(path)
							if err != nil {
								t.Fatal(err)
							}
							meta := data[16:80]
							if binary.NativeEndian.Uint64(data[os.Getpagesize()+64:]) > binary.NativeEndian.Uint64(meta[48:]) {
								meta = data[os.Getpagesize()+16 : os.Getpagesize()+80]
							}
							pageID := binary.NativeEndian.Uint64(meta[16:])
							if damage == "freelist count" {
								if noFreelist { // Install a freelist reference to a damaged root page.
									editSnapshotMeta(t, path, func(m []byte) { binary.NativeEndian.PutUint64(m[32:], pageID) })
									data, err = os.ReadFile(path)
									if err != nil {
										t.Fatal(err)
									}
								} else {
									pageID = binary.NativeEndian.Uint64(meta[32:])
								}
							}
							page := data[pageID*uint64(os.Getpagesize()):]
							switch damage {
							case "cycle":
								binary.NativeEndian.PutUint16(page[8:], 1) // branch
								binary.NativeEndian.PutUint16(page[10:], 1)
								binary.NativeEndian.PutUint32(page[16:], 16)
								binary.NativeEndian.PutUint32(page[20:], 1)
								binary.NativeEndian.PutUint64(page[24:], pageID)
								page[32] = 'a'
							case "key offset":
								binary.NativeEndian.PutUint32(page[20:], ^uint32(0))
							case "freelist count":
								binary.NativeEndian.PutUint16(page[8:], 16)
								binary.NativeEndian.PutUint16(page[10:], 65535)
								binary.NativeEndian.PutUint64(page[16:], 1<<30)
							}
							if err := os.WriteFile(path, data, 0600); err != nil {
								t.Fatal(err)
							}
						})
					})
				}
			})
		}
	})
}

// Each boundary is exercised with a real bbolt file, so a refusal cannot
// pass just because the fixture was invalid before the selected mutation.
func TestSnapshotVerificationLayoutDamage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.db")
	writeSnapshot(t, path, false)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSnapshot(bytes.NewReader(original), int64(len(original))); err != nil {
		t.Fatal(err)
	}
	order := binary.NativeEndian
	pageSize := os.Getpagesize()
	active := 0
	if order.Uint64(original[pageSize+64:]) > order.Uint64(original[64:]) {
		active = pageSize
	}
	root := int(order.Uint64(original[active+32:])) * pageSize
	free := int(order.Uint64(original[active+48:])) * pageSize
	if order.Uint16(original[root+8:]) != 2 {
		t.Fatal("fixture root must be a leaf")
	}
	value := root + 16 + int(order.Uint32(original[root+20:])) + int(order.Uint32(original[root+24:]))
	if order.Uint64(original[value:]) != 0 {
		t.Fatal("fixture first bucket must be inline")
	}
	tests := map[string]func([]byte){
		"page identity":                    func(b []byte) { order.PutUint64(b[root:], 0) },
		"page overflow":                    func(b []byte) { order.PutUint32(b[root+12:], ^uint32(0)) },
		"page type":                        func(b []byte) { order.PutUint16(b[root+8:], 4) },
		"empty branch":                     func(b []byte) { order.PutUint16(b[root+8:], 1); order.PutUint16(b[root+10:], 0) },
		"element count":                    func(b []byte) { order.PutUint16(b[root+10:], 65535) },
		"element overlaps header":          func(b []byte) { order.PutUint32(b[root+20:], 0) },
		"empty key":                        func(b []byte) { order.PutUint32(b[root+24:], 0) },
		"value past page":                  func(b []byte) { order.PutUint32(b[root+28:], ^uint32(0)) },
		"key order":                        func(b []byte) { b[root+16+int(order.Uint32(b[root+20:]))] = 'z' },
		"entry flags":                      func(b []byte) { order.PutUint32(b[root+16:], 2) },
		"root value":                       func(b []byte) { order.PutUint32(b[root+16:], 0) },
		"bucket header":                    func(b []byte) { order.PutUint32(b[root+28:], 8) },
		"inline header":                    func(b []byte) { order.PutUint32(b[root+28:], 20) },
		"inline identity":                  func(b []byte) { order.PutUint64(b[value+16:], 1) },
		"inline trailing data":             func(b []byte) { order.PutUint16(b[value+26:], 0) },
		"inline type":                      func(b []byte) { order.PutUint16(b[value+24:], 1) },
		"inline overflow":                  func(b []byte) { order.PutUint32(b[value+28:], 1) },
		"inline subbucket":                 func(b []byte) { order.PutUint32(b[value+32:], 1) },
		"nested cycle":                     func(b []byte) { order.PutUint64(b[value:], uint64(root/pageSize)) },
		"freelist type":                    func(b []byte) { order.PutUint16(b[free+8:], 2) },
		"freelist count":                   func(b []byte) { order.PutUint16(b[free+10:], 65534) },
		"extended freelist count overflow": func(b []byte) { order.PutUint16(b[free+10:], 65535); order.PutUint64(b[free+16:], ^uint64(0)) },
		"external bucket with trailing data": func(b []byte) {
			last := root + 16*int(order.Uint16(b[root+10:]))
			if size := order.Uint32(b[last+12:]); size != 16 {
				t.Fatalf("last bucket has %d bytes, want an external bucket header", size)
			}
			order.PutUint32(b[last+12:], 17)
		},
		"misplaced recovery meta": func(b []byte) {
			copy(b[1024:1024+80], b[pageSize:pageSize+80])
			b[16] ^= 0xff
			b[pageSize+16] ^= 0xff
		},
		"inconsistent meta page sizes": func(b []byte) {
			order.PutUint32(b[pageSize+24:], uint32(pageSize*2))
			h := fnv.New64a()
			_, _ = h.Write(b[pageSize+16 : pageSize+72])
			order.PutUint64(b[pageSize+72:], h.Sum64())
		},
		"freed live page":   func(b []byte) { order.PutUint16(b[free+10:], 1); order.PutUint64(b[free+16:], uint64(root/pageSize)) },
		"double freed page": func(b []byte) { order.PutUint16(b[free+10:], 2); copy(b[free+24:free+32], b[free+16:free+24]) },
		"leaked pages":      func(b []byte) { order.PutUint16(b[free+10:], 0) },
	}
	for name, damage := range tests {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(original)
			damage(data)
			if err := checkSnapshot(bytes.NewReader(data), int64(len(data))); err == nil {
				t.Fatal("accepted damaged snapshot")
			}
		})
	}
	for _, test := range []struct {
		name   string
		damage func([]byte)
	}{
		{"zero page size", func(m []byte) { order.PutUint32(m[8:], 0) }},
		{"oversized page size", func(m []byte) { order.PutUint32(m[8:], ^uint32(0)) }},
		{"exhausted transaction ID", func(m []byte) { order.PutUint64(m[48:], ^uint64(0)) }},
		{"zero high water mark", func(m []byte) { order.PutUint64(m[40:], 0) }},
		{"oversized high water mark", func(m []byte) { order.PutUint64(m[40:], ^uint64(0)) }},
		{"meta as root", func(m []byte) { order.PutUint64(m[16:], 1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "snapshot.db")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			editSnapshotMeta(t, path, test.damage)
			if err := verifySnapshot(path); err == nil {
				t.Fatal("accepted damaged metadata")
			}
		})
	}
}

func TestSnapshotVerificationValidLayouts(t *testing.T) {
	for _, pageSize := range []int{1024, 4096, 16384, 65536} {
		for _, noFreelist := range []bool{false, true} {
			t.Run(fmt.Sprintf("page size %d no freelist %t", pageSize, noFreelist), func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "live.db")
				db, openErr := bolt.Open(path, 0600, &bolt.Options{PageSize: pageSize, NoFreelistSync: noFreelist, InitialMmapSize: 64 * 1024 * 1024})
				if openErr != nil {
					t.Fatal(openErr)
				}
				defer func() { _ = db.Close() }()
				// Overflows, inline buckets, branch pages and pending freed pages all
				// occur in ordinary exports. Keep an older reader open during writes.
				old, beginErr := db.Begin(false)
				if beginErr != nil {
					t.Fatal(beginErr)
				}
				defer func() { _ = old.Rollback() }()
				for revision := 0; revision < 3; revision++ {
					if err := db.Update(func(tx *bolt.Tx) error {
						b, createErr := tx.CreateBucketIfNotExists([]byte("data"))
						if createErr != nil {
							return createErr
						}
						for i := 0; i < 200; i++ {
							if putErr := b.Put(fmt.Appendf(nil, "%08d", i), bytes.Repeat([]byte{byte(revision)}, pageSize/2)); putErr != nil {
								return putErr
							}
						}
						_, createErr = b.CreateBucketIfNotExists([]byte("empty"))
						return createErr
					}); err != nil {
						t.Fatal(err)
					}
				}
				snapshot := filepath.Join(dir, "snapshot.db")
				if err := db.View(func(tx *bolt.Tx) error { return tx.CopyFile(snapshot, 0600) }); err != nil {
					t.Fatal(err)
				}
				if err := verifySnapshot(snapshot); err != nil {
					t.Fatal(err)
				}
				// A damaged meta page is recoverable from the other valid copy.
				data, err := os.ReadFile(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				ps := int(binary.NativeEndian.Uint32(data[24:]))
				for _, metaOffset := range []int{0, ps} {
					damaged := bytes.Clone(data)
					damaged[metaOffset+16] ^= 0xff
					if err := checkSnapshot(bytes.NewReader(damaged), int64(len(damaged))); err != nil {
						t.Fatalf("recovering meta %d: %v", metaOffset, err)
					}
				}
				if err := DisarmBrowserSessionsSnapshot(snapshot); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// Values can span many pages. Validation must check their bounds without
// allocating or reading the entire value, even when overflow is damaged.
func TestSnapshotVerificationStreamsValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.db")
	db, err := bolt.Open(path, 0600, &bolt.Options{PageSize: 65536})
	if err != nil {
		t.Fatal(err)
	}
	var root uint64
	err = db.Update(func(tx *bolt.Tx) error {
		b, createErr := tx.CreateBucket([]byte("data"))
		if createErr != nil {
			return createErr
		}
		return b.Put([]byte("key"), bytes.Repeat([]byte{'v'}, 1024*1024))
	})
	if err == nil {
		err = db.View(func(tx *bolt.Tx) error { root = uint64(tx.Bucket([]byte("data")).Root()); return nil })
	}
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader := &countSnapshotReads{ReaderAt: bytes.NewReader(data)}
	if err := checkSnapshot(reader, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if reader.bytes >= 1024*1024 {
		t.Fatalf("read %d bytes to validate a large value", reader.bytes)
	}
	// Reassign part of the value to an oversized key, without changing the
	// element's total extent. Bounds alone cannot catch this invalid key.
	at := root*65536 + snapshotPageHeader
	binary.NativeEndian.PutUint32(data[at+8:], bolt.MaxKeySize+1)
	binary.NativeEndian.PutUint32(data[at+12:], 1024*1024+3-bolt.MaxKeySize-1)
	if err := checkSnapshot(bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("accepted an oversized key")
	}
}

type countSnapshotReads struct {
	io.ReaderAt
	bytes int
}

func (r *countSnapshotReads) ReadAt(p []byte, offset int64) (int, error) {
	n, err := r.ReaderAt.ReadAt(p, offset)
	r.bytes += n
	return n, err
}

func TestSnapshotVerificationRefusesOversizedValue(t *testing.T) {
	// A sparse overflow page can advertise a value beyond bbolt's supported
	// size without storing gigabytes of fixture data.
	data := make([]byte, 33)
	binary.NativeEndian.PutUint16(data[8:], snapshotLeaf)
	binary.NativeEndian.PutUint16(data[10:], 1)
	binary.NativeEndian.PutUint32(data[20:], 16)
	binary.NativeEndian.PutUint32(data[24:], 1)
	binary.NativeEndian.PutUint32(data[28:], bolt.MaxValueSize+1)
	data[32] = 'k'
	page := io.NewSectionReader(bytes.NewReader(data), 0, 33+bolt.MaxValueSize+1)
	v := snapshotVerifier{}
	if _, err := v.treePage(snapshotTree{inline: page}); err == nil {
		t.Fatal("accepted a value bbolt cannot store")
	}
}

func TestSnapshotVerificationRefusesSpecialFile(t *testing.T) {
	inChild(t, "TestSnapshotVerificationRefusesSpecialFile", func() {
		path := filepath.Join(t.TempDir(), "snapshot.db")
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifySnapshot(path); err == nil {
			t.Fatal("accepted a pipe as a snapshot")
		}
	})
}
