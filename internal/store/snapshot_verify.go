package store

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"os"

	bolt "go.etcd.io/bbolt"
)

// bbolt's version 2 disk format uses native byte order. Decode it with
// bounded reads: its mmap cursors and Tx.Check can fault, recurse forever,
// or panic on library-owned goroutines when page references are damaged.
const (
	snapshotPageHeader = 16
	snapshotMetaSize   = 64
	snapshotBranch     = 1
	snapshotLeaf       = 2
	snapshotFreelist   = 16
)

// verifySnapshot only accepts private, stopped snapshots. Callers keep
// them private until the subsequent bbolt read or mutation completes.
func verifySnapshot(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("bbolt snapshot is not a regular file")
	}
	// #nosec G304 -- path is a private snapshot staged by backup or import.
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := checkSnapshot(f, info.Size()); err != nil {
		return fmt.Errorf("bbolt snapshot is damaged: %w", err)
	}
	return nil
}

var errLeakedPages = errors.New("snapshot has unreachable unfreed pages")

// verifyDatabase checks a stopped live database as verifySnapshot checks a
// snapshot, but accepts leaked pages: they waste space, and bbolt reads and
// writes around them. A missing file is a new database.
func verifyDatabase(path string) error {
	err := verifySnapshot(path)
	if os.IsNotExist(err) || errors.Is(err, errLeakedPages) {
		return nil
	}
	return err
}

type snapshotMeta struct {
	pageSize                    int64
	root, freelist, pages, txid uint64
}

func readSnapshotMeta(r io.ReaderAt, offset int64) (snapshotMeta, bool) {
	var data [snapshotPageHeader + snapshotMetaSize]byte
	if _, err := r.ReadAt(data[:], offset); err != nil {
		return snapshotMeta{}, false
	}
	m := data[snapshotPageHeader:]
	order := binary.NativeEndian
	h := fnv.New64a()
	_, _ = h.Write(m[:56])
	if order.Uint32(m) != 0xED0CDAED || order.Uint32(m[4:]) != 2 || order.Uint64(m[56:]) != h.Sum64() {
		return snapshotMeta{}, false
	}
	return snapshotMeta{
		pageSize: int64(order.Uint32(m[8:])), root: order.Uint64(m[16:]),
		freelist: order.Uint64(m[32:]), pages: order.Uint64(m[40:]), txid: order.Uint64(m[48:]),
	}, true
}

func checkSnapshot(r io.ReaderAt, size int64) error {
	m, valid := readSnapshotMeta(r, 0)
	if !valid {
		// Match bbolt's recovery of the page size from the second meta.
		for offset := int64(1024); offset <= 1024<<14 && offset < size; offset *= 2 {
			if m, valid = readSnapshotMeta(r, offset); valid {
				break
			}
		}
	}
	if !valid || m.pageSize < snapshotPageHeader+snapshotMetaSize || m.pageSize > size/2 {
		return fmt.Errorf("invalid snapshot metadata")
	}
	other, otherValid := readSnapshotMeta(r, m.pageSize)
	if otherValid && other.pageSize != m.pageSize {
		return fmt.Errorf("inconsistent snapshot page sizes")
	}
	if otherValid && other.txid > m.txid {
		m = other
	}
	if m.pages < 2 || m.pages > math.MaxInt64 || int64(m.pages) > size/m.pageSize {
		return fmt.Errorf("snapshot pages exceed file bounds")
	}
	v := snapshotVerifier{reader: r, meta: m, used: make(map[uint64]bool)}
	if m.freelist != ^uint64(0) {
		if err := v.freePages(); err != nil {
			return err
		}
	}
	work := []snapshotTree{{id: m.root, root: true}}
	for len(work) > 0 {
		last := len(work) - 1
		tree := work[last]
		work[last] = snapshotTree{}
		work = work[:last]
		children, err := v.treePage(tree)
		if err != nil {
			return err
		}
		work = append(work, children...)
	}
	if m.freelist != ^uint64(0) && uint64(len(v.used)) != m.pages-2 {
		return errLeakedPages
	}
	return nil
}

type snapshotVerifier struct {
	reader io.ReaderAt
	meta   snapshotMeta
	used   map[uint64]bool
}

// claim rejects both cycles and a live page overlapping another allocation
// or the freelist. Unused pages need not contain a valid page header.
func (v *snapshotVerifier) claim(id uint64) error {
	if id < 2 || id >= v.meta.pages || v.used[id] {
		return fmt.Errorf("invalid or multiply referenced snapshot page %d", id)
	}
	v.used[id] = true
	return nil
}

func (v *snapshotVerifier) page(id uint64) (*io.SectionReader, error) {
	if err := v.claim(id); err != nil {
		return nil, err
	}
	var header [snapshotPageHeader]byte
	// #nosec G115 -- claim bounds id below pages, which is at most file size / page size.
	offset := int64(id) * v.meta.pageSize
	if _, err := v.reader.ReadAt(header[:], offset); err != nil {
		return nil, err
	}
	order := binary.NativeEndian
	span := uint64(order.Uint32(header[12:])) + 1
	if order.Uint64(header[:]) != id || span > v.meta.pages-id {
		return nil, fmt.Errorf("invalid snapshot page %d header", id)
	}
	for i := uint64(1); i < span; i++ {
		if err := v.claim(id + i); err != nil {
			return nil, err
		}
	}
	// span is a uint32 overflow count plus one, so it fits in int64.
	return io.NewSectionReader(v.reader, offset, (int64(order.Uint32(header[12:]))+1)*v.meta.pageSize), nil
}

func (v *snapshotVerifier) freePages() error {
	data, err := v.page(v.meta.freelist)
	if err != nil {
		return err
	}
	order := binary.NativeEndian
	var header [snapshotPageHeader]byte
	if _, err := io.ReadFull(data, header[:]); err != nil {
		return err
	}
	if order.Uint16(header[8:]) != snapshotFreelist {
		return fmt.Errorf("invalid snapshot freelist type")
	}
	count := uint64(order.Uint16(header[10:]))
	remaining := data.Size() - snapshotPageHeader
	ids := bufio.NewReader(data)
	var id [8]byte
	if count == 0xffff {
		if _, err := io.ReadFull(ids, id[:]); err != nil {
			return err
		}
		count = order.Uint64(id[:])
		remaining -= 8
	}
	if count > math.MaxInt64 || int64(count) > remaining/8 {
		return fmt.Errorf("snapshot freelist exceeds page bounds")
	}
	for i := uint64(0); i < count; i++ {
		if _, err := io.ReadFull(ids, id[:]); err != nil {
			return err
		}
		if err := v.claim(order.Uint64(id[:])); err != nil {
			return err
		}
	}
	return nil
}

type snapshotTree struct {
	id       uint64
	inline   *io.SectionReader
	min, max []byte
	root     bool // the top-level tree may contain only bucket entries
}

func (v *snapshotVerifier) treePage(tree snapshotTree) ([]snapshotTree, error) {
	data := tree.inline
	if data == nil {
		var err error
		data, err = v.page(tree.id)
		if err != nil {
			return nil, err
		}
	}
	if data.Size() < snapshotPageHeader {
		return nil, fmt.Errorf("short inline snapshot page")
	}
	order := binary.NativeEndian
	var header [snapshotPageHeader]byte
	if _, err := data.ReadAt(header[:], 0); err != nil {
		return nil, err
	}
	flags, count := order.Uint16(header[8:]), int64(order.Uint16(header[10:]))
	if flags != snapshotLeaf && flags != snapshotBranch || flags == snapshotBranch && count == 0 {
		return nil, fmt.Errorf("invalid snapshot tree page type or count")
	}
	if tree.inline != nil && (flags != snapshotLeaf || order.Uint32(header[12:]) != 0) {
		return nil, fmt.Errorf("invalid inline snapshot page")
	}
	// Both branch and leaf elements have a 16-byte header.
	end := int64(snapshotPageHeader) + count*16
	if end > data.Size() {
		return nil, fmt.Errorf("snapshot elements exceed page bounds")
	}
	var children []snapshotTree
	var previous []byte
	elements := bufio.NewReader(io.NewSectionReader(data, snapshotPageHeader, count*16))
	for i := int64(0); i < count; i++ {
		at := int64(snapshotPageHeader) + i*16
		var element [16]byte
		if _, err := io.ReadFull(elements, element[:]); err != nil {
			return nil, err
		}
		var pos, keySize, valueSize int64
		if flags == snapshotLeaf {
			pos, keySize, valueSize = int64(order.Uint32(element[4:])), int64(order.Uint32(element[8:])), int64(order.Uint32(element[12:]))
		} else {
			pos, keySize = int64(order.Uint32(element[:])), int64(order.Uint32(element[4:]))
		}
		start, stop := at+pos, at+pos+keySize+valueSize
		if start < end || stop > data.Size() || keySize == 0 || keySize > bolt.MaxKeySize || valueSize > bolt.MaxValueSize {
			return nil, fmt.Errorf("snapshot key or value exceeds page bounds")
		}
		end = stop
		key := make([]byte, keySize)
		if _, err := data.ReadAt(key, start); err != nil {
			return nil, err
		}
		if i > 0 && bytes.Compare(previous, key) >= 0 || tree.min != nil && bytes.Compare(key, tree.min) < 0 || tree.max != nil && bytes.Compare(key, tree.max) >= 0 {
			return nil, fmt.Errorf("snapshot keys are out of order")
		}
		previous = key
		if flags == snapshotBranch {
			if len(children) > 0 {
				children[len(children)-1].max = key
			}
			children = append(children, snapshotTree{id: order.Uint64(element[8:]), min: key, max: tree.max, root: tree.root})
			continue
		}
		entryFlags := order.Uint32(element[:])
		if entryFlags != 0 && entryFlags != 1 || tree.root && entryFlags != 1 {
			return nil, fmt.Errorf("invalid snapshot bucket entry")
		}
		if entryFlags == 0 {
			continue
		}
		// bbolt never inlines a bucket containing subbuckets.
		if valueSize < 16 || tree.inline != nil {
			return nil, fmt.Errorf("invalid snapshot bucket header")
		}
		var bucket [16]byte
		if _, err := data.ReadAt(bucket[:], start+keySize); err != nil {
			return nil, err
		}
		child := snapshotTree{id: order.Uint64(bucket[:])}
		if child.id == 0 {
			child.inline = io.NewSectionReader(data, start+keySize+16, valueSize-16)
		}
		children = append(children, child)
	}
	return children, nil
}
