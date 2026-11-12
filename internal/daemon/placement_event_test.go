package daemon

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
	"time"
)

// placementRecord builds a ring record the way the BPF program fills it: a
// full-size reservation whose path area holds depth NUL-terminated names,
// leaf first, followed by whatever the ring held before.
func placementRecord(kind, isDir, truncated uint8, pid uint32, dev, ino uint64, leafFirst ...string) []byte {
	b := bytes.Repeat([]byte{0xff}, placementEventHeaderSize+placementEventPathSize)
	b[0], b[1], b[2], b[3] = kind, isDir, uint8(len(leafFirst)), truncated
	binary.LittleEndian.PutUint32(b[4:8], pid)
	binary.LittleEndian.PutUint64(b[8:16], dev)
	binary.LittleEndian.PutUint64(b[16:24], ino)
	off := placementEventHeaderSize
	for _, name := range leafFirst {
		off += copy(b[off:], name)
		b[off] = 0
		off++
	}
	return b
}

func TestDecodePlacementEventRoundTrip(t *testing.T) {
	rec := placementRecord(2, 0, 0, 4242, 259<<20|3, 987654, "shell.php", "public_html", "user")
	before := time.Now()
	got, err := decodePlacementEvent(rec)
	if err != nil {
		t.Fatal(err)
	}
	// The read time, not when a worker gets to it: restore detection
	// compares it with the writer's start time.
	if got.At.Before(before) || got.At.After(time.Now()) {
		t.Fatalf("decoded at %v, want the read time", got.At)
	}
	want := PlacementRawEvent{Kind: 2, PID: 4242, Dev: 259<<20 | 3, Ino: 987654, Components: []string{"shell.php", "public_html", "user"}}
	if got.Kind != want.Kind || got.IsDir || got.Truncated || got.PID != want.PID || got.Dev != want.Dev || got.Ino != want.Ino || !slices.Equal(got.Components, want.Components) {
		t.Fatalf("decoded %+v, want %+v", got, want)
	}
}

func TestDecodePlacementEventKeepsTruncatedFlag(t *testing.T) {
	rec := placementRecord(1, 1, 1, 7, 30, 11, "plugin", "plugins")
	got, err := decodePlacementEvent(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || !got.IsDir || got.Kind != 1 || !slices.Equal(got.Components, []string{"plugin", "plugins"}) {
		t.Fatalf("truncated directory event decoded as %+v", got)
	}
}

func TestDecodePlacementEventRejectsMalformedRecords(t *testing.T) {
	if _, err := decodePlacementEvent(make([]byte, placementEventHeaderSize-1)); err == nil {
		t.Error("short header decoded")
	}
	// A depth larger than the names present must not read stale ring bytes
	// as path components.
	rec := placementRecord(1, 0, 0, 1, 30, 11, "a.php")
	rec[2] = 2
	if ev, err := decodePlacementEvent(rec); err == nil {
		t.Errorf("depth past the last name decoded as %+v", ev)
	}
	// The ring may hand back exactly the header and names when the record is
	// shorter than a full reservation.
	short := placementRecord(1, 0, 0, 1, 30, 11, "a.php")[:placementEventHeaderSize+len("a.php")+1]
	if ev, err := decodePlacementEvent(short); err != nil || !slices.Equal(ev.Components, []string{"a.php"}) {
		t.Errorf("exact-length record: %+v, %v", ev, err)
	}
}
