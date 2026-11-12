package daemon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

// Wire layout of struct placement_event in _placement.bpf.c.
const (
	placementEventHeaderSize = 24
	placementEventPathSize   = 4096
)

// PlacementRawEvent is one decoded ring record. Components are the new
// entry's names from the leaf up to the filesystem root, so userspace can
// join them under that filesystem's mount. Dev is the kernel dev_t. At is
// when the ring reader decoded it, however long a worker takes to reach it.
type PlacementRawEvent struct {
	Kind       uint8
	IsDir      bool
	Truncated  bool
	PID        uint32
	Dev, Ino   uint64
	Components []string
	At         time.Time
}

func decodePlacementEvent(b []byte) (PlacementRawEvent, error) {
	if len(b) < placementEventHeaderSize {
		return PlacementRawEvent{}, errors.New("placement event short buffer")
	}
	ev := PlacementRawEvent{
		Kind:      b[0],
		IsDir:     b[1] != 0,
		Truncated: b[3] != 0,
		PID:       binary.LittleEndian.Uint32(b[4:8]),
		Dev:       binary.LittleEndian.Uint64(b[8:16]),
		Ino:       binary.LittleEndian.Uint64(b[16:24]),
		At:        time.Now(),
	}
	depth := int(b[2])
	names := b[placementEventHeaderSize:]
	ev.Components = make([]string, 0, depth)
	for range depth {
		// The reservation is not zeroed, so only counted names are path.
		end := bytes.IndexByte(names, 0)
		if end < 0 {
			return PlacementRawEvent{}, errors.New("placement event path shorter than its depth")
		}
		ev.Components = append(ev.Components, string(names[:end]))
		names = names[end+1:]
	}
	return ev, nil
}
