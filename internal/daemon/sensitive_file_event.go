package daemon

import (
	"encoding/binary"
	"errors"
)

// SensitiveFileEvent matches struct sensitive_event in sensitive_file.bpf.c
// byte for byte. Userspace looks up (Dev, Ino) in the in-memory mirror of
// the BPF watchset map to recover the path string at finding time.
type SensitiveFileEvent struct {
	UID  uint32
	PID  uint32
	Mask uint32
	Dev  uint64
	Ino  uint64
	Comm string
}

const sensitiveFileEventSize = 4 + 4 + 4 + 4 + 8 + 8 + 16

func decodeSensitiveFileEvent(b []byte) (SensitiveFileEvent, error) {
	if len(b) < sensitiveFileEventSize {
		return SensitiveFileEvent{}, errors.New("sensitive file event short buffer")
	}
	ev := SensitiveFileEvent{
		UID:  binary.LittleEndian.Uint32(b[0:4]),
		PID:  binary.LittleEndian.Uint32(b[4:8]),
		Mask: binary.LittleEndian.Uint32(b[8:12]),
		Dev:  binary.LittleEndian.Uint64(b[16:24]),
		Ino:  binary.LittleEndian.Uint64(b[24:32]),
	}
	ev.Comm = nullTerm(b[32 : 32+16])
	return ev, nil
}
