package daemon

import (
	"encoding/binary"
	"errors"
)

// ExecEvent matches struct exec_event in exec.bpf.c byte for byte:
// scalars are little-endian (host order on amd64/arm64), comm/parent_comm
// are 16-byte null-padded, filename is 256-byte null-padded.
type ExecEvent struct {
	UID        uint32
	PID        uint32
	PPID       uint32
	Comm       string
	ParentComm string
	Filename   string
}

const execEventSize = 4 + 4 + 4 + 16 + 16 + 256

func decodeExecEvent(b []byte) (ExecEvent, error) {
	if len(b) < execEventSize {
		return ExecEvent{}, errors.New("exec event short buffer")
	}
	ev := ExecEvent{
		UID:  binary.LittleEndian.Uint32(b[0:4]),
		PID:  binary.LittleEndian.Uint32(b[4:8]),
		PPID: binary.LittleEndian.Uint32(b[8:12]),
	}
	ev.Comm = nullTerm(b[12:28])
	ev.ParentComm = nullTerm(b[28:44])
	ev.Filename = nullTerm(b[44 : 44+256])
	return ev, nil
}
