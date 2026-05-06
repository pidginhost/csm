package daemon

import (
	"encoding/binary"
	"errors"
	"net"
)

// ConnectionEvent is the userspace shape of a struct conn_event emitted by
// the cgroup/connect BPF program. Field layout matches connection.bpf.c
// byte for byte: scalars are little-endian (host order on amd64/arm64),
// dst_ip4 is network-order, dst_ip6 is the raw 16-byte address.
type ConnectionEvent struct {
	UID     uint32
	PID     uint32
	Family  uint32 // AF_INET=2, AF_INET6=10
	DstPort uint16 // host order; BPF program calls bpf_ntohs
	DstIP   net.IP // resolved from dst_ip4 (v4) or dst_ip6 (v6) per Family
	Comm    string // null-terminated, up to 16 bytes
}

const connectionEventSize = 4 + 4 + 4 + 4 + 4 + 16 + 16

func decodeConnectionEvent(b []byte) (ConnectionEvent, error) {
	if len(b) < connectionEventSize {
		return ConnectionEvent{}, errors.New("connection event short buffer")
	}
	// The BPF program stores dst_port as __u32 for alignment but calls
	// bpf_ntohs() before writing, which guarantees the value fits in 16 bits.
	// The narrowing is safe by construction.
	dstPort := binary.LittleEndian.Uint32(b[12:16]) & 0xffff
	ev := ConnectionEvent{
		UID:     binary.LittleEndian.Uint32(b[0:4]),
		PID:     binary.LittleEndian.Uint32(b[4:8]),
		Family:  binary.LittleEndian.Uint32(b[8:12]),
		DstPort: uint16(dstPort), // #nosec G115 -- masked to low 16 bits above
	}
	switch ev.Family {
	case 2: // AF_INET
		ipv4 := make(net.IP, 4)
		binary.BigEndian.PutUint32(ipv4, binary.BigEndian.Uint32(b[16:20]))
		ev.DstIP = ipv4
	case 10: // AF_INET6
		v6 := make(net.IP, 16)
		copy(v6, b[20:36])
		ev.DstIP = v6
	default:
		return ConnectionEvent{}, errors.New("unknown family")
	}
	ev.Comm = nullTerm(b[36 : 36+16])
	return ev, nil
}

func indexNull(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// nullTerm returns the prefix of b up to (but not including) the first NUL,
// or the whole slice if there is none. Helper for fixed-size character
// fields the BPF programs emit (comm[16], filename[256], exe[256]).
func nullTerm(b []byte) string {
	if i := indexNull(b); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
