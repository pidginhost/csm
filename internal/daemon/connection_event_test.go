package daemon

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func writeLE32(t *testing.T, buf *bytes.Buffer, v uint32) {
	t.Helper()
	if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
		t.Fatalf("binary.Write LE: %v", err)
	}
}

func writeBE32(t *testing.T, buf *bytes.Buffer, v uint32) {
	t.Helper()
	if err := binary.Write(buf, binary.BigEndian, v); err != nil {
		t.Fatalf("binary.Write BE: %v", err)
	}
}

func TestDecodeConnectionEventV4(t *testing.T) {
	var buf bytes.Buffer
	writeLE32(t, &buf, 1000)                                          // uid
	writeLE32(t, &buf, 12345)                                         // pid
	writeLE32(t, &buf, 2)                                             // family AF_INET
	writeLE32(t, &buf, 4444)                                          // dst_port (host order)
	writeBE32(t, &buf, 0x08080808)                                    // dst_ip4 network order = 8.8.8.8
	buf.Write(make([]byte, 16))                                       // dst_ip6 (zeros)
	buf.Write(append([]byte("curl"), bytes.Repeat([]byte{0}, 12)...)) // comm
	writeLE32(t, &buf, 0)                                             // decision (DECISION_ALLOW)

	got, err := decodeConnectionEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.UID != 1000 || got.PID != 12345 || got.DstPort != 4444 {
		t.Fatalf("scalars wrong: %+v", got)
	}
	if got.Family != 2 {
		t.Fatalf("family = %d, want AF_INET (2)", got.Family)
	}
	if !got.DstIP.Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("DstIP = %v, want 8.8.8.8", got.DstIP)
	}
	if got.Comm != "curl" {
		t.Fatalf("Comm = %q, want curl", got.Comm)
	}
}

func TestDecodeConnectionEventV6(t *testing.T) {
	var buf bytes.Buffer
	writeLE32(t, &buf, 1000)  // uid
	writeLE32(t, &buf, 12345) // pid
	writeLE32(t, &buf, 10)    // family AF_INET6
	writeLE32(t, &buf, 4444)  // dst_port
	writeLE32(t, &buf, 0)     // dst_ip4 zero
	v6 := net.ParseIP("2001:db8::1").To16()
	buf.Write(v6)
	buf.Write(append([]byte("curl"), bytes.Repeat([]byte{0}, 12)...))
	writeLE32(t, &buf, 0) // decision (DECISION_ALLOW)

	got, err := decodeConnectionEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.DstIP.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("DstIP = %v, want 2001:db8::1", got.DstIP)
	}
}

func TestDecodeConnectionEventShortBuffer(t *testing.T) {
	if _, err := decodeConnectionEvent(make([]byte, 10)); err == nil {
		t.Fatal("expected error on short buffer")
	}
}

func TestDecodeConnectionEventIncludesDecision(t *testing.T) {
	buf := make([]byte, 56)
	binary.LittleEndian.PutUint32(buf[0:4], 1001)
	binary.LittleEndian.PutUint32(buf[4:8], 4242)
	binary.LittleEndian.PutUint32(buf[8:12], 2) // AF_INET
	binary.LittleEndian.PutUint32(buf[12:16], 587)
	binary.BigEndian.PutUint32(buf[16:20], 0xCB007302)
	copy(buf[36:52], "ncat\x00")
	binary.LittleEndian.PutUint32(buf[52:56], 2) // DECISION_DENY

	ev, err := decodeConnectionEvent(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Decision != 2 {
		t.Errorf("Decision: want 2 (DECISION_DENY), got %d", ev.Decision)
	}
}

func TestDecodeConnectionEventShortBufferStillFails(t *testing.T) {
	short := make([]byte, 55) // one short of the new 56
	if _, err := decodeConnectionEvent(short); err == nil {
		t.Errorf("expected short-buffer error")
	}
}
