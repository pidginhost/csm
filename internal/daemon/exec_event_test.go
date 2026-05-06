package daemon

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecodeExecEvent(t *testing.T) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, uint32(1000)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint32(5555)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint32(4444)); err != nil {
		t.Fatal(err)
	}
	buf.Write(append([]byte("curl"), bytes.Repeat([]byte{0}, 12)...))
	buf.Write(append([]byte("pcurl"), bytes.Repeat([]byte{0}, 11)...))
	path := append([]byte("/usr/bin/curl"), bytes.Repeat([]byte{0}, 256-13)...)
	buf.Write(path)

	got, err := decodeExecEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.UID != 1000 || got.PID != 5555 || got.PPID != 4444 {
		t.Fatalf("scalars wrong: %+v", got)
	}
	if got.Comm != "curl" || got.ParentComm != "pcurl" {
		t.Fatalf("comms wrong: %+v", got)
	}
	if got.Filename != "/usr/bin/curl" {
		t.Fatalf("filename = %q, want /usr/bin/curl", got.Filename)
	}
}

func TestDecodeExecEventShortBuffer(t *testing.T) {
	if _, err := decodeExecEvent(make([]byte, 10)); err == nil {
		t.Fatal("expected error on short buffer")
	}
}
