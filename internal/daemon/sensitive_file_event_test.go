package daemon

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecodeSensitiveFileEvent(t *testing.T) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, uint32(1000)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint32(5555)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint32(0x2)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint32(0)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint64(64768)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint64(123456)); err != nil {
		t.Fatal(err)
	}
	buf.Write(append([]byte("vim"), bytes.Repeat([]byte{0}, 13)...))

	got, err := decodeSensitiveFileEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.UID != 1000 || got.PID != 5555 || got.Mask != 0x2 {
		t.Fatalf("scalars wrong: %+v", got)
	}
	if got.Dev != 64768 || got.Ino != 123456 {
		t.Fatalf("dev/ino wrong: %+v", got)
	}
	if got.Comm != "vim" {
		t.Fatalf("Comm = %q, want vim", got.Comm)
	}
}

func TestDecodeSensitiveFileEventShortBuffer(t *testing.T) {
	if _, err := decodeSensitiveFileEvent(make([]byte, 10)); err == nil {
		t.Fatal("expected error on short buffer")
	}
}
