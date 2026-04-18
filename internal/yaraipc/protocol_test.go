package yaraipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	args := ScanFileArgs{Path: "/tmp/x", MaxBytes: 4096}
	orig, err := EncodePayload(OpScanFile, args)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}

	var buf bytes.Buffer
	if werr := WriteFrame(&buf, orig); werr != nil {
		t.Fatalf("WriteFrame: %v", werr)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Op != OpScanFile {
		t.Errorf("op: got %q want %q", got.Op, OpScanFile)
	}

	var decoded ScanFileArgs
	if err := DecodePayload(got, &decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if decoded != args {
		t.Errorf("round-trip: got %+v want %+v", decoded, args)
	}
}

func TestFrameErrorField(t *testing.T) {
	orig := Frame{Error: "rule_compile_failed: bad syntax"}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, orig); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Error != orig.Error {
		t.Errorf("error: got %q want %q", got.Error, orig.Error)
	}
	if got.Op != "" {
		t.Errorf("op should be empty on error frame, got %q", got.Op)
	}
}

func TestReadFrameRejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(MaxFrameBytes)+1)
	buf.Write(hdr[:])

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatal("expected error for oversize length prefix")
	}
	if !strings.Contains(err.Error(), "exceeds cap") {
		t.Errorf("error should mention cap: %v", err)
	}
}

func TestReadFrameRejectsZeroLength(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0})

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatal("expected error for zero-length frame")
	}
}

func TestReadFrameShortBody(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 10})
	buf.WriteString("short")

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatal("expected error for truncated body")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadFrameRejectsBadJSON(t *testing.T) {
	var buf bytes.Buffer
	body := []byte("{not json")
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	buf.Write(hdr[:])
	buf.Write(body)

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatal("expected error for malformed JSON body")
	}
	if !strings.Contains(err.Error(), "unmarshal frame") {
		t.Errorf("error should mention unmarshal: %v", err)
	}
}

func TestWriteFrameRejectsOversizeBody(t *testing.T) {
	payload := make([]byte, MaxFrameBytes+1)
	for i := range payload {
		payload[i] = 'a'
	}
	raw, err := json.Marshal(string(payload))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	f := Frame{Op: OpScanBytes, Payload: raw}

	var buf bytes.Buffer
	if werr := WriteFrame(&buf, f); werr == nil {
		t.Fatal("expected error for oversize payload")
	}
}

func TestEncodePayloadNilSkipsField(t *testing.T) {
	f, err := EncodePayload(OpPing, nil)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	if len(f.Payload) != 0 {
		t.Errorf("ping frame should have empty payload, got %q", f.Payload)
	}

	var buf bytes.Buffer
	if werr := WriteFrame(&buf, f); werr != nil {
		t.Fatalf("WriteFrame: %v", werr)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Op != OpPing {
		t.Errorf("op: got %q want %q", got.Op, OpPing)
	}
	if len(got.Payload) != 0 {
		t.Errorf("payload: got %q want empty", got.Payload)
	}
}

func TestScanResultPayload(t *testing.T) {
	res := ScanResult{Matches: []Match{{RuleName: "webshell_generic"}, {RuleName: "backdoor_eval"}}}
	f, err := EncodePayload("", res)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	var decoded ScanResult
	if err := DecodePayload(f, &decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if len(decoded.Matches) != 2 {
		t.Fatalf("matches: got %d want 2", len(decoded.Matches))
	}
	if decoded.Matches[0].RuleName != "webshell_generic" {
		t.Errorf("first match: got %q want webshell_generic", decoded.Matches[0].RuleName)
	}
}
