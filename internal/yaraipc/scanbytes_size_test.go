package yaraipc

import (
	"bytes"
	"testing"
)

// A payload exactly at MaxScanBytes must still marshal within MaxFrameBytes,
// or the ceiling is set too high and a legitimate max-size scan would fail
// deep inside WriteFrame instead of being accepted.
func TestMaxScanBytesFitsInOneFrame(t *testing.T) {
	f, err := EncodePayload(OpScanBytes, ScanBytesArgs{Data: make([]byte, MaxScanBytes)})
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, f); err != nil {
		t.Fatalf("a MaxScanBytes payload must fit in one frame: %v", err)
	}
}
