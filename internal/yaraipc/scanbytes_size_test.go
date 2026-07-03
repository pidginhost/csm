package yaraipc

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// An OpScanBytes payload larger than a single frame can hold must be rejected
// with a typed error before any I/O -- never silently dropped. The daemon's
// supervisor maps a swallowed transport error to "no matches", so a big
// infected attachment would otherwise pass as clean.
func TestClientScanBytesRejectsOversizePayload(t *testing.T) {
	c := NewClientWithDialer(func() (net.Conn, error) {
		t.Fatal("dialer must not be reached for an oversize payload")
		return nil, nil
	}, time.Second)

	_, err := c.ScanBytes(ScanBytesArgs{Data: make([]byte, MaxScanBytes+1)})
	if err == nil {
		t.Fatal("oversize ScanBytes must error, not silently succeed")
	}
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("want ErrPayloadTooLarge, got %v", err)
	}
}

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
