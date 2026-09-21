//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// oversizeInlineBackend refuses an inline payload the way the worker IPC does
// once the buffered content passes the frame ceiling, but can still read the
// file itself.
type oversizeInlineBackend struct{ scannedPath string }

func (*oversizeInlineBackend) ScanBytes([]byte) []yara.Match     { return nil }
func (*oversizeInlineBackend) ScanFile(string, int) []yara.Match { return nil }
func (*oversizeInlineBackend) Reload() error                     { return nil }
func (*oversizeInlineBackend) RuleCount() int                    { return 1 }

func (*oversizeInlineBackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	return nil, fmt.Errorf("%w (%d > %d bytes)", yaraipc.ErrPayloadTooLarge, 13418072, yaraipc.MaxScanBytes)
}

func (b *oversizeInlineBackend) ScanFileChecked(path string, _ int) (yara.FileScanResult, error) {
	b.scannedPath = path
	sum := sha256.Sum256([]byte("payload"))
	return yara.FileScanResult{
		Matches:       []yara.Match{{RuleName: "oversize_payload"}},
		ContentSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

// The frame ceiling is a property of the transport, not of the file. The deep
// scan and the mail path both fall back to letting the worker open the file,
// but the realtime path reported a scan error and stopped -- so padding a
// dropper past the inline ceiling kept it from ever being scanned on write.
func TestRealtimeYARARetriesOversizePayloadByPath(t *testing.T) {
	backend := &oversizeInlineBackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })

	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	const path = "/home/alice/public_html/big.php"

	if !fm.runSignatureScan([]byte("<?php payload; ?>"), path, ".php", "") {
		t.Fatal("an oversize inline payload was not retried by path, so the file is never scanned on write")
	}
	if backend.scannedPath != path {
		t.Fatalf("path retry scanned %q, want %q", backend.scannedPath, path)
	}

	var got alert.Finding
	select {
	case got = <-alerts:
	default:
		t.Fatal("no alert emitted for the rule that matched on the path retry")
	}
	if got.Check != "yara_match_realtime" {
		t.Fatalf("alert check = %q, want yara_match_realtime", got.Check)
	}
}
