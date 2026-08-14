//go:build yara

package mime

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	csmyara "github.com/pidginhost/csm/internal/yara"
)

func TestExtractedZIPMemberYARAScanPreservesOffsetZero(t *testing.T) {
	shell := []byte("#!/bin/bash\n" +
		"echo \"Content-type: text/html\"\n" +
		"echo \"\"\n" +
		"CMD=$(echo \"$QUERY_STRING\" | base64 -d)\n" +
		"eval \"$CMD\"\n")
	archive := buildZipArchive(t, map[string][]byte{"cgi/shell.cgi": shell})
	body := buildMultipartBody("BOUND", "upload.zip", "application/zip", archive)
	headerPath, bodyPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)
	limits := DefaultLimits()
	limits.TempDir = t.TempDir()

	result, err := ParseSpoolMessage(headerPath, bodyPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, part := range result.Parts {
			_ = os.Remove(part.TempPath)
		}
	}()

	scanner, err := csmyara.NewScanner(filepath.Join("..", "..", "configs"))
	if err != nil {
		t.Fatalf("loading YARA rules: %v", err)
	}
	for _, part := range result.Parts {
		if !part.Nested || part.Filename != "shell.cgi" {
			continue
		}
		data, readErr := os.ReadFile(part.TempPath)
		if readErr != nil {
			t.Fatalf("reading extracted member: %v", readErr)
		}
		if !bytes.HasPrefix(data, []byte("#!/bin/bash")) {
			t.Fatalf("extracted archive member does not start at its own offset zero: %q", data)
		}
		matches, scanErr := csmyara.ScanBytesChecked(scanner, data)
		if scanErr != nil {
			t.Fatalf("scanning extracted member: %v", scanErr)
		}
		for _, match := range matches {
			if match.RuleName == "cgi_webshell_bash" {
				return
			}
		}
		t.Fatal("cgi_webshell_bash did not detect a real shell extracted from ZIP")
	}
	t.Fatal("ZIP member shell.cgi was not extracted as a nested part")
}
