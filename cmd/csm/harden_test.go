package main

import (
	"strings"
	"testing"
)

func TestHardenUsageMentionsCopyFail(t *testing.T) {
	got := hardenUsageString()
	if !strings.Contains(got, "--copy-fail") {
		t.Error("usage should document the --copy-fail subcommand")
	}
	if !strings.Contains(strings.ToLower(got), "cve-2026-31431") {
		t.Error("usage should reference the CVE for searchability")
	}
}
