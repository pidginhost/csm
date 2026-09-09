//go:build yara

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelfTestRunsRejectUnavailableYaraRules(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"missing", ""},
		{"invalid", "rule broken {"},
		{"empty", "// no rules\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := selfTestRulesDir(t)
			if tc.content != "" {
				if err := os.WriteFile(filepath.Join(dir, "malware.yar"), []byte(tc.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := selfTestRuns(dir); err == nil {
				t.Fatal("unusable YARA rules report success")
			}
		})
	}
}
