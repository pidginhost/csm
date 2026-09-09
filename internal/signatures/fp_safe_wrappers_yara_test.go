//go:build yara

package signatures

import (
	"os"
	"path/filepath"
	"testing"

	yara_x "github.com/VirusTotal/yara-x/go"
)

func TestFPSafe_YARA_CreateFunction(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "configs", "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := yara_x.Compile(string(source))
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Destroy()
	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()

	check := func(t *testing.T, sample string, want bool) {
		t.Helper()
		results, err := scanner.Scan([]byte(sample))
		if err != nil {
			t.Fatal(err)
		}
		hit := false
		for _, rule := range results.MatchingRules() {
			if rule.Identifier() == "obfuscation_create_function_exec" {
				hit = true
			}
		}
		if hit != want {
			t.Errorf("obfuscation_create_function_exec match = %t, want %t", hit, want)
		}
	}
	// The same cases exercise both engines, so neither can silently lose body
	// sources or start borrowing execution evidence from unrelated arguments.
	t.Run("body", func(t *testing.T) {
		for name, call := range safeCreateFunctionBodyExpressions() {
			t.Run(name, func(t *testing.T) {
				check(t, "<?php $f = "+call+"; $f();", true)
			})
		}
	})
	t.Run("benign", func(t *testing.T) {
		for name, sample := range safeCreateFunctionBenignSamples() {
			t.Run(name, func(t *testing.T) {
				check(t, sample, false)
			})
		}
	})
}
