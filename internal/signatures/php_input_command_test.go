package signatures

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func phpInputCommandSamples() []struct {
	name, sample string
	want         bool
} {
	return []struct {
		name, sample string
		want         bool
	}{
		{"direct", `<?php system(file_get_contents('php://input'));`, true},
		{"suppressed read", `<?php system(@file_get_contents('php://input'));`, true},
		{"suppressed decoder", `<?php passthru(@base64_decode(file_get_contents('php://input')));`, true},
		{"suppressed nested decoder", `<?php exec(base64_decode(@str_rot13(@file_get_contents('php://input'))));`, true},
		{"five decoders", `<?php shell_exec(` + strings.Repeat("base64_decode(", 5) + `file_get_contents('php://input')` + strings.Repeat(")", 5) + `);`, true},
		{"assigned", `<?php $body = file_get_contents('php://input'); system($body);`, true},
		{"assigned with command suffix", `<?php $body = file_get_contents('php://input') . ' 2>&1'; system($body);`, true},
		{"assigned with variable suffix", `<?php $body = file_get_contents('php://input') . $suffix; system($body);`, true},
		{"assigned with fallback", `<?php $body = file_get_contents('php://input') ?: 'true'; system($body);`, true},
		{"suppressed variable", `<?php $body = file_get_contents('php://input'); system(@$body);`, true},
		{"mixed case", "<?php $C = @FILE_GET_CONTENTS('PHP://INPUT'); // run\nSHELL_EXEC($C);", true},
		{"padded read", `<?php $body = file_get_contents('php://input'` + strings.Repeat(" ", 256) + `); system($body);`, true},
		{"long comment", "<?php $body = file_get_contents('php://input'); // " + strings.Repeat("padding ", 40) + "\nsystem($body);", true},
		{"boolean result", `<?php $hasBody = file_get_contents('php://input') !== false; system($hasBody);`, false},
		{"JSON with unrelated command", `<?php
function read_body() {
    $raw = file_get_contents('php://input');
    return json_decode($raw, true);
}
function diagnostics($command) {
    return popen($command, 'r');
}`, false},
		{"decoded JSON", `<?php system(json_decode(file_get_contents('php://input')));`, false},
	}
}

func TestPHPInputCommandYAML(t *testing.T) {
	scanner := loadRepoScanner(t)
	for _, tc := range phpInputCommandSamples() {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasRule(scanner.ScanContent([]byte(tc.sample), ".php"), "dropper_php_input_stream"); got != tc.want {
				t.Errorf("request-body command match = %t, want %t", got, tc.want)
			}
		})
	}
}

// The command branches use the common regex subset of Go and YARA-X. Keep
// their source identical too, so non-YARA builds catch accidental drift.
// The tagged test checks behavior with the real YARA-X engine.
func TestPHPInputCommandPatternsStayInSync(t *testing.T) {
	scanner := loadRepoScanner(t)
	var yamlPatterns []string
	for _, rule := range scanner.rules {
		if rule.Name == "dropper_php_input_stream" {
			yamlPatterns = rule.Regexes
		}
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)rule dropper_php_input_stream \{.*?\n\}`).Find(data)
	patterns := regexp.MustCompile(`(?m)^\s*\$(command_input|assigned_command) = /(.*)/ nocase$`).FindAllSubmatch(block, -1)
	if len(patterns) != 2 {
		t.Fatalf("found %d command patterns, want 2", len(patterns))
	}
	var commandPatterns []*regexp.Regexp
	for _, pattern := range patterns {
		src := strings.ReplaceAll(string(pattern[2]), `\/`, `/`)
		commandPatterns = append(commandPatterns, regexp.MustCompile("(?i)"+src))
		if !slices.Contains(yamlPatterns, src) {
			t.Errorf("YARA %s has no identical YAML command pattern", pattern[1])
		}
	}
	for _, tc := range phpInputCommandSamples() {
		t.Run(tc.name, func(t *testing.T) {
			got := slices.ContainsFunc(commandPatterns, func(re *regexp.Regexp) bool {
				return re.MatchString(tc.sample)
			})
			if got != tc.want {
				t.Errorf("command regex match under Go = %t, want %t", got, tc.want)
			}
		})
	}
}
