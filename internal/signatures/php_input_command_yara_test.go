//go:build yara

package signatures

import "testing"

func TestPHPInputCommandYARA(t *testing.T) {
	scanner := repositoryYARAScanner(t)
	for _, tc := range phpInputCommandSamples() {
		t.Run(tc.name, func(t *testing.T) {
			if got := yaraRuleFired(t, scanner, "dropper_php_input_stream", []byte(tc.sample)); got != tc.want {
				t.Errorf("request-body command match = %t, want %t", got, tc.want)
			}
		})
	}
}
