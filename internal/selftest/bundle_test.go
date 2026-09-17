package selftest

import (
	"os/exec"
	"regexp"
	"testing"
)

func TestChrBuilderUsesCallableFunction(t *testing.T) {
	for _, sample := range Samples() {
		if sample.Name != "obfuscated_chr_builder" {
			continue
		}
		content, err := sample.Content()
		if err != nil {
			t.Fatal(err)
		}
		// Evaluate only a literal chr() assignment, never the payload or its
		// invocation. PHP language constructs cannot be variable functions.
		assignment := regexp.MustCompile(`^<\?php\s+(\$s=chr\([0-9]+\)(?:\.chr\([0-9]+\))*;)`).FindSubmatch(content)
		if len(assignment) != 2 {
			t.Fatal("chr sample has no literal function-name assignment")
		}
		probe := string(assignment[1]) + `if (!is_callable($s)) { fwrite(STDERR, "not callable: " . $s); exit(1); }`
		if output, err := exec.Command("php", "-r", probe).CombinedOutput(); err != nil {
			t.Fatalf("chr sample does not construct a callable function: %v: %s", err, output)
		}
		return
	}
	t.Fatal("chr sample missing from bundle")
}
