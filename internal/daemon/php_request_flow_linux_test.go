//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestPHPRequestBodyTextStaysReviewOnly(t *testing.T) {
	for _, body := range []string{
		"<?php $example = `cat <<'TEXT'\nsystem(file_get_contents(\"php://input\"))\nTEXT`;",
		"<?php $example = `printf 'system(file_get_contents(\"php://input\"))'`;",
		"<?php $value = `printf 'php://input'`; system(file_get_contents($value));",
		"<?php $value = `printf \"php://input\"`; system(file_get_contents($value));",
		"<?php $example = `system(file_get_contents('php://input'));",
		"<?php $example = <<<TEXT\nsystem(file_get_contents('php://input'));\nTEXT;",
		"<?php $example = <<<'TEXT'\nsystem(file_get_contents('php://input'));\nTEXT;",
		"<p>system(file_get_contents('php://input'))</p><?php system($local);",
	} {
		t.Run(body, func(t *testing.T) {
			if confirmedPHPExecutionData([]byte(body)) {
				t.Error("literal text confirmed PHP execution")
			}
			root := t.TempDir()
			path := filepath.Join(root, "example.php")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{StatePath: root}
			cfg.AutoResponse.Enabled, cfg.AutoResponse.QuarantineFiles = true, true
			oldResponse := inlineQuarantineConfirmedPHP
			calls := 0
			inlineQuarantineConfirmedPHP = func(_ *config.Config, _ *alert.Finding, _ string, _ []byte, _ os.FileInfo, _ int) (string, bool, *alert.Finding) {
				calls++
				return "", false, nil
			}
			t.Cleanup(func() { inlineQuarantineConfirmedPHP = oldResponse })
			alerts := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: cfg, alertCh: alerts}
			fm.checkPHPContent(openRawFd(t, path), path, "")
			if calls != 0 {
				t.Errorf("inline quarantine called %d times for literal text", calls)
			}
			close(alerts)
			for finding := range alerts {
				if finding.AutoFileResponseEvaluated {
					t.Error("literal text was marked as an automatic file response")
				}
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != body {
				t.Fatalf("review-only finding changed the file: %v", err)
			}
		})
	}
}

func TestPHPRequestBodyFlowAfterBacktick(t *testing.T) {
	// Shell quotes do not delimit PHP strings. They must not hide the real
	// request flow that follows the closing backtick.
	const body = "<?php $example = `printf '\n`; $body = file_get_contents('php://input'); system($body);"
	if !confirmedPHPExecutionData([]byte(body)) {
		t.Fatal("backtick content hid a subsequent request-to-execution flow")
	}
}
