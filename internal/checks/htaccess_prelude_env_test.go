package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// PHP-FPM reads PHP_VALUE from the FastCGI parameters, and Apache passes
// environment variables through as parameters, so a prelude set through an
// environment variable runs like php_value does. The variable name is no
// evidence either: Apache expands an E= name, so a request header can supply
// it. The target is the evidence wherever the line carries one.
var htaccessPreludeThroughEnvironment = []string{
	"SetEnv PHP_VALUE \"auto_prepend_file=/tmp/x.php\"\n",
	"RewriteRule .* - [E=PHP_VALUE:auto_prepend_file=/tmp/x.php]\n",
	"RewriteCond %{HTTP:X-N} (.+)\nRewriteRule .* - [E=%1:auto_prepend_file=/tmp/x.php]\n",
}

func TestHtaccessPreludeThroughEnvironmentIsReported(t *testing.T) {
	for _, body := range htaccessPreludeThroughEnvironment {
		path := filepath.Join(t.TempDir(), ".htaccess")
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		var findings []alert.Finding
		checkHtaccessFile(context.Background(), path, []string{"auto_prepend_file"}, nil, &findings)
		if countByCheck(findings, "htaccess_injection") != 1 {
			t.Errorf("scheduled findings for %q = %+v, want one htaccess_injection", body, findings)
		}
	}
}

// Really Simple Security writes its prelude as a php_value directive; that is
// the only form kept out of cleaning. Its filename behind an environment
// variable is an ordinary prelude, so the finding is cleanable.
func TestHtaccessPluginPreludeNameThroughEnvironmentIsCleanable(t *testing.T) {
	findings, ranges := AuditHtaccessContent("/home/example/public_html/.htaccess",
		[]byte("SetEnv PHP_VALUE \"auto_prepend_file=/home/example/other/wp-content/advanced-headers.php\"\n"))
	if got := countByCheck(findings, "htaccess_injection"); got != 1 {
		t.Errorf("findings = %+v, want one htaccess_injection", findings)
	}
	if len(ranges) != 1 {
		t.Errorf("removal ranges = %v, want the directive", ranges)
	}
}
