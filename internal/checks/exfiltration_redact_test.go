package checks

import (
	"context"
	"os"
	"strings"
	"testing"
)

// The database_dump finding quoted the whole /proc cmdline, so a
// mysqldump -pSECRET invocation shipped the database password into the
// finding store, the web UI and every alert channel.
func TestCheckDatabaseDumpsRedactsPasswordArgument(t *testing.T) {
	oldOS := osFS
	osFS = &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/proc/4242/cmdline"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/4242/cmdline":
				return []byte("mysqldump\x00-u\x00shop\x00-pS3cr3t!\x00shop_db\x00"), nil
			case "/proc/4242/status":
				return []byte("Name:\tmysqldump\nUid:\t1001\t1001\t1001\t1001\n"), nil
			}
			return nil, os.ErrNotExist
		},
	}
	t.Cleanup(func() { osFS = oldOS })

	findings := CheckDatabaseDumps(context.Background(), nil, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if strings.Contains(findings[0].Details, "S3cr3t") {
		t.Fatalf("password argument leaked into details: %q", findings[0].Details)
	}
	if !strings.Contains(findings[0].Details, "-p[REDACTED]") {
		t.Fatalf("details do not show the redacted argument: %q", findings[0].Details)
	}
}
