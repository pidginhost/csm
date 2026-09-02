package checks

import (
	"strings"
	"testing"
)

// The quarantine and pre-clean backup names embedded the whole source path
// with slashes replaced, so a deeply nested file produced a name past the
// 255-byte filename limit and the move failed with ENAMETOOLONG, leaving
// the malware in place. Long paths are shortened to a hash plus the tail.
func TestQuarantineSafeNameStaysWithinFilenameLimit(t *testing.T) {
	short := "/home/acct/public_html/shell.php"
	if got := quarantineSafeName(short); got != "_home_acct_public_html_shell.php" {
		t.Fatalf("short path name = %q", got)
	}

	long := "/home/acct/public_html/" + strings.Repeat("directory-with-a-long-name/", 12) + "payload.php"
	a := quarantineSafeName(long)
	if len(a) > 200 {
		t.Fatalf("long path name is %d bytes", len(a))
	}
	if !strings.HasSuffix(a, "payload.php") {
		t.Fatalf("long path name lost the file name: %q", a)
	}
	b := quarantineSafeName(strings.Replace(long, "acct", "other", 1))
	if a == b {
		t.Fatal("two different long paths map to the same quarantine name")
	}
}
