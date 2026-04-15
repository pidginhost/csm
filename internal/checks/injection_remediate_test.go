package checks

import (
	"strings"
	"testing"
)

// Error-path tests for remediate.go fix functions. These exercise the
// validation guards and run on any platform (no real file ops).

func TestFixPermissionsEmptyPath(t *testing.T) {
	got := fixPermissions("")
	if got.Success || !strings.Contains(got.Error, "could not extract") {
		t.Errorf("expected error for empty path, got %+v", got)
	}
}

func TestFixPermissionsRelativePath(t *testing.T) {
	got := fixPermissions("relative/path.php")
	if got.Success || !strings.Contains(got.Error, "must be absolute") {
		t.Errorf("expected absolute-path error, got %+v", got)
	}
}

func TestFixPermissionsOutsideAllowedRoots(t *testing.T) {
	// /etc is not under /home, the only root allowed for fixPermissions.
	got := fixPermissions("/etc/passwd")
	if got.Success || !strings.Contains(got.Error, "outside the allowed") {
		t.Errorf("expected outside-roots error, got %+v", got)
	}
}

func TestFixPermissionsNonExistentPath(t *testing.T) {
	got := fixPermissions("/home/nobody/missing.php")
	if got.Success || !strings.Contains(got.Error, "file not found") {
		t.Errorf("expected not-found error, got %+v", got)
	}
}

func TestFixQuarantineEmptyPath(t *testing.T) {
	got := fixQuarantine("")
	if got.Success || !strings.Contains(got.Error, "could not extract") {
		t.Errorf("expected error for empty path, got %+v", got)
	}
}

func TestFixQuarantineOutsideAllowedRoots(t *testing.T) {
	got := fixQuarantine("/etc/passwd")
	if got.Success || !strings.Contains(got.Error, "outside the allowed") {
		t.Errorf("expected outside-roots error, got %+v", got)
	}
}

func TestFixHtaccessEmptyPath(t *testing.T) {
	got := fixHtaccess("", "msg")
	if got.Success || !strings.Contains(got.Error, "could not extract") {
		t.Errorf("expected error for empty path, got %+v", got)
	}
}

func TestFixHtaccessWrongFilename(t *testing.T) {
	// Caller passed a non-.htaccess path - guard rejects it before any I/O.
	got := fixHtaccess("/home/alice/public_html/index.php", "msg")
	if got.Success || !strings.Contains(got.Error, "only applies to .htaccess") {
		t.Errorf("expected filename-guard error, got %+v", got)
	}
}

func TestFixHtaccessOutsideAllowedRoots(t *testing.T) {
	got := fixHtaccess("/etc/.htaccess", "msg")
	if got.Success || !strings.Contains(got.Error, "outside the allowed") {
		t.Errorf("expected outside-roots error, got %+v", got)
	}
}

func TestFixQuarantineSpoolMessageNoMsgID(t *testing.T) {
	got := fixQuarantineSpoolMessage("no message id here")
	if got.Success || !strings.Contains(got.Error, "could not extract Exim message ID") {
		t.Errorf("expected msg-id error, got %+v", got)
	}
}

func TestFixQuarantineSpoolMessageInvalidMsgIDFormat(t *testing.T) {
	// Path-traversal attempt should be rejected by the format regex.
	got := fixQuarantineSpoolMessage("(message: ../../../etc/passwd)")
	if got.Success || !strings.Contains(got.Error, "invalid Exim message ID format") {
		t.Errorf("expected format error, got %+v", got)
	}
}

func TestFixQuarantineSpoolMessageNotFound(t *testing.T) {
	// Valid format but no spool file present.
	got := fixQuarantineSpoolMessage("(message: 2jKPFm-000abc-1X)")
	if got.Success || !strings.Contains(got.Error, "not found") {
		t.Errorf("expected not-found error, got %+v", got)
	}
}

func TestExtractEximMsgID(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"phishing detected (message: 2jKPFm-000abc-1X) blah", "2jKPFm-000abc-1X"},
		{"no marker", ""},
		{"(message: open-but-no-close", ""},
		{"(message: )", ""},
	}
	for _, c := range cases {
		if got := extractEximMsgID(c.in); got != c.want {
			t.Errorf("extractEximMsgID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
