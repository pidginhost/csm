package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Severity is how an operator triages, and these two fire on ordinary use of
// core hosting features: any File Manager upload, save, rename, paste or
// delete, and any successful FTP login. On shared hosting every customer is a
// "non-infra IP", so rating them Critical and High made routine work look
// like an incident and buried the findings that are not routine.
//
// A production host raised Critical for a customer uploading a file, and High
// for five addresses whose FTP logins had already succeeded.
//
// Warning keeps the record without claiming a verdict. The value of these
// findings is correlation -- a File Manager write from an unfamiliar address
// on an account whose password just changed -- not the single event.
func TestSuccessfulAuthFindingsAreNotHighSeverity(t *testing.T) {
	cfg := &config.Config{}

	tests := []struct {
		name, line, wantCheck string
	}{
		{
			name:      "file manager upload",
			line:      `198.51.100.10 - alice [10/Sep/2026:12:00:00 -0000] "POST /cpsess1234/execute/Fileman/upload_files HTTP/1.1" 200 12 "-" "Mozilla/5.0" 2083`,
			wantCheck: "cpanel_file_upload_realtime",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got *alert.Finding
			for _, f := range parseAccessLogLineEnhanced(tc.line, cfg) {
				if f.Check == tc.wantCheck {
					finding := f
					got = &finding
				}
			}
			if got == nil {
				t.Fatalf("%s was not produced for line: %s", tc.wantCheck, tc.line)
			}
			if got.Severity == alert.Critical || got.Severity == alert.High {
				t.Errorf("%s severity = %v; a successful authenticated operation must not be Critical or High",
					tc.wantCheck, got.Severity)
			}
		})
	}
}

// The same for a successful FTP login, which pure-ftpd records only after
// authentication succeeded.
func TestSuccessfulFTPLoginIsNotHighSeverity(t *testing.T) {
	cfg := &config.Config{}
	line := `Sep 10 11:30:46 cp1 pure-ftpd[281309]: (?@198.51.100.11) [INFO] alice@example.com is now logged in`

	var got *alert.Finding
	for _, f := range parseFTPLogLine(line, cfg) {
		if f.Check == "ftp_login" {
			finding := f
			got = &finding
		}
	}
	if got == nil {
		t.Fatal("ftp_login was not produced for a successful login line")
	}
	if got.Severity == alert.Critical || got.Severity == alert.High {
		t.Errorf("ftp_login severity = %v; a successful login must not be Critical or High", got.Severity)
	}
}

// Failed FTP authentication is real evidence and keeps its severity, or the
// change would trade a false positive for a blind spot.
func TestFailedFTPAuthKeepsItsSeverity(t *testing.T) {
	cfg := &config.Config{}
	line := `Sep 10 11:30:46 cp1 pure-ftpd[281309]: (?@198.51.100.12) [WARNING] Authentication failed for user [alice]`

	for _, f := range parseFTPLogLine(line, cfg) {
		if f.Check == "ftp_auth_failure_realtime" {
			// Warning is the lowest severity this codebase has; a failed
			// authentication must stay above it.
			if f.Severity == alert.Warning {
				t.Error("ftp_auth_failure_realtime was downgraded to Warning; failed auth is real evidence")
			}
			return
		}
	}
	t.Fatal("ftp_auth_failure_realtime was not produced for a failed authentication line")
}
