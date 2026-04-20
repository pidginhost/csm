package daemon

import "testing"

// looksLikeAtomicWriteStage drives the realtime-scan skip for transient
// write-then-rename staging files. Fix context: cPanel's fileTransfer
// service produced a ~35-alert storm during a WordPress restore because
// every write landed at `.temp.<nanoseconds>.<name>.<ext>` (scanned by
// fanotify CLOSE_WRITE) before rename(2) to the final path (not scanned
// -- fanotify mask does not include MOVED_TO).

func TestLooksLikeAtomicWriteStage_Positive(t *testing.T) {
	cases := []string{
		".temp.1776678837447384369.PHPMailer.php",
		".temp.1776678837499645998.class-json.php",
		".temp.0.file.php",
		".temp.1.foo.html",
		".temp.9999999999.x.htaccess",
		".temp.1.a.b.c",
	}
	for _, name := range cases {
		if !looksLikeAtomicWriteStage(name) {
			t.Errorf("looksLikeAtomicWriteStage(%q) = false, want true", name)
		}
	}
}

func TestLooksLikeAtomicWriteStage_Negative(t *testing.T) {
	cases := []struct {
		name   string
		reason string
	}{
		{"temp.1234.file.php", "no leading dot"},
		{".temp.abc.file.php", "non-digit between the two dots"},
		{".temp.file.php", "no digits at all"},
		{".temp.1234", "no trailing name segment"},
		{".temp.1234.", "empty trailing name segment"},
		{".temporary.1234.file.php", "wrong prefix word"},
		{"PHPMailer.php", "plain filename"},
		{".tmp.1234.file.php", "abbreviated prefix (not matched)"},
		{"", "empty"},
	}
	for _, tc := range cases {
		if looksLikeAtomicWriteStage(tc.name) {
			t.Errorf("looksLikeAtomicWriteStage(%q) = true, want false (%s)", tc.name, tc.reason)
		}
	}
}
