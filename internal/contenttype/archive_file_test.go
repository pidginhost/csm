package contenttype

import "testing"

// A file that starts with archive magic is only an archive when its name says
// so as well. PHP echoes any leading bytes and runs the rest, so four bytes of
// ZIP magic in front of a webshell must not exempt it from scanning.
func TestIsArchiveFileNeedsNameAndMagic(t *testing.T) {
	zipMagic := []byte{'P', 'K', 0x03, 0x04}
	shell := append(append([]byte{}, zipMagic...), []byte("<?php system($_POST['cmd']);")...)
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"backup.zip", zipMagic, true},
		{"/home/u/backups/site-2026.tar.gz", []byte{0x1f, 0x8b, 0x08, 0x00}, true},
		{"report.docx", zipMagic, true},
		{"plugin.jar", zipMagic, true},
		{"x.7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, true},
		{"shell.php", shell, false},
		{"shell.phtml", shell, false},
		{"index.html", shell, false},
		{"noext", zipMagic, false},
		{"notes.txt", zipMagic, false},
		{"backup.zip", []byte("<?php echo 1;"), false},
		{"BACKUP.ZIP", zipMagic, true},
	}
	for _, c := range cases {
		if got := IsArchiveFile(c.name, c.data); got != c.want {
			t.Errorf("IsArchiveFile(%q) = %t, want %t", c.name, got, c.want)
		}
	}
}
