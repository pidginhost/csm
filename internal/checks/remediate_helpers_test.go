package checks

import "testing"

// --- FixDescription ---------------------------------------------------

func TestFixDescriptionWorldWritable(t *testing.T) {
	got := FixDescription("world_writable_php", "", "/home/alice/public_html/config.php")
	if got == "" {
		t.Error("expected description for world_writable_php")
	}
}

func TestFixDescriptionWebshell(t *testing.T) {
	got := FixDescription("webshell", "Found /home/alice/public_html/wso.php")
	if got == "" {
		t.Error("expected description for webshell")
	}
}

func TestFixDescriptionBackdoor(t *testing.T) {
	got := FixDescription("backdoor_binary", "", "/home/alice/.config/miner")
	if got == "" {
		t.Error("expected description for backdoor_binary")
	}
}

func TestFixDescriptionCrontab(t *testing.T) {
	got := FixDescription("suspicious_crontab", "")
	if got == "" {
		t.Error("expected description for suspicious_crontab")
	}
}

func TestFixDescriptionHtaccess(t *testing.T) {
	got := FixDescription("htaccess_injection", "", "/home/alice/public_html/.htaccess")
	if got == "" {
		t.Error("expected description for htaccess_injection")
	}
}

func TestFixDescriptionExim(t *testing.T) {
	got := FixDescription("email_phishing_content", "Phishing (message: 1ABC23-DEFG45-HI)")
	if got == "" {
		t.Error("expected description for email_phishing_content")
	}
}

func TestFixDescriptionUnknown(t *testing.T) {
	if got := FixDescription("unknown_check", ""); got != "" {
		t.Errorf("unknown check should return empty, got %q", got)
	}
}

// --- HasFix -----------------------------------------------------------

func TestHasFixTrue(t *testing.T) {
	for _, check := range []string{"world_writable_php", "webshell", "backdoor_binary", "htaccess_injection"} {
		if !HasFix(check) {
			t.Errorf("HasFix(%q) should be true", check)
		}
	}
}

func TestHasFixFalse(t *testing.T) {
	if HasFix("waf_status") {
		t.Error("waf_status should not have fix")
	}
}

// --- extractFilePathFromMessage ---------------------------------------

func TestExtractFilePathFromMessageHome(t *testing.T) {
	msg := "Found malware in /home/alice/public_html/evil.php size 1234"
	if got := extractFilePathFromMessage(msg); got != "/home/alice/public_html/evil.php" {
		t.Errorf("got %q", got)
	}
}

func TestExtractFilePathFromMessageTmp(t *testing.T) {
	msg := "Suspicious binary at /tmp/miner running"
	if got := extractFilePathFromMessage(msg); got != "/tmp/miner" {
		t.Errorf("got %q", got)
	}
}

func TestExtractFilePathFromMessageNone(t *testing.T) {
	if got := extractFilePathFromMessage("no path here"); got != "" {
		t.Errorf("got %q", got)
	}
}

// --- homeAccountRoot --------------------------------------------------

func TestHomeAccountRootValid(t *testing.T) {
	if got := homeAccountRoot("/home/alice/public_html/file.php"); got != "/home/alice" {
		t.Errorf("got %q, want /home/alice", got)
	}
}

func TestHomeAccountRootNonHome(t *testing.T) {
	if got := homeAccountRoot("/tmp/file"); got != "" {
		t.Errorf("non-home should return empty, got %q", got)
	}
}

func TestHomeAccountRootShallow(t *testing.T) {
	if got := homeAccountRoot("/home/alice"); got != "" {
		t.Errorf("too shallow should return empty, got %q", got)
	}
}

// --- extractEximMsgID -------------------------------------------------

func TestExtractEximMsgIDStandard(t *testing.T) {
	msg := "Phishing content detected (message: 1ABC23-DEFG45-HI)"
	if got := extractEximMsgID(msg); got != "1ABC23-DEFG45-HI" {
		t.Errorf("got %q", got)
	}
}

func TestExtractEximMsgIDMissing(t *testing.T) {
	if got := extractEximMsgID("no message id here"); got != "" {
		t.Errorf("got %q", got)
	}
}
