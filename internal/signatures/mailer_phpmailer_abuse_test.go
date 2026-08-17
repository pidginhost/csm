package signatures

import "testing"

// The rule fired whenever request data appeared anywhere after addAddress or
// send on a line, which is the shape of any demo form that passes a display
// name through. What actually marks an open relay is the recipient itself
// coming from the request.

func TestMailerPHPMailerAbuse_RecipientFromRequest(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
require 'PHPMailer/PHPMailerAutoload.php';
$mail = new PHPMailer();
$mail->isSMTP();
foreach ($list as $row) {
    $mail->addAddress($_POST['to']);
    $mail->send();
}
if (!$sent) { mail($fallback, $subject, $body); }
`)

	if !hasRule(scanner.ScanContent(malicious, ".php"), "mailer_phpmailer_abuse") {
		t.Error("mailer_phpmailer_abuse miss: recipient taken straight from the request is an open relay")
	}
}

func TestMailerPHPMailerAbuse_BccAndCcFromRequest(t *testing.T) {
	scanner := loadRepoScanner(t)

	for name, sample := range map[string]string{
		"bcc": `<?php
require 'PHPMailer/PHPMailerAutoload.php';
$mail = new PHPMailer();
$mail->addBCC($_REQUEST['bcc']);
$mail->send();
mail($x, $y, $z);
`,
		"cc": `<?php
require 'PHPMailer/PHPMailerAutoload.php';
$mail = new PHPMailer();
$mail->addCC($_GET['cc']);
$mail->send();
mail($x, $y, $z);
`,
	} {
		t.Run(name, func(t *testing.T) {
			if !hasRule(scanner.ScanContent([]byte(sample), ".php"), "mailer_phpmailer_abuse") {
				t.Errorf("mailer_phpmailer_abuse miss: %s recipient from request", name)
			}
		})
	}
}

// PHPMailer ships this shape in its own examples directory, and those files sit
// on shared hosts in large numbers. The recipient is a local variable; only the
// display name comes from the request, so nothing here is attacker-routable.
func TestMailerPHPMailerAbuse_ExampleFormWithRequestDisplayName(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
require '../PHPMailerAutoload.php';
$mail = new PHPMailer();
$to = 'owner@example.test';
if (array_key_exists('To_Name', $_POST)) {
    $mail->addAddress($to, $_POST['To_Name']);
    $example_code .= "\n\$mail->addAddress(\"$to\", \"" . $_POST['To_Name'] . "\");";
}
$mail->send();
if (!$ok) { mail($to, $subject, $body); }
`)

	if hasRule(scanner.ScanContent(legit, ".php"), "mailer_phpmailer_abuse") {
		t.Error("mailer_phpmailer_abuse FP: only the display name comes from the request, not the recipient")
	}
}

// A contact form mailing the site owner is the overwhelmingly common shape:
// hardcoded recipient, request data only in the body.
func TestMailerPHPMailerAbuse_ContactFormToOwner(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
require 'PHPMailer/PHPMailerAutoload.php';
$mail = new PHPMailer();
$mail->addAddress('owner@example.test');
$mail->Body = $_POST['message'];
$mail->send();
if (!$ok) { mail('owner@example.test', $subject, $body); }
`)

	if hasRule(scanner.ScanContent(legit, ".php"), "mailer_phpmailer_abuse") {
		t.Error("mailer_phpmailer_abuse FP: hardcoded recipient with request data in the body is a contact form")
	}
}
