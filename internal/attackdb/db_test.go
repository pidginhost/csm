package attackdb

import "testing"

func TestClassify_SMTPChecksAsBruteForce(t *testing.T) {
	for _, check := range []string{"smtp_bruteforce", "smtp_subnet_spray"} {
		got := checkToAttack[check]
		if got != AttackBruteForce {
			t.Errorf("%q classified as %q, want %q", check, got, AttackBruteForce)
		}
	}
}

func TestClassify_MailChecksAsBruteForce(t *testing.T) {
	for _, check := range []string{"mail_bruteforce", "mail_subnet_spray", "mail_account_compromised"} {
		got := checkToAttack[check]
		if got != AttackBruteForce {
			t.Errorf("%q classified as %q, want %q", check, got, AttackBruteForce)
		}
	}
}
