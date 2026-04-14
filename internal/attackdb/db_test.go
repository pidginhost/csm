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
