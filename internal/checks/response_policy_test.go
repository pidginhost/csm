package checks

import "testing"

func TestResponsePolicyRegistryIsValid(t *testing.T) {
	if err := validateResponsePolicy(checkRegistry); err != nil {
		t.Fatal(err)
	}
}

func TestValidateResponsePolicyRejectsContradictions(t *testing.T) {
	cases := map[string]CheckInfo{
		"critical-only without block":   {Name: "x_check", Response: ResponsePolicy{CriticalOnly: true}},
		"challenge and never challenge": {Name: "x_check", Response: ResponsePolicy{ChallengeFirst: true, NeverChallenge: true}},
		"challenge on a dynamic prefix": {Name: "modsec_x_check", Response: ResponsePolicy{ChallengeFirst: true}},
		"unknown eligibility":           {Name: "x_check", Response: ResponsePolicy{Block: BlockEligibility(9)}},
	}
	for name, entry := range cases {
		if err := validateResponsePolicy([]CheckInfo{entry}); err == nil {
			t.Errorf("%s: accepted %+v", name, entry.Response)
		}
	}
}

func TestResponsePolicyForUnknownCheckIsInert(t *testing.T) {
	for _, name := range []string{"", "not_a_check", "AUTO_BLOCK"} {
		if p := ResponsePolicyFor(name); p != (ResponsePolicy{}) {
			t.Errorf("ResponsePolicyFor(%q) = %+v, want the zero policy", name, p)
		}
	}
}

func TestNeverChallengeDynamicNames(t *testing.T) {
	for _, name := range []string{"modsec_attack_detected", "spam_outbreak", "outgoing_mail_hold", "email_auth_failure_smtp", "email_compromised_x", "email_credential_x"} {
		if !neverChallengeDynamicName(name) {
			t.Errorf("neverChallengeDynamicName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"wp_login_bruteforce", "ip_reputation", "email_phishing_content", ""} {
		if neverChallengeDynamicName(name) {
			t.Errorf("neverChallengeDynamicName(%q) = true, want false", name)
		}
	}
}
