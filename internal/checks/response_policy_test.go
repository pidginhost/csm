package checks

import (
	"strings"
	"sync"
	"testing"
)

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

func TestResponsePolicyForFollowsRenamedProducers(t *testing.T) {
	for name, want := range map[string]ResponsePolicy{
		"ssh_login_realtime":   {Block: BlockAlways},
		"ssh_login_unknown_ip": {Block: BlockAlways},
		"ftp_login_realtime":   {},
		"ftp_login":            {},
	} {
		if got := ResponsePolicyFor(name); got != want {
			t.Errorf("ResponsePolicyFor(%q)=%+v want %+v", name, got, want)
		}
	}
}

// The registry and lookup must carry exactly the frozen policy.
func TestRegistryResponsePolicyMatchesGoldenTables(t *testing.T) {
	for _, c := range checkRegistry {
		want := ResponsePolicy{
			CriticalOnly:   c.Name == "mail_account_compromised",
			ChallengeFirst: goldenChallengeable[c.Name],
			NeverChallenge: goldenNeverChallenge[c.Name],
		}
		switch {
		case goldenAlwaysBlock[c.Name]:
			want.Block = BlockAlways
		case goldenCpanelFailure[c.Name]:
			want.Block = BlockWithCpanelLogins
		}
		if c.Response != want {
			t.Errorf("registry %q Response = %+v, want %+v", c.Name, c.Response, want)
		}
		if got := ResponsePolicyFor(c.Name); got != want {
			t.Errorf("lookup %q Response = %+v, want %+v", c.Name, got, want)
		}
	}
}

// Attacker-side checks that deliberately never drive an IP response. Each is
// a summary of many sources, an advisory, or evidence another layer already
// acted on. Adding an attacker-side check to the registry means either giving
// it a Response or adding it here with a reason.
var nonActionableAttackerSide = map[string]string{
	"email_auth_failure_realtime": "one raw mailbox failure; thresholded checks block",
	"email_malware":               "content may come from a compromised local sender",
	"email_phishing_content":      "content may come from a compromised local sender",
	"http_asn_crawl":              "subnet-scoped; handled by its own tempban path",
	"http_distributed_flood":      "describes a targeted vhost, not one source",
	"mail_account_spray":          "per-mailbox summary of many sources",
	"mail_bruteforce_suspected":   "advisory for an established source",
	"mail_subnet_spray":           "subnet summary; no single-IP block or challenge policy",
	"smtp_subnet_spray":           "subnet summary; no single-IP block or challenge policy",
	"modsec_block_realtime":       "ModSecurity already denied the request",
	"modsec_low_confidence_burst": "low-confidence advisory",
	"modsec_warning_realtime":     "warning-level WAF event",
	"smtp_account_spray":          "per-mailbox summary of many sources",
	"whm_unauth_scripts_realtime": "unauthenticated WHM script probe; visibility only",
}

func TestAttackerSideChecksHaveAResponseDecision(t *testing.T) {
	for _, c := range checkRegistry {
		if correlationReasonOf(c.Name) != reasonAttackerSide {
			continue
		}
		_, listed := nonActionableAttackerSide[c.Name]
		hasPolicy := c.Response.Block != BlockNever || c.Response.ChallengeFirst
		switch {
		case hasPolicy && listed:
			t.Errorf("%q has a response policy and is listed as non-actionable", c.Name)
		case !hasPolicy && !listed:
			t.Errorf("attacker-side check %q has no response decision: give it a Response or list it in nonActionableAttackerSide", c.Name)
		}
	}
	for name, reason := range nonActionableAttackerSide {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("non-actionable check %q has no explanation", name)
		}
		if _, ok := LookupCheck(name); !ok || correlationReasonOf(name) != reasonAttackerSide {
			t.Errorf("nonActionableAttackerSide lists %q, which is not a registered attacker-side check", name)
		}
	}
}

// A record of an action or CSM's own health must never become an input that
// aims another response.
func TestResponseAndHealthChecksAreNeverActionable(t *testing.T) {
	for name, reason := range map[string]string{"auto_block": reasonResponse, "challenge_route": reasonResponse, "yara_worker_crashed": reasonSelfHealth} {
		if _, ok := LookupCheck(name); !ok || correlationReasonOf(name) != reason {
			t.Fatalf("required response/health sentinel %q is missing or reclassified", name)
		}
	}
	for _, c := range checkRegistry {
		switch correlationReasonOf(c.Name) {
		case reasonResponse, reasonSelfHealth:
			if c.Response.Block != BlockNever || c.Response.ChallengeFirst {
				t.Errorf("%q is a response or health record but has an actionable policy %+v", c.Name, c.Response)
			}
		}
	}
}

// Concurrent first reads must all see the complete index. Run alone with
// -race in a fresh process to cover the first initialization.
func TestResponsePolicyLookupConcurrent(t *testing.T) {
	want := map[string]ResponsePolicy{
		"ssh_login_realtime":  {Block: BlockAlways},
		"wp_login_bruteforce": {Block: BlockAlways, ChallengeFirst: true},
		"not_a_check":         {},
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan string, 32*len(want)*50)
	for r := 0; r < 32; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 50; i++ {
				for name, w := range want {
					if got := ResponsePolicyFor(name); got != w {
						errs <- name
						return
					}
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for name := range errs {
		t.Errorf("concurrent ResponsePolicyFor(%q) returned %+v, want %+v", name, ResponsePolicyFor(name), want[name])
	}
}
