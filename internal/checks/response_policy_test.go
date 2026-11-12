package checks

import (
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
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
		"ssh_login_realtime":   {Block: BlockAlways, Evidence: admission.FamilySSH, Basis: admission.BasisLocal, Attribution: peerKind},
		"ssh_login_unknown_ip": {Block: BlockAlways, Evidence: admission.FamilySSH, Basis: admission.BasisLocal, Attribution: peerKind},
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
			CriticalOnly:   goldenCriticalOnly[c.Name],
			ChallengeFirst: goldenChallengeable[c.Name],
			NeverChallenge: goldenNeverChallenge[c.Name],
			Evidence:       evidencePolicy[c.Name].Family,
			Basis:          evidencePolicy[c.Name].Basis,
			Attribution:    evidencePolicy[c.Name].Attribution,
			Subnet:         goldenSubnet[c.Name],
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

// goldenSubnet is the subnet response each subnet summary feeds.
var goldenSubnet = map[string]admission.Entry{
	"mail_subnet_spray": admission.EntryMailSubnet,
	"smtp_subnet_spray": admission.EntryMailSubnet,
	"http_asn_crawl":    admission.EntryASNCrawl,
}

// Attacker-side checks that deliberately never drive a single-IP scan block
// or a challenge. Each is a summary of many sources, an advisory, or evidence
// another layer already acted on; the subnet summaries among them feed the
// subnet response their registry row names. Adding an attacker-side check to
// the registry means either giving it a Response or adding it here with a
// reason.
var nonActionableAttackerSide = map[string]string{
	"email_av_parse_worker_source":  "advisory for an account, address or subnet; no single-IP response",
	"email_auth_failure_realtime":   "one raw mailbox failure; thresholded checks block",
	"email_malware":                 "content may come from a compromised local sender",
	"email_phishing_content":        "content may come from a compromised local sender",
	"email_php_form_relay_observed": "observe mode report; aims no response",
	"http_asn_crawl":                "subnet-scoped; handled by its own tempban path",
	"local_threat_score":            "retired: nothing emits it; kept so a scan clears stored findings",
	"http_distributed_flood":        "describes a targeted vhost, not one source",
	"mail_account_spray":            "per-mailbox summary of many sources",
	"mail_bruteforce_suspected":     "advisory for an established source",
	"mail_spam_source":              "report only; no local response by design",
	"mail_subnet_spray":             "subnet summary; no single-IP block or challenge policy",
	"stalwart_webmail_bruteforce":   "address may come from a forwarded header; Stalwart throttles and bans it",
	"smtp_subnet_spray":             "subnet summary; no single-IP block or challenge policy",
	"modsec_block_realtime":         "ModSecurity already denied the request",
	"modsec_low_confidence_burst":   "low-confidence advisory",
	"modsec_warning_realtime":       "warning-level WAF event",
	"smtp_account_spray":            "per-mailbox summary of many sources",
	"whm_unauth_scripts_realtime":   "unauthenticated WHM script probe; visibility only",
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
		"ssh_login_realtime":  {Block: BlockAlways, Evidence: admission.FamilySSH, Basis: admission.BasisLocal, Attribution: peerKind},
		"wp_login_bruteforce": {Block: BlockAlways, ChallengeFirst: true, Evidence: admission.FamilyHTTP, Basis: admission.BasisLocal, Attribution: httpKinds},
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

// The form relay client finding names a browser client that submitted a
// web form: it is challenged first and blocked when the challenge is off.
// The script and table findings name no client and must never aim a
// response, and the observe mode client finding only reports.
func TestFormRelayResponsePolicy(t *testing.T) {
	for _, name := range []string{"email_php_form_relay", "email_php_form_relay_observed", "email_php_form_relay_script", "email_php_form_relay_table_full"} {
		if _, ok := LookupCheck(name); !ok {
			t.Fatalf("%s is not registered", name)
		}
	}
	if !isChallengeableCheck("email_php_form_relay") {
		t.Error("email_php_form_relay is not challenge-first")
	}
	if !blockableCheck("email_php_form_relay", false) {
		t.Error("email_php_form_relay cannot block")
	}
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	if got := responseActionForCheck(cfg, "email_php_form_relay"); got != responseChallenge {
		t.Errorf("challenge on: action = %q, want %q", got, responseChallenge)
	}
	cfg.Challenge.Enabled = false
	if got := responseActionForCheck(cfg, "email_php_form_relay"); got != responseBlock {
		t.Errorf("challenge off: action = %q, want %q", got, responseBlock)
	}
	for _, name := range []string{"email_php_form_relay_observed", "email_php_form_relay_script", "email_php_form_relay_table_full"} {
		if p := ResponsePolicyFor(name); p != (ResponsePolicy{}) {
			t.Errorf("%s policy = %+v, want the zero policy", name, p)
		}
		if isChallengeableCheck(name) || blockableCheck(name, true) {
			t.Errorf("%s can challenge or block", name)
		}
	}
}

func TestChallengeRouteIPs_FormRelayFinding(t *testing.T) {
	list := &mockIPList{ips: make(map[string]bool)}
	old := GetChallengeIPList()
	SetChallengeIPList(list)
	t.Cleanup(func() { SetChallengeIPList(old) })

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.EmailProtection.PHPRelay.IPRecipientMode = "enforce"
	actions := ChallengeRouteIPs(cfg, []alert.Finding{{
		Check: "email_php_form_relay", Severity: alert.High, SourceIP: "203.0.113.9", CPUser: "alice",
		Message: "Path 6: client 203.0.113.9 made hosted sites mail 5 different outside addresses in 24h0m0s",
	}})
	if len(actions) != 1 || actions[0].Check != "challenge_route" {
		t.Fatalf("actions = %+v, want one challenge_route", actions)
	}
	if len(list.ips) != 1 || !list.ips["203.0.113.9"] {
		t.Fatalf("challenge list = %v, want only 203.0.113.9", list.ips)
	}
}

// The script finding's message embeds the request path, which the client
// controls through PATH_INFO, and address extraction falls back to message
// text when a finding has no SourceIP. Its zero policy is what keeps a
// crafted path from aiming a challenge or block at a third party.
func TestFormRelayScriptFindingAimsNoResponse(t *testing.T) {
	const victim = "198.51.100.7"
	oldList, oldBlocker := GetChallengeIPList(), getIPBlocker()
	t.Cleanup(func() {
		SetChallengeIPList(oldList)
		SetIPBlocker(oldBlocker)
	})
	for _, challenge := range []bool{true, false} {
		cfg := &config.Config{}
		cfg.StatePath = t.TempDir()
		cfg.AutoResponse.Enabled = true
		cfg.AutoResponse.BlockIPs = true
		setAutoResponseLive(cfg)
		cfg.Challenge.Enabled = challenge
		cfg.EmailProtection.PHPRelay.IPRecipientMode = "enforce"

		list := &mockIPList{ips: make(map[string]bool)}
		SetChallengeIPList(list)
		blocker := &recordingIPBlocker{}
		SetIPBlocker(blocker)

		challenged, blocked := ChallengeThenBlock(cfg, []alert.Finding{
			{Check: "email_php_form_relay_script", Severity: alert.High, CPUser: "alice",
				Message: "Bots use shop.example/contact.php/x: " + victim},
			{Check: "email_php_form_relay_script", Severity: alert.High, CPUser: "alice",
				Message: "Bots use shop.example/contact.php/ from " + victim + " to mail outside addresses"},
			{Check: "email_php_form_relay_table_full", Severity: alert.Warning, Message: "table full: " + victim},
			// The client finding in the same batch proves the harness responds.
			{Check: "email_php_form_relay", Severity: alert.High, SourceIP: "203.0.113.9", CPUser: "alice",
				Message: "Path 6: client 203.0.113.9 made hosted sites mail 5 different outside addresses in 24h0m0s"},
		})

		if list.ips[victim] || slices.Contains(blocker.blocked, victim) {
			t.Errorf("challenge=%v: %s reached a response: challenged %v, blocked %v", challenge, victim, list.ips, blocker.blocked)
		}
		for _, a := range append(challenged, blocked...) {
			if strings.Contains(a.Message, victim) {
				t.Errorf("challenge=%v: action names %s: %s", challenge, victim, a.Message)
			}
		}
		if challenge && (len(list.ips) != 1 || !list.ips["203.0.113.9"] || len(blocker.blocked) != 0) {
			t.Errorf("challenge on: challenged %v, blocked %v, want only 203.0.113.9 challenged", list.ips, blocker.blocked)
		}
		if !challenge && !slices.Equal(blocker.blocked, []string{"203.0.113.9"}) {
			t.Errorf("challenge off: blocked %v, want [203.0.113.9]", blocker.blocked)
		}
	}
}
