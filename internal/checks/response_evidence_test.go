package checks

import (
	"sort"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// evidencePolicy is the reviewed evidence family and basis of every check
// that can drive an automatic response. A check absent here has
// FamilyNone. Change it only with a reviewed policy decision.
var evidencePolicy = map[string]admission.Policy{
	"admin_panel_bruteforce":      {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"http_asn_crawl":              {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"http_claimed_bot_unverified": {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"http_request_flood":          {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"http_scanner_profile":        {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"http_ua_spoof":               {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"modsec_block_escalation":     {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"modsec_csm_block_escalation": {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"waf_attack_blocked":          {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"wp_login_bruteforce":         {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"wp_user_enumeration":         {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"xmlrpc_abuse":                {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"api_auth_failure":            {Family: admission.FamilyPanel, Basis: admission.BasisLocal},
	"api_auth_failure_realtime":   {Family: admission.FamilyPanel, Basis: admission.BasisLocal},
	"cpanel_multi_ip_login":       {Family: admission.FamilyPanel, Basis: admission.BasisLocal},
	"webmail_bruteforce":          {Family: admission.FamilyPanel, Basis: admission.BasisLocal},
	"email_cloud_relay_abuse":     {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"email_compromised_account":   {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"mail_bruteforce":             {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"mail_subnet_spray":           {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"smtp_bruteforce":             {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"smtp_probe_abuse":            {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"smtp_subnet_spray":           {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"credential_stuffing":         {Family: admission.FamilySSH, Basis: admission.BasisLocal},
	"pam_bruteforce":              {Family: admission.FamilySSH, Basis: admission.BasisLocal},
	"ssh_login_unknown_ip":        {Family: admission.FamilySSH, Basis: admission.BasisLocal},
	"ftp_auth_failure_realtime":   {Family: admission.FamilyFTP, Basis: admission.BasisLocal},
	"ftp_bruteforce":              {Family: admission.FamilyFTP, Basis: admission.BasisLocal},
	"ip_reputation":               {Family: admission.FamilyReputation, Basis: admission.BasisIntel},
	"local_threat_score":          {Family: admission.FamilyDerived, Basis: admission.BasisIntel},
	"c2_connection":               {Family: admission.FamilyNetwork, Basis: admission.BasisCompromise},
	"mail_account_compromised":    {Family: admission.FamilyMail, Basis: admission.BasisCompromise},
}

// reviewedCompromise is every check whose own evidence is C3. Each is
// direct evidence of successful unauthorized access or a compromised host,
// not a Critical label or an ordinary successful login.
var reviewedCompromise = map[string]string{
	"c2_connection":            "a local process holds a connection to a listed command-and-control address",
	"mail_account_compromised": "a login succeeded from the address after its brute force (Critical only)",
}

func TestRegistryEvidenceMatchesReviewedTable(t *testing.T) {
	for _, c := range checkRegistry {
		want := evidencePolicy[c.Name]
		if got := (admission.Policy{Family: c.Response.Evidence, Basis: c.Response.Basis}); got != want {
			t.Errorf("%q evidence = %s/%s, want %s/%s", c.Name, got.Family, got.Basis, want.Family, want.Basis)
		}
	}
	for name := range evidencePolicy {
		if _, ok := LookupCheck(name); !ok {
			t.Errorf("evidencePolicy lists unregistered check %q", name)
		}
	}
}

func TestReviewedCompromiseChecksAreExact(t *testing.T) {
	for _, c := range checkRegistry {
		_, reviewed := reviewedCompromise[c.Name]
		if (c.Response.Basis == admission.BasisCompromise) != reviewed {
			t.Errorf("%q has basis %s; reviewed compromise list says %v", c.Name, c.Response.Basis, reviewed)
		}
	}
	for name, reason := range reviewedCompromise {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("reviewed compromise check %q has no reason", name)
		}
	}
}

func TestValidateResponsePolicyRejectsEvidenceContradictions(t *testing.T) {
	cases := map[string]CheckInfo{
		"block without evidence":     {Name: "x_check", Response: ResponsePolicy{Block: BlockAlways}},
		"challenge without evidence": {Name: "x_check", Response: ResponsePolicy{ChallengeFirst: true}},
		"family without basis":       {Name: "x_check", Response: ResponsePolicy{Evidence: admission.FamilySSH}},
		"intel on a local family":    {Name: "x_check", Response: ResponsePolicy{Block: BlockAlways, Evidence: admission.FamilySSH, Basis: admission.BasisIntel}},
		"compromise from derived":    {Name: "x_check", Response: ResponsePolicy{Block: BlockAlways, Evidence: admission.FamilyDerived, Basis: admission.BasisCompromise}},
	}
	for name, entry := range cases {
		if err := validateResponsePolicy([]CheckInfo{entry}); err == nil {
			t.Errorf("%s: accepted %+v", name, entry.Response)
		}
	}
	ok := CheckInfo{Name: "x_check", Response: ResponsePolicy{Evidence: admission.FamilyMail, Basis: admission.BasisLocal}}
	if err := validateResponsePolicy([]CheckInfo{ok}); err != nil {
		t.Errorf("evidence without a response policy refused: %v", err)
	}
}

func TestAdmissionPolicyLookup(t *testing.T) {
	cases := []struct {
		in, canonical string
		want          admission.Policy
		ok            bool
	}{
		{"ssh_login_realtime", "ssh_login_unknown_ip", admission.Policy{Family: admission.FamilySSH, Basis: admission.BasisLocal}, true},
		{"ip_reputation", "ip_reputation", admission.Policy{Family: admission.FamilyReputation, Basis: admission.BasisIntel}, true},
		{"cpanel_login", "cpanel_login", admission.Policy{}, true},
		{"not_a_check", "", admission.Policy{}, false},
		{"", "", admission.Policy{}, false},
	}
	for _, tc := range cases {
		name, p, ok := AdmissionPolicy(tc.in)
		if name != tc.canonical || p != tc.want || ok != tc.ok {
			t.Errorf("AdmissionPolicy(%q) = %q %+v %v, want %q %+v %v", tc.in, name, p, ok, tc.canonical, tc.want, tc.ok)
		}
	}
}

// The production lookup must drive the admission registry: every
// classified check can be registered, nothing else can.
func TestAdmissionRegistryAcceptsEveryClassifiedCheck(t *testing.T) {
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	byFamily := map[admission.Family][]string{}
	for name, p := range evidencePolicy {
		byFamily[p.Family] = append(byFamily[p.Family], name)
	}
	for fam, names := range byFamily {
		sort.Strings(names)
		spec := admission.ProducerSpec{ID: admission.ProducerID("fixture_" + fam.String()), Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: names}
		if _, err := reg.Register(spec); err != nil {
			t.Errorf("family %s: %v", fam, err)
		}
	}
	if _, err := reg.Register(admission.ProducerSpec{ID: "fixture_none", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: []string{"cpanel_login"}}); err == nil {
		t.Error("a check without evidence registered")
	}
}
