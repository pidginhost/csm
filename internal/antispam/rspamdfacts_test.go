package antispam

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRspamdVersion(t *testing.T) {
	for out, want := range map[string]string{
		"Rspamd daemon version 4.2.1\n\nCPU architecture x86_64; features: avx2\n": "4.2.1",
		"Rspamadm 4.2.1\n":            "4.2.1",
		"Rspamd daemon version 3.8\n": "3.8",
	} {
		v, _, err := ParseRspamdVersion(out)
		if err != nil || v != want {
			t.Errorf("ParseRspamdVersion(%q) = %q, %v; want %q", out, v, err, want)
		}
	}
	if _, major, _ := ParseRspamdVersion("Rspamd daemon version 2.7\n"); major != 2 {
		t.Errorf("major = %d, want 2", major)
	}
	if _, _, err := ParseRspamdVersion("bash: rspamd: command not found\n"); err == nil {
		t.Error("missing version accepted")
	}
}

func TestParseRspamdVersionRejectsMalformedVersions(t *testing.T) {
	for _, version := range []string{"4.12345", "4.2.12345", "4.2.", "4.2.x", "4.2.1.3", "4.2oops"} {
		t.Run(version, func(t *testing.T) {
			if got, major, err := ParseRspamdVersion("Rspamd daemon version " + version + "\n"); err == nil || got != "" || major != 0 {
				t.Fatalf("got %q, %d, %v; want empty version and error", got, major, err)
			}
		})
	}
}

func TestParseRspamdVersionWithReleaseSuffix(t *testing.T) {
	got, major, err := ParseRspamdVersion("Rspamadm 4.2.1-git\n")
	if err != nil || got != "4.2.1" || major != 4 {
		t.Fatalf("got %q, %d, %v; want 4.2.1, 4, nil", got, major, err)
	}
}

// modulesState is `rspamadm configdump -m` from rspamd 4.2.1 with CSM's files.
const modulesState = `Modules enabled: bayes_expiry, multimap, whitelist, milter_headers, dkim, spf, asn, dmarc, phishing, arc, chartable
Modules disabled (explicitly): bimi, greylist, rbl, fuzzy_check, gpt
Modules disabled (unconfigured): reputation, emails, clickhouse
Modules disabled (no Redis): history_redis, neural, ratelimit
`

func TestEnabledModules(t *testing.T) {
	set, err := EnabledModules(modulesState)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"bayes_expiry": true, "multimap": true, "whitelist": true, "milter_headers": true,
		"dkim": true, "spf": true, "asn": true, "dmarc": true,
		"phishing": true, "arc": true, "chartable": true,
	}
	if !reflect.DeepEqual(set, want) {
		t.Errorf("enabled set = %v, want %v", set, want)
	}
	if _, err := EnabledModules("Modules disabled (explicitly): rbl\n"); err == nil {
		t.Error("output without enabled line accepted")
	}
}

func TestParseActions(t *testing.T) {
	a, err := ParseActions([]byte(`{"reject": 15, "add_header": 6, "greylist": null, "rewrite_subject": null, "subject": "***SPAM*** %s"}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Reject == nil || *a.Reject != 15 || a.AddHeader == nil || *a.AddHeader != 6 || a.Greylist != nil || a.RewriteSubject != nil {
		t.Fatalf("got %+v", a)
	}
	for _, bad := range []string{`not json`, `{"reject": "high"}`, `[1,2]`} {
		if _, err := ParseActions([]byte(bad)); err == nil {
			t.Errorf("ParseActions(%s) = nil error", bad)
		}
	}
}

func TestParseActionsCanonicalNames(t *testing.T) {
	a, err := ParseActions([]byte(`{"reject":15,"add header":6,"greylist":null,"rewrite subject":8}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Reject == nil || *a.Reject != 15 || a.AddHeader == nil || *a.AddHeader != 6 || a.Greylist != nil || a.RewriteSubject == nil || *a.RewriteSubject != 8 {
		t.Fatalf("got %+v; want reject 15, add header 6, disabled greylist and rewrite subject 8", a)
	}
	if got, want := CheckRspamd(nil, a, defaults(false)), []string{"rspamd rewrite_subject action is enabled"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CheckRspamd = %v, want %v", got, want)
	}
}

func TestParseActionsPreservesZeroAndFractionalScores(t *testing.T) {
	a, err := ParseActions([]byte(`{"reject":20.5,"add_header":0,"greylist":0,"rewrite subject":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Reject == nil || *a.Reject != 20.5 || a.AddHeader == nil || *a.AddHeader != 0 || a.Greylist == nil || *a.Greylist != 0 || a.RewriteSubject != nil {
		t.Fatalf("got %+v; want reject 20.5, add header 0, greylist 0 and disabled rewrite subject", a)
	}
	got := CheckRspamd(nil, a, defaults(false))
	want := []string{
		"rspamd reject threshold is 20.5, want 15",
		"rspamd add_header threshold is 0, want 6",
		"rspamd greylist action is enabled",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CheckRspamd = %v, want %v", got, want)
	}
}

func TestParseActionsRejectsAmbiguousAliases(t *testing.T) {
	for _, out := range []string{
		`{"reject":15,"add_header":6,"add header":10}`,
		`{"reject":15,"add_header":6,"rewrite_subject":null,"rewrite subject":8}`,
		`{"reject":15,"add_header":6,"rewrite_subject":8,"rewrite subject":null}`,
	} {
		if a, err := ParseActions([]byte(out)); err == nil || a != (Actions{}) {
			t.Errorf("ParseActions(%s) = %+v, %v; want empty actions and error", out, a, err)
		}
	}
}

func TestParseActionsAcceptsEquivalentAliases(t *testing.T) {
	a, err := ParseActions([]byte(`{"reject":15,"add_header":6,"add header":6.0,"rewrite_subject":null,"rewrite subject":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Reject == nil || *a.Reject != 15 || a.AddHeader == nil || *a.AddHeader != 6 || a.Greylist != nil || a.RewriteSubject != nil {
		t.Fatalf("got %+v; want reject 15, add header 6 and disabled greylist and rewrite subject", a)
	}
	if got := CheckRspamd(nil, a, defaults(false)); len(got) != 0 {
		t.Fatalf("equivalent aliases reported conflicts: %v", got)
	}
}

func TestParseActionsRejectsNullSection(t *testing.T) {
	if a, err := ParseActions([]byte("null")); err == nil || a != (Actions{}) {
		t.Fatalf("got %+v, %v; want empty actions and error", a, err)
	}
}

func TestCheckRspamd(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	s := defaults(false)
	enabled, err := EnabledModules(modulesState)
	if err != nil {
		t.Fatal(err)
	}
	got := CheckRspamd(enabled, Actions{Reject: f(15), AddHeader: f(6)}, s)
	if len(got) != 1 || !strings.Contains(got[0], "asn") {
		t.Fatalf("got %v, want only the asn conflict", got)
	}
	delete(enabled, "asn")
	got = CheckRspamd(enabled, Actions{Reject: f(15), AddHeader: f(6)}, s)
	if len(got) != 0 {
		t.Errorf("clean state reported %v", got)
	}
	got = CheckRspamd(enabled, Actions{Reject: f(20), Greylist: f(4), RewriteSubject: f(8)}, s)
	want := []string{
		"rspamd reject threshold is 20, want 15",
		"rspamd add_header threshold is disabled, want 6",
		"rspamd greylist action is enabled",
		"rspamd rewrite_subject action is enabled",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCheckRspamdDetectsAllDisabledModules(t *testing.T) {
	s := defaults(false)
	s.RejectScore, s.TagScore = 20, 8
	reject, tag := float64(20), float64(8)
	enabled := map[string]bool{"asn": true, "emails": true, "fuzzy_check": true, "greylist": true, "rbl": true, "dkim": true}
	got := CheckRspamd(enabled, Actions{Reject: &reject, AddHeader: &tag}, s)
	want := []string{
		"rspamd module asn is enabled; an override defeats CSM's asn.conf",
		"rspamd module emails is enabled; an override defeats CSM's emails.conf",
		"rspamd module fuzzy_check is enabled; an override defeats CSM's fuzzy_check.conf",
		"rspamd module greylist is enabled; an override defeats CSM's greylist.conf",
		"rspamd module rbl is enabled; an override defeats CSM's rbl.conf",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CheckRspamd = %v, want %v", got, want)
	}
}
