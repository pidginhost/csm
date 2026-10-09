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
	if !set["asn"] || !set["dkim"] || set["rbl"] || set["emails"] || len(set) != 11 {
		t.Errorf("enabled set = %v", set)
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

func TestCheckRspamd(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	s := defaults(false)
	enabled, _ := EnabledModules(modulesState)
	got := CheckRspamd(enabled, Actions{Reject: f(15), AddHeader: f(6)}, s)
	if len(got) != 1 || !strings.Contains(got[0], "asn") {
		t.Fatalf("got %v, want only the asn conflict", got)
	}
	delete(enabled, "asn")
	if got := CheckRspamd(enabled, Actions{Reject: f(15), AddHeader: f(6)}, s); len(got) != 0 {
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
