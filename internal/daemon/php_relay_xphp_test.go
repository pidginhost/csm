package daemon

import (
	"fmt"
	"testing"
	"time"
)

func TestParseXPHPScript_SingleIP(t *testing.T) {
	k, ip := parseXPHPScript("site-a.example/wp-admin/admin-ajax.php for 203.0.113.9")
	if k != "site-a.example:/wp-admin/admin-ajax.php" || ip != "203.0.113.9" {
		t.Fatalf("got %q %q", k, ip)
	}
}

func TestParseXPHPScript_ListTakesServerObservedAddress(t *testing.T) {
	_, ip := parseXPHPScript("site-a.example/index.php for 198.51.100.77, 203.0.113.9")
	if ip != "203.0.113.9" {
		t.Fatalf("ip = %q, want the server-observed element", ip)
	}
}

func TestParseXPHPScript_ForgedForwardedForCannotChangeIP(t *testing.T) {
	for _, forged := range []string{"192.0.2.1", "192.0.2.1, 192.0.2.2", "not-an-ip"} {
		_, ip := parseXPHPScript("site-a.example/index.php for " + forged + ", 203.0.113.9")
		if ip != "203.0.113.9" {
			t.Fatalf("forged %q moved ip to %q", forged, ip)
		}
	}
}

func TestParseXPHPScript_IPv6Canonical(t *testing.T) {
	_, ip := parseXPHPScript("site-a.example/index.php for 2001:DB8::1, 2001:db8:0:0::1")
	if ip != "2001:db8::1" {
		t.Fatalf("ip = %q", ip)
	}
}

func TestParseXPHPScript_GarbageYieldsNoIP(t *testing.T) {
	for _, v := range []string{"site-a.example/x.php for unknown", "site-a.example/x.php for ::1%eth0",
		"site-a.example/x.php for 203.0.113.9,", "site-a.example/x.php for ", "site-a.example/x.php"} {
		if _, ip := parseXPHPScript(v); ip != "" {
			t.Fatalf("%q gave ip %q", v, ip)
		}
	}
}

func TestParseXPHPScript_ForwardedTextCannotChangeScript(t *testing.T) {
	for _, forwarded := range []string{
		"192.0.2.1 for 198.51.100.1",
		"arbitrary text for another script",
		"192.0.2.1, for , for ",
		" for 198.51.100.1?query=/other.php",
	} {
		t.Run(forwarded, func(t *testing.T) {
			key, ip := parseXPHPScript("site-a.example/index.php for " + forwarded + ", 203.0.113.9")
			if key != "site-a.example:/index.php" || ip != "203.0.113.9" {
				t.Fatalf("forwarded text changed attribution: key=%q ip=%q", key, ip)
			}
		})
	}
}

func TestParseXPHPScript_PathInfoCannotChangeIP(t *testing.T) {
	for _, path := range []string{
		"/index.php/extra,path",
		"/index.php/ for 192.0.2.1",
		"/index.php/ for 192.0.2.1, 198.51.100.1",
		"/index.php/ for ,192.0.2.1/ for 198.51.100.1",
	} {
		for _, forwarded := range []string{"", "192.0.2.2, ", "text for 192.0.2.2, ", " for , , "} {
			for _, remote := range []string{"203.0.113.9", "2001:db8::9"} {
				v := "site-a.example" + path + " for " + forwarded + remote
				if _, ip := parseXPHPScript(v); ip != remote {
					t.Errorf("%q gave IP %q, want %q", v, ip, remote)
				}
			}
		}
	}
}

func TestParseXPHPScript_InvalidRemoteNeverUsesForwardedIP(t *testing.T) {
	for _, remote := range []string{"", "unknown", "203.0.113.9:80", "[2001:db8::9]", "2001:db8::9%eth0"} {
		v := "site-a.example/index.php for 192.0.2.1 for 198.51.100.1, " + remote
		key, ip := parseXPHPScript(v)
		if key != "site-a.example:/index.php" || ip != "" {
			t.Errorf("%q gave key=%q ip=%q", v, key, ip)
		}
	}
}

// Varying only a forwarding header must neither invent fanout nor split the
// per-script volume that drives queue freezes.
func TestPHPRelay_ForwardedTextKeepsOneScript(t *testing.T) {
	p, findings := fanoutPipeline(t, "a")
	now := time.Unix(1_700_000_000, 0).UTC()
	count := p.eng.config().EmailProtection.PHPRelay.AbsoluteVolumePerHour
	const source = "203.0.113.9"
	const key = "site-a.example:/wp-comments-post.php"
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("1abc23-000456-%02d", i)
		forwarded := fmt.Sprintf("request-%d for 192.0.2.1, %s", i, source)
		feedSiteMail(t, p, id, "a", forwarded, now, fmt.Sprintf("recipient%d@outside.example", i))
	}
	if got := p.eng.ips.distinctScriptsSince(source, now); got != 1 {
		t.Errorf("one script counted as %d scripts", got)
	}
	if len(*findings) != 1 {
		t.Fatalf("findings = %+v, want one volume finding", *findings)
	}
	f := (*findings)[0]
	if f.Path != "volume" || f.ScriptKey != key || f.SourceIP != source || f.RelayTotal != count {
		t.Fatalf("unexpected volume finding: %+v", f)
	}
	ids, capped := p.eng.scripts.getOrCreate(key).snapshotActiveMsgs()
	if len(ids) != count || capped {
		t.Fatalf("freeze candidates = %d, capped=%v, want %d", len(ids), capped, count)
	}
}
