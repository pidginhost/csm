package daemon

import "testing"

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
