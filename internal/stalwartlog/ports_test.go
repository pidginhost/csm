package stalwartlog

import (
	"strings"
	"testing"
)

func TestParsePortsDefaultsAndOverrides(t *testing.T) {
	def, err := ParsePorts(nil)
	if err != nil {
		t.Fatal(err)
	}
	for port, want := range map[uint16]Protocol{
		25: ProtoSMTP, 465: ProtoSMTP, 587: ProtoSMTP,
		143: ProtoIMAP, 993: ProtoIMAP,
		110: ProtoPOP3, 995: ProtoPOP3,
		4190: ProtoSieve,
		80:   ProtoHTTP, 443: ProtoHTTP, 8080: ProtoHTTP,
		10465: ProtoUnknown,
	} {
		if got := def.Of(port); got != want {
			t.Errorf("default Of(%d) = %q, want %q", port, got, want)
		}
	}
	p, err := ParsePorts([]string{"10465:smtp", "8080:imap"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Of(10465) != ProtoSMTP || p.Of(8080) != ProtoIMAP || p.Of(993) != ProtoIMAP {
		t.Fatalf("overrides not applied: 10465=%q 8080=%q 993=%q", p.Of(10465), p.Of(8080), p.Of(993))
	}
	for _, bad := range []string{"x:smtp", "25:ftp", "70000:smtp", "25", "0:smtp", ":smtp"} {
		_, err := ParsePorts([]string{bad})
		if err == nil || !strings.Contains(err.Error(), bad) {
			t.Errorf("ParsePorts(%q) error = %v, want one naming the entry", bad, err)
		}
	}
}

func TestParsePortsDoesNotShareDefaults(t *testing.T) {
	if _, err := ParsePorts([]string{"25:http"}); err != nil {
		t.Fatal(err)
	}
	p, _ := ParsePorts(nil)
	if p.Of(25) != ProtoSMTP {
		t.Fatal("an override leaked into the defaults")
	}
}
