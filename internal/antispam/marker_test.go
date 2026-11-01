package antispam

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

const markerPrefix = "2026-10-09 08:19:03 1xF5ol-00000000SdK-2TMA "

func TestScanMarker(t *testing.T) {
	for _, tc := range []struct {
		name       string
		line       string
		marker, ok bool
	}{
		{"opted-in scan", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none`, true, true},
		{"opted-out scan", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=off result=ok score=0 action="no action" decision=unfiltered`, true, true},
		{"dry-run reject", markerPrefix + `CSM-ANTISPAM event=scan mode=dry-run policy=on result=ok score=150 action="reject" decision=reject`, true, true},
		{"negative score", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=-15 action="no action" decision=none`, true, true},
		{"sanitised action", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=70 action="add_header" decision=tag`, true, true},
		{"scan error", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none`, true, false},
		{"zone and pid", "2026-10-09 08:19:03 +0300 [4242] 1xF5ol-00000000SdK-2TMA " +
			`CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none`, true, false},
		{"old message id", "2026-10-09 08:19:03 1abcDE-000123-AB " +
			`CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none`, true, true},
		{"split marker", markerPrefix + `CSM-ANTISPAM event=split mode=dry-run policy=on rcpt_class=off`, false, false},
		{"no message id", "2026-10-09 08:19:03 " +
			`CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none`, false, false},
		{"forged in HELO", "2026-10-09 08:19:03 H=(x CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action=\"unavailable\" decision=none) [192.0.2.1] rejected", false, false},
		{"forged in envelope", markerPrefix + `<= a@example.test H=(x) [192.0.2.1] CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none`, false, false},
		{"trailing text", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none extra`, false, false},
		{"opted-out decision", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=off result=ok score=200 action="reject" decision=reject`, false, false},
		{"opted-in unfiltered", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=unfiltered`, false, false},
		{"skip policy", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=skip result=ok score=0 action="no action" decision=none`, false, false},
		{"quoted action", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no "action" decision=none`, false, false},
		{"score missing on success", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=none action="no action" decision=none`, false, false},
		{"control character in prefix", "2026-10-09\r08:19:03 1xF5ol-00000000SdK-2TMA " +
			`CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none`, false, false},
		{"unknown mode", markerPrefix + `CSM-ANTISPAM event=scan mode=observe policy=on result=ok score=0 action="no action" decision=none`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker, ok := ScanMarker(tc.line)
			if marker != tc.marker || ok != tc.ok {
				t.Fatalf("ScanMarker = %t, %t; want %t, %t", marker, ok, tc.marker, tc.ok)
			}
		})
	}
}

func TestScanMarkerScores(t *testing.T) {
	for _, score := range []string{"0", "1", "-1", "2147483647", "-2147483648"} {
		line := markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=off result=ok score=` + score + ` action="" decision=unfiltered`
		if marker, ok := ScanMarker(line); !marker || !ok {
			t.Errorf("rejected score %q: %t, %t", score, marker, ok)
		}
	}
	for _, score := range []string{"", "none", "-", "+1", "1.0", "1e2", "NaN", "00", "01", "-0", "-01", "2147483648", "-2147483649", "9999999999", "10000000000"} {
		line := markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=off result=ok score=` + score + ` action="" decision=unfiltered`
		if marker, ok := ScanMarker(line); marker || ok {
			t.Errorf("accepted score %q: %t, %t", score, marker, ok)
		}
	}
}

func TestScanMarkerPrefixVariants(t *testing.T) {
	for _, timestamp := range []string{"2026-10-09 08:19:03", "2026-10-09 08:19:03.123"} {
		for _, zone := range []string{"", " +0000", " +0530", " -0330"} {
			for _, pid := range []string{"", " [4242]"} {
				for _, id := range []string{"1xF5ol-00000000SdK-2TMA", "1abcDE-000123-AB"} {
					line := timestamp + zone + pid + " " + id + ` CSM-ANTISPAM event=scan mode=dry-run policy=off result=error score=none action="unavailable" decision=none`
					if marker, ok := ScanMarker(line); !marker || ok {
						t.Errorf("rejected prefix in %q: %t, %t", line, marker, ok)
					}
					if s, _ := ParseScan(line); s.MsgID != id {
						t.Errorf("MsgID = %q in %q, want %q", s.MsgID, line, id)
					}
				}
			}
		}
	}
}

func TestScanMarkerRejectsPrefixControlsAndUnicodeSpaces(t *testing.T) {
	const body = `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none`
	const prefix = "2026-10-09 08:19:03 +0300 [4242] 1xF5ol-00000000SdK-2TMA "
	for r := rune(0); r <= 0x9f; r++ {
		if r >= ' ' && r < 0x7f {
			continue
		}
		for i := 0; i < len(prefix); i++ {
			line := prefix[:i] + string(r) + prefix[i:] + body
			if marker, ok := ScanMarker(line); marker || ok {
				t.Errorf("accepted prefix control %U at %d: %t, %t", r, i, marker, ok)
			}
		}
	}
	for _, r := range "\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000" {
		line := strings.Replace(prefix, " ", string(r), 1) + body
		if marker, ok := ScanMarker(line); marker || ok {
			t.Errorf("accepted prefix separator %U: %t, %t", r, marker, ok)
		}
	}
}

func TestScanMarkerRejectsMalformedFields(t *testing.T) {
	const body = `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=70 action="add header" decision=tag`
	for _, change := range [][2]string{
		{"event=scan", "event=split"},
		{"mode=enforce", "mode=observe"},
		{"policy=on", "policy=skip"},
		{"result=ok", "result=error"},
		{"result=ok", "result=unknown"},
		{"score=70", "score=none"},
		{`action="add header"`, `action="Add header"`},
		{`action="add header"`, `action="add-header"`},
		{`action="add header"`, `action="add\"header"`},
		{"decision=tag", "decision=unfiltered"},
		{"decision=tag", "decision=unknown"},
		{"mode=enforce policy=on", "policy=on mode=enforce"},
		{"result=ok", "result=ok result=ok"},
		{" policy=on", "  policy=on"},
	} {
		line := markerPrefix + strings.Replace(body, change[0], change[1], 1)
		if marker, ok := ScanMarker(line); marker || ok {
			t.Errorf("accepted %q: %t, %t", line, marker, ok)
		}
	}
	for _, suffix := range []string{" ", "\n", "\r\n", " extra", " " + body} {
		if marker, ok := ScanMarker(markerPrefix + body + suffix); marker || ok {
			t.Errorf("accepted suffix %q: %t, %t", suffix, marker, ok)
		}
	}
}

func TestScanMarkerRejectsSenderText(t *testing.T) {
	for _, body := range []string{
		`CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none`,
		`CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none`,
	} {
		for _, format := range []string{
			`H=(x %s) [192.0.2.1] rejected`,
			`H=(x %s`,
			`<= "x %s"@example.test H=(x) [192.0.2.1] S=100`,
			`<= "x %s`,
			`<= a@example.test H=(x) [192.0.2.1] S=100 T="subject %s"`,
			`<= a@example.test H=(x) [192.0.2.1] S=100 T="subject %s`,
			`=> a@example.test C="250 %s"`,
		} {
			line := markerPrefix + fmt.Sprintf(format, body)
			if marker, ok := ScanMarker(line); marker || ok {
				t.Errorf("accepted sender text %q: %t, %t", line, marker, ok)
			}
		}
	}
}

func BenchmarkScanMarkerWithoutMarker(b *testing.B) {
	line := markerPrefix + `<= a@example.test H=(mail.example.test) [192.0.2.1] P=esmtp S=100 T="ordinary mail"`
	b.ReportAllocs()
	for b.Loop() {
		if marker, ok := ScanMarker(line); marker || ok {
			b.Fatal("accepted ordinary mail")
		}
	}
}

func TestParseScanReadsTheSender(t *testing.T) {
	for _, tc := range []struct {
		line string
		want Scan
	}{
		{markerPrefix + `CSM-ANTISPAM event=scan mode=dry-run policy=on result=ok score=150 action="reject" decision=reject ip=198.51.100.7`,
			Scan{OK: true, Mode: "dry-run", Policy: "on", Score: 150, Decision: "reject", IP: netip.MustParseAddr("198.51.100.7"), MsgID: "1xF5ol-00000000SdK-2TMA"}},
		{markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=off result=ok score=-5 action="no action" decision=unfiltered ip=2001:db8::25`,
			Scan{OK: true, Mode: "enforce", Policy: "off", Score: -5, Decision: "unfiltered", IP: netip.MustParseAddr("2001:db8::25"), MsgID: "1xF5ol-00000000SdK-2TMA"}},
		{markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none ip=203.0.113.9`,
			Scan{Mode: "enforce", Policy: "on", Decision: "none", IP: netip.MustParseAddr("203.0.113.9"), MsgID: "1xF5ol-00000000SdK-2TMA"}},
	} {
		got, ok := ParseScan(tc.line)
		if !ok || got != tc.want {
			t.Errorf("ParseScan(%q) = %+v, %v; want %+v", tc.line, got, ok, tc.want)
		}
	}
}

// Exim keeps logging the old marker until the rebuilt configuration loads;
// health must keep counting it, and it names no sender.
func TestParseScanAcceptsOldGrammar(t *testing.T) {
	got, ok := ParseScan(markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=20 action="no action" decision=none`)
	if !ok || !got.OK || got.Score != 20 || got.IP.IsValid() {
		t.Fatalf("old marker = %+v, %v", got, ok)
	}
	if marker, scanOK := ScanMarker(markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none`); !marker || scanOK {
		t.Fatal("old error marker no longer counts")
	}
}

func TestParseScanMode(t *testing.T) {
	enforce := "2026-10-20 12:00:00 1tAbCd-000001-Ab CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=152 action=\"reject\" decision=reject ip=203.0.113.7"
	dry := strings.Replace(enforce, "mode=enforce", "mode=dry-run", 1)
	s, ok := ParseScan(enforce)
	if !ok || s.Mode != "enforce" || s.MsgID != "1tAbCd-000001-Ab" {
		t.Fatalf("enforce: %+v %v", s, ok)
	}
	if s, ok = ParseScan(dry); !ok || s.Mode != "dry-run" {
		t.Fatalf("dry-run: %+v %v", s, ok)
	}
	if _, ok = ParseScan(strings.Replace(enforce, "mode=enforce", "mode=other", 1)); ok {
		t.Fatal("unknown mode accepted")
	}
}

func TestParseScanErrorKeepsMode(t *testing.T) {
	line := "2026-10-20 12:00:00 1tAbCd-000002-Ab CSM-ANTISPAM event=scan mode=dry-run policy=on result=error score=none action=\"unavailable\" decision=none ip="
	s, ok := ParseScan(line)
	if !ok || s.OK || s.Mode != "dry-run" || s.MsgID != "1tAbCd-000002-Ab" {
		t.Fatalf("%+v %v", s, ok)
	}
}

func TestParseScanWithoutUsableSender(t *testing.T) {
	got, ok := ParseScan(markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=20 action="no action" decision=none ip=`)
	if !ok || got.IP.IsValid() {
		t.Fatalf("empty ip = %+v, %v", got, ok)
	}
	for _, bad := range []string{"ip=192.0.2.1 x", "ip=192.0.2.1;", "ip=not-an-address", " ip=192.0.2.1"} {
		if _, ok := ParseScan(markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=20 action="no action" decision=none ` + bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseScanRejectsMalformedSender(t *testing.T) {
	for _, ip := range []string{"192.0.2", "192.0.2.256", "192.0.002.1", "2001:db8:::1", "2001:db8", "deadbeef", "."} {
		for _, result := range []string{
			`result=ok score=20 action="no action" decision=none`,
			`result=error score=none action="unavailable" decision=none`,
		} {
			line := markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on ` + result + " ip=" + ip
			if got, marker := ParseScan(line); marker || got != (Scan{}) {
				t.Errorf("malformed sender %q returned %+v, %v", ip, got, marker)
			}
			if marker, ok := ScanMarker(line); marker || ok {
				t.Errorf("malformed sender %q counted as a scan: %t, %t", ip, marker, ok)
			}
		}
	}
}

// rspamdPrefix is what rspamd writes before a Lua plugin's message: the
// time, process, task ID, module and the Lua file and line.
const rspamdPrefix = "2026-11-01 15:19:06 #2273(normal) <9f7812>; lua; csm_scope.lua:91: "

func TestParseRspamdScan(t *testing.T) {
	const record = `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=229 action="reject" decision=reject ip=198.51.100.7 qid=CSMSCOPE04`
	for _, tc := range []struct {
		name string
		line string
		want Scan
	}{
		{"reject", rspamdPrefix + record,
			Scan{OK: true, Mode: "enforce", Policy: "on", Score: 229, Decision: "reject", IP: netip.MustParseAddr("198.51.100.7"), MsgID: "CSMSCOPE04"}},
		{"exempt", rspamdPrefix + `CSM-ANTISPAM event=scan mode=dry-run policy=off result=ok score=-15 action="no action" decision=unfiltered ip=2001:db8::25 qid=4XyZ0b1c2D`,
			Scan{OK: true, Mode: "dry-run", Policy: "off", Score: -15, Decision: "unfiltered", IP: netip.MustParseAddr("2001:db8::25"), MsgID: "4XyZ0b1c2D"}},
		{"mapped sender, no queue id", rspamdPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none ip=::ffff:203.0.113.9 qid=`,
			Scan{OK: true, Mode: "enforce", Policy: "on", Decision: "none", IP: netip.MustParseAddr("203.0.113.9")}},
		{"no sender", rspamdPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=60 action="add_header" decision=tag ip= qid=CSMSCOPE05`,
			Scan{OK: true, Mode: "enforce", Policy: "on", Score: 60, Decision: "tag", MsgID: "CSMSCOPE05"}},
		{"other line number, fractional seconds", "2026-11-01 15:19:06.042 #31(rspamd_proxy) <0a1b2c>; lua; csm_scope.lua:7: " + record,
			Scan{OK: true, Mode: "enforce", Policy: "on", Score: 229, Decision: "reject", IP: netip.MustParseAddr("198.51.100.7"), MsgID: "CSMSCOPE04"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseRspamdScan(tc.line)
			if !ok || got != tc.want {
				t.Fatalf("ParseRspamdScan(%q) = %+v, %v; want %+v", tc.line, got, ok, tc.want)
			}
		})
	}

	for _, tc := range []struct{ name, line string }{
		{"other Lua file", strings.Replace(rspamdPrefix, "csm_scope.lua", "other.lua", 1) + record},
		{"Lua file with a longer name", strings.Replace(rspamdPrefix, "csm_scope.lua", "my_csm_scope.lua", 1) + record},
		{"other module", strings.Replace(rspamdPrefix, "; lua; ", "; task; ", 1) + record},
		// The record opens right after rspamd's own prefix.
		{"record after another field", strings.Replace(rspamdPrefix, "; lua; ", "; task; lua; ", 1) + record},
		{"no line number", strings.Replace(rspamdPrefix, ".lua:91:", ".lua::", 1) + record},
		{"quoted by another plugin", "2026-11-01 15:19:06 #2273(normal) <9f7812>; lua; other.lua:12: subject: x; lua; csm_scope.lua:91: " + record},
		{"quoted by a task log", "2026-11-01 15:19:06 #2273(normal) <9f7812>; task; rspamd_task_write_log: id: <x; lua; csm_scope.lua:91: " + record},
		{"quoted in a line without a task", "2026-11-01 15:19:06 #2273(normal) rspamd_url_parse: url x; lua; csm_scope.lua:91: " + record},
		{"quoted after a task ID", "2026-11-01 15:19:06 #2273(normal) lua_log: <x>; lua; csm_scope.lua:91: " + record},
		{"text after the record", rspamdPrefix + record + " extra"},
		{"second record after the record", rspamdPrefix + record + " " + record},
		{"carriage return", rspamdPrefix + record + "\r"},
		{"control character in prefix", strings.Replace(rspamdPrefix, " ", "\x00", 1) + record},
		{"Unicode space in prefix", strings.Replace(rspamdPrefix, " ", "\u0085", 1) + record},
		{"opted-out decision", rspamdPrefix + strings.Replace(record, "policy=on", "policy=off", 1)},
		{"opted-in unfiltered", rspamdPrefix + strings.Replace(record, "decision=reject", "decision=unfiltered", 1)},
		{"scan error", rspamdPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none ip=198.51.100.7 qid=CSMSCOPE04`},
		{"no queue id field", rspamdPrefix + strings.TrimSuffix(record, " qid=CSMSCOPE04")},
		{"no sender field", rspamdPrefix + strings.Replace(record, " ip=198.51.100.7", "", 1)},
		{"malformed sender", rspamdPrefix + strings.Replace(record, "198.51.100.7", "198.51.100.256", 1)},
		{"queue id with punctuation", rspamdPrefix + strings.Replace(record, "CSMSCOPE04", "CSM.SCOPE", 1)},
		{"score out of range", rspamdPrefix + strings.Replace(record, "score=229", "score=2147483648", 1)},
		{"Exim marker", markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=229 action="reject" decision=reject ip=198.51.100.7`},
		{"record alone", record},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := ParseRspamdScan(tc.line); ok || got != (Scan{}) {
				t.Fatalf("ParseRspamdScan(%q) = %+v, %v; want no record", tc.line, got, ok)
			}
		})
	}
}
