package antispam

import (
	"fmt"
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
