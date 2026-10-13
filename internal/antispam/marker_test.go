package antispam

import "testing"

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
