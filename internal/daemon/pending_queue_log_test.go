package daemon

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestPendingQueueRealLogRoundTrip(t *testing.T) {
	for _, multibyte := range []bool{false, true} {
		label := "ascii_control"
		suffix := "xyz"
		if multibyte {
			label = "utf8_cut_by_existing_parser"
			suffix = "\u20ac"
		}
		t.Run(label, func(t *testing.T) {
			cfg := &config.Config{}
			prefix := "Sep 10 12:00:00 fixture sshd[63]: Accepted password for fixture from 192.0.2.63 port 12345 ssh2 "
			line := prefix + strings.Repeat("x", 199-len(prefix)) + suffix
			if !utf8.ValidString(line) {
				t.Fatal("probe input must be valid UTF-8")
			}
			findings := parseSecureLogLine(line, cfg)
			if len(findings) != 1 {
				t.Fatalf("real parser finding count=%d", len(findings))
			}
			if utf8.ValidString(findings[0].Details) == multibyte {
				t.Fatal("probe missed actual byte truncation boundary")
			}
			dir := t.TempDir()
			_, restore := openTestBoltStore(t, dir)
			defer restore()
			st, err := state.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			d := New(cfg, st, nil, "")
			d.persistPendingFindingsOnShutdown(findings)
			before := d.QueueStatuses()["state.pending"]
			if before.Depth != 1 || before.DroppedTotal != 0 || before.DroppedLowerBound || before.Status != "ok" {
				t.Fatalf("first successful parking: %+v", before)
			}
			got, err := st.TakePendingFindings()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Check != "ssh_login_unknown_ip" || !utf8.ValidString(got[0].Details) {
				t.Fatal("roundtrip changed original serialization policy")
			}
			row := d.QueueStatuses()["state.pending"]
			if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.DroppedLowerBound || row.Status != "ok" {
				t.Errorf("successful real parser/shutdown/read/clear invented persistence uncertainty: %+v", row)
			}
		})
	}
}
