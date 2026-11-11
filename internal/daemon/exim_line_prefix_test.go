package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// logZone returns a fixed zone shift away from time.Local at wall, so a
// reader that ignores the zone in a log line lands shift off the real instant.
func logZone(wall time.Time, shift time.Duration) *time.Location {
	_, off := wall.In(time.Local).Zone()
	return time.FixedZone("log", off+int(shift/time.Second))
}

// Exim writes the zone (log_timezone) and PID (+pid) between the time and
// the message ID. A completion line in either form must still reap.
func TestReapCompletedMsgReadsZoneAndPID(t *testing.T) {
	for _, prefix := range []string{
		"2026-07-03 12:00:05 +0000 ",
		"2026-07-03 12:00:05 [12345] ",
		"2026-07-03 12:00:05 -0500 [12345] ",
	} {
		t.Run(prefix, func(t *testing.T) {
			cfg := defaultPHPRelayCfg()
			psw := newPerScriptWindow()
			idx := newMsgIDIndex(nil, 100)
			eng := newEvaluator(psw, nil, nil, cfg, nil)
			eng.SetMsgIndex(idx)

			msgID := "1wHpIU-0000000G8Fo-1FA1"
			sk := scriptKey("bad.example.com:/x.php")
			psw.getOrCreate(sk).recordActive(msgID, time.Now())
			idx.Put(msgID, indexEntry{ScriptKey: string(sk), At: time.Now()})

			eng.reapCompletedMsg(prefix + msgID + " Completed QT=1s")
			if ids, _ := psw.getOrCreate(sk).snapshotActiveMsgs(); len(ids) != 0 {
				t.Fatalf("Completed line must reap the active msg, still have %v", ids)
			}
		})
	}
}

// The retro cloud-relay scan compares each line's time with its lookback
// edge. A zoned line must be read at the instant Exim meant, not as local.
func TestCloudRelayScanReadsLogZone(t *testing.T) {
	wall := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	zone := logZone(wall, -5*time.Hour)
	at := time.Date(2026, 11, 9, 10, 0, 0, 0, zone)
	line := eximLine(at, "victim@example.com", "ec2-192-0-2-10.compute-1.amazonaws.com", "192.0.2.10", "subj")
	line = line[:19] + " " + at.Format("-0700") + line[19:]

	byUser := map[string]*cloudRelayScanAccumulator{}
	processCloudRelayScanLine(line, &config.Config{}, at.Add(-time.Hour), byUser)
	if acc := byUser["victim@example.com"]; acc == nil || acc.total != 1 {
		t.Fatalf("zoned line inside the lookback was not counted: %+v", acc)
	}
}

// History replay drops lines dated after now. A log zone east of local time
// must not push in-window sends into the future.
func TestPHPRelayReplayReadsLogZone(t *testing.T) {
	path2bTestHost(t)
	wall := time.Date(2026, 4, 29, 14, 0, 1, 0, time.UTC)
	zone := logZone(wall, 2*time.Hour)
	at := time.Date(2026, 4, 29, 14, 0, 1, 0, zone)
	var b strings.Builder
	for i := 0; i < 80; i++ {
		fmt.Fprintf(&b, "2026-04-29 14:00:01 %s 1ab%03d-DEF-01 <= info@example.com U=exampleuser P=local S=900 for buyer@example.net\n", at.Format("-0700"), i)
	}
	logPath := filepath.Join(t.TempDir(), "exim_mainlog")
	if err := os.WriteFile(logPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 50
	eng := newEvaluator(nil, nil, newPerAccountWindow(5000), cfg, nil)
	eng.SetEffectiveAccountLimit(50)

	fired := 0
	ScanEximHistoryForPHPRelayAccountVolume(context.Background(), logPath, eng, at.Add(30*time.Minute), func(f alert.Finding) {
		if f.Path == "volume_account" {
			fired++
		}
	})
	if fired == 0 {
		t.Fatal("zoned sends inside the window were dropped as future-dated")
	}
}
