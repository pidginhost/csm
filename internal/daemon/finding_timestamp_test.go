package daemon

import (
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestYaraHealthFindingsStampTimestamp(t *testing.T) {
	for _, tc := range []struct {
		check string
		emit  func(*Daemon)
	}{
		{"yara_worker_compile_failed", func(d *Daemon) { d.reportYaraCompileStatus("invalid rule") }},
		{"yara_worker_crashed", func(d *Daemon) { d.onYaraWorkerRestart(1, syscall.SIGSEGV, time.Second) }},
	} {
		t.Run(tc.check, func(t *testing.T) {
			d := newDaemonForYaraBackendTest(t)
			before := time.Now()
			tc.emit(d)
			after := time.Now()
			if len(d.alertCh) != 1 {
				t.Fatalf("got %d alerts, want 1", len(d.alertCh))
			}
			f := <-d.alertCh
			if f.Check != tc.check || f.Severity != alert.Critical {
				t.Fatalf("finding = %+v, want Critical %s", f, tc.check)
			}
			if f.Timestamp.Before(before) || f.Timestamp.After(after) {
				t.Errorf("timestamp = %v, want within [%v, %v]", f.Timestamp, before, after)
			}
		})
	}
}

func TestMsgIndexErrorFindingsStampTimestamp(t *testing.T) {
	for _, failure := range []string{"encode", "commit"} {
		t.Run(failure, func(t *testing.T) {
			db := openTestDB(t)
			p := newMsgIndexPersister(db, 1, time.Hour)
			var findings []alert.Finding
			p.SetErrorCallback(func(f alert.Finding) { findings = append(findings, f) })
			entry := indexEntry{At: time.Now()}
			if failure == "encode" {
				// time.Time cannot gob-encode a zone offset outside int16 minutes.
				entry.At = entry.At.In(time.FixedZone("invalid", 32768*60))
			} else if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			p.commitBatch([]persistOp{{msgID: "test-message", entry: entry}})
			after := time.Now()
			if len(findings) != 1 || p.ErrorCount() != 1 {
				t.Fatalf("findings = %+v, errors = %d, want one persistence error", findings, p.ErrorCount())
			}
			f := findings[0]
			if f.Check != "email_php_relay_msgindex_persist_failed" || f.Severity != alert.Critical || !strings.Contains(f.Message, failure) {
				t.Fatalf("finding = %+v, want Critical %s error", f, failure)
			}
			if f.Timestamp.Before(before) || f.Timestamp.After(after) {
				t.Errorf("timestamp = %v, want within [%v, %v]", f.Timestamp, before, after)
			}
		})
	}
}
