package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestMailReaderRecoversInitialMissingFile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "maillog")
		d := New(&config.Config{MailLogs: config.MailLogsConfig{Source: "file", File: path}}, nil, nil, "")
		previous := config.Active()
		config.SetActive(d.cfg)
		defer config.SetActive(previous)
		defer func() {
			close(d.stopCh)
			d.wg.Wait()
			if d.WatcherStatuses()["maillog"] {
				t.Error("stopped mail reader still reported attached")
			}
		}()
		var messages []string
		d.startMailLogReader("", func(line string, _ *config.Config) []alert.Finding {
			messages = append(messages, line)
			return nil
		})
		synctest.Wait()
		if d.WatcherStatuses()["maillog"] {
			t.Fatal("missing source reported healthy")
		}
		select {
		case finding := <-d.alertCh:
			if finding.Check != "mail_log_source_unavailable" {
				t.Fatalf("unexpected outage finding: %+v", finding)
			}
		default:
			t.Fatal("initial attachment failure did not emit a finding")
		}
		if err := os.WriteFile(path, []byte("historical authentication failure\n"), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(31 * time.Second)
		synctest.Wait()
		if !d.WatcherStatuses()["maillog"] {
			t.Fatal("mail watcher did not recover after file appeared")
		}
		w, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		if _, err := w.WriteString("current authentication failure\n"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if len(messages) != 1 || messages[0] != "current authentication failure\n" {
			t.Fatalf("messages = %q, want only the new record once", messages)
		}
	})
}
