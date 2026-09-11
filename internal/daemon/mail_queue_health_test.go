package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestMailReaderReportsStalledDeliveryAndRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "maillog")
		writer, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		d := New(&config.Config{MailLogs: config.MailLogsConfig{Source: "file", File: path}}, nil, nil, "")
		previous := config.Active()
		config.SetActive(d.cfg)
		defer config.SetActive(previous)
		release := make(chan struct{})
		releaseConsumer := sync.OnceFunc(func() { close(release) })
		defer func() {
			releaseConsumer()
			close(d.stopCh)
			d.wg.Wait()
		}()
		var messages []string
		d.startMailLogReader("", func(line string, _ *config.Config) []alert.Finding {
			messages = append(messages, line)
			<-release
			return nil
		})
		synctest.Wait()
		if _, err := writer.WriteString("one\ntwo\nthree\n"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if !slices.Equal(messages, []string{"one\n"}) {
			t.Fatalf("consumer did not pause on the first line: %q", messages)
		}
		time.Sleep(61 * time.Second)
		synctest.Wait()
		got, exists := d.queueStatuses(time.Now())["mail.delivery"]
		if !exists || got.Status != "degraded" || got.Capacity != 64 || got.Depth != 2 || got.InFlight != 1 || got.LagSeconds != 61 || got.ProcessingSeconds != 61 || got.DroppedTotal != 0 {
			t.Fatalf("stalled mail consumer has no accurate queue evidence: exists=%v status=%+v", exists, got)
		}
		releaseConsumer()
		synctest.Wait()
		got = d.queueStatuses(time.Now())["mail.delivery"]
		if !slices.Equal(messages, []string{"one\n", "two\n", "three\n"}) || got.Status != "ok" || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("mail delivery did not recover without loss: messages=%q status=%+v", messages, got)
		}
	})
}
