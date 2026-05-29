package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestHandleMailLogSourceGoneMarksUnhealthyAndEmitsFinding(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.MarkWatcher("maillog", true)

	d.handleMailLogSourceGone(errors.New("stat /var/log/maillog: no such file"))

	if d.WatcherStatuses()["maillog"] {
		t.Fatal("maillog watcher should be unhealthy after source gone")
	}
	select {
	case f := <-d.alertCh:
		if f.Check != "mail_log_source_unavailable" {
			t.Fatalf("check = %q, want mail_log_source_unavailable", f.Check)
		}
		if f.Severity != alert.Warning {
			t.Fatalf("severity = %v, want warning", f.Severity)
		}
		if f.SourceIP != "" {
			t.Fatalf("SourceIP = %q, want empty so auto-block cannot target it", f.SourceIP)
		}
		if !strings.Contains(f.Message, "no such file") {
			t.Fatalf("message %q does not include source error", f.Message)
		}
	default:
		t.Fatal("expected maillog source finding")
	}
}

func TestHandleMailLogSourceRestoredMarksHealthy(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.MarkWatcher("maillog", false)

	d.handleMailLogSourceRestored()

	if !d.WatcherStatuses()["maillog"] {
		t.Fatal("maillog watcher should be healthy after source restore")
	}
}
