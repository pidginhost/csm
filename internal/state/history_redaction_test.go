package state

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestAppendHistoryRedacts(t *testing.T) {
	t.Cleanup(setupBboltGlobal(t))
	s := openTestStore(t)
	f := alert.Finding{
		Check: "cpanel_login_realtime", Message: "password=message-fixture",
		Details: "[cpaneld] NEW shop:session-fixture", Timestamp: time.Now().UTC(),
		SourceIP: "198.51.100.23", TenantID: "shop", FilePath: "/password=filename",
	}
	want := f
	want.Message = "password=[REDACTED]"
	want.Details = "[cpaneld] NEW shop:[REDACTED]"
	input := []alert.Finding{f}
	s.AppendHistory(input)
	if !reflect.DeepEqual(input, []alert.Finding{f}) {
		t.Fatal("history redaction mutated the caller's finding")
	}
	got, total := s.ReadHistory(10, 0)
	if total != 1 || !reflect.DeepEqual(got, []alert.Finding{want}) {
		t.Errorf("history = %+v, total %d; want %+v, total 1", got, total, want)
	}
}
