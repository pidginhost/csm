package state

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestPendingFindingsKeepFileResponseIdentity(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	f := alert.Finding{Check: "obfuscated_php", FileResponseIdentity: "1:2:3:4:5:6:7"}
	if err = st.AppendPendingFindings([]alert.Finding{f}); err != nil {
		t.Fatal(err)
	}
	got, err := st.TakePendingFindings()
	if err != nil || len(got) != 1 || got[0].FileResponseIdentity != f.FileResponseIdentity {
		t.Fatalf("lost response identity across replay: %+v, %v", got, err)
	}
	public, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), f.FileResponseIdentity) {
		t.Fatal("file identity leaked into public finding")
	}
}
