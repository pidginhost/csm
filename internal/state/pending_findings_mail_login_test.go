package state

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
)

// Shutdown replay must not turn a mailbox attack into an unrelated web incident.
func TestPendingFindingsKeepMailLoginKind(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	mail := alert.Finding{Check: "ip_reputation", Severity: alert.Critical, SourceIP: "192.0.2.86", MailLoginFailure: true, Timestamp: time.Now()}
	web := mail
	web.SourceIP, web.MailLoginFailure = "192.0.2.87", false
	if appendErr := st.AppendPendingFindings([]alert.Finding{mail, web}); appendErr != nil {
		t.Fatal(appendErr)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("replayed %d findings, want 2", len(got))
	}
	for i, want := range []incident.Kind{incident.KindMailboxBruteforce, incident.KindWebAttack} {
		if kind := incident.ClassifyKind(got[i]); kind != want {
			t.Errorf("replayed finding %d: kind = %s, want %s", i, kind, want)
		}
	}
}

func TestPendingIdentityCoversMailLoginKind(t *testing.T) {
	mail := alert.Finding{Check: "ip_reputation", SourceIP: "192.0.2.86", MailLoginFailure: true}
	web := mail
	web.MailLoginFailure = false
	if pendingIdentity([]alert.Finding{mail}) == pendingIdentity([]alert.Finding{web}) {
		t.Fatal("queue identity ignores the incident kind")
	}
}
