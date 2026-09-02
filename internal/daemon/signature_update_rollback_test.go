package daemon

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/signatures"
)

func TestSignatureRollbackRefusalEmitsFinding(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.reportSignatureUpdateError(errors.Join(signatures.ErrUpdateRollback, errors.New("rule count collapsed")))
	select {
	case finding := <-d.alertCh:
		if finding.Check != "signature_update_rollback" || finding.Severity != alert.Critical {
			t.Fatalf("finding = %+v", finding)
		}
	default:
		t.Fatal("rollback refusal was only logged")
	}
}
