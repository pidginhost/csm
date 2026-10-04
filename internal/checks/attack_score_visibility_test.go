package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/attackdb"
)

// The attack database's scores rank addresses and feed the unified verdict,
// which operators act on. A check that names no evidence family is visibility
// only and must not feed those scores; successful-login audit records are
// stored but never scored.
func TestVisibilityChecksNeverFeedAttackScores(t *testing.T) {
	for _, info := range checkRegistry {
		typ, ok := attackdb.AttackTypeFor(info.Name)
		if !ok || typ == attackdb.AttackAuthSuccess {
			continue
		}
		if info.Response.Evidence == admission.FamilyNone {
			t.Errorf("%s feeds attack score type %s but names no evidence family", info.Name, typ)
		}
	}
}
