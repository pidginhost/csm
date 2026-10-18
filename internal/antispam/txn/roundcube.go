package txn

import (
	"errors"
	"slices"

	"github.com/pidginhost/csm/internal/antispam"
)

// roundcube applies the webmail include change after rspamd and Exim are
// verified, then checks what a fresh Roundcube request loads through
// cPanel's PHP (spec 6.4). An include that does not take effect, or whose
// check fails, is put back to its prior state alone and reported; learning
// and the rest of the transaction stand. A removal is reported, never
// undone. The include still rolls back with an enclosing failure.
func (t *tx) roundcube(changes []change) (string, error) {
	for _, c := range changes {
		if err := t.write(c); err != nil {
			return "", err
		}
		// A failed check is reported, not returned: it never fails the
		// transaction.
		uid, gid, idErr := t.h.unprivileged()
		if idErr != nil {
			uid, gid = -1, -1
		}
		state, checkErr := antispam.RoundcubeEffective(t.fwd, t.cmd, uid, gid)
		checked, install := checkErr == nil, c.next.exists
		switch {
		case !install && !checked:
			return antispam.RoundcubeUnavailable + "CSM could not confirm that Roundcube stopped loading the include", nil
		case !install && (state.JunkMbox == antispam.RoundcubeJunkFolder || state.SpamMbox == antispam.RoundcubeJunkFolder):
			return antispam.RoundcubeUnavailable + "Roundcube still sends Junk to INBOX.spam through another include", nil
		case !install:
			continue
		case checked && state.Applied():
			continue
		}
		reason := "Roundcube does not load the include's Junk folder, another include may override it; " + state.Describe()
		if !checked {
			reason = "cPanel's PHP could not verify the include"
		}
		if restoreErr := t.restoreLast(); restoreErr != nil {
			return "", restoreErr
		}
		return antispam.RoundcubeUnavailable + reason, nil
	}
	return "", nil
}

// restoreLast puts the last written file back to its snapshot and drops it
// from the rollback list, so an enclosing rollback does not find it changed.
func (t *tx) restoreLast() error {
	last := len(t.writes) - 1
	w := t.writes[last]
	if err := t.h.replace(w.path, w.next, w.before); err != nil {
		if errors.Is(err, errDurability) {
			// The snapshot reached disk. An enclosing rollback must retry
			// against it, not mistake our own restore for a foreign edit.
			t.writes[last].next = w.before
		}
		return err
	}
	t.writes = slices.Delete(t.writes, last, len(t.writes))
	return nil
}
