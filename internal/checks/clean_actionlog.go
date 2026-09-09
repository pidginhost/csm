package checks

import "github.com/pidginhost/csm/internal/actionlog"

type cleanAction struct{ rec actionlog.Record }

func newCleanAction(path string) *cleanAction {
	return &cleanAction{rec: actionlog.Record{Op: "respond.clean_file", Target: path, Before: actionlog.Metadata(path), Result: actionlog.Refused}}
}

func (a *cleanAction) capture(target *cleanTarget, data []byte) {
	a.rec.Target = target.Path
	a.rec.Before = actionlog.ContentState(target.Info, data)
}

func (a *cleanAction) replace(target *cleanTarget, content []byte, backupPath string) error {
	a.rec.Result = actionlog.Failed
	a.rec.RecoveryPath = backupPath
	err := writeCleanedFileAtomic(target, content)
	// Rename can succeed even when the following directory sync fails. The
	// record must still describe the installed bytes and retained recovery copy.
	if target.installed {
		a.rec.Result = actionlog.Applied
		a.rec.After = actionlog.ContentState(target.replacementInfo, content)
	}
	return err
}

func (a *cleanAction) finish(message string) {
	a.rec.Error = message
	if a.rec.After == nil {
		a.rec.After = actionlog.Metadata(a.rec.Target)
	}
	actionlog.Write(a.rec)
}
