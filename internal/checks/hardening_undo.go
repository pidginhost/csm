package checks

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/atomicio"
)

// Undo restores what the last apply of one fix changed, from the record the
// root worker wrote then, and only while the host still holds what that
// apply set: a setting changed since is left alone. Every path and key comes
// from the fix name, as on apply, and a record naming others is refused.

// hardeningPHPInstalls lists the PHP builds an undo derives drop-in paths
// from, found the way the apply finds them.
var hardeningPHPInstalls = func() []phpInstall { return discoverPHPInstalls(detectServerType()) }

var hardeningUndoWriteDropIn = writeDropIn
var hardeningUndoChown = (*os.File).Chown
var hardeningUndoChmod = func(f *os.File, mode uint32) error { return syscall.Fchmod(int(f.Fd()), mode) }

// undoRefusal is an undo that changed nothing; the record stays.
type undoRefusal string

func (r undoRefusal) Error() string { return string(r) }

const errUndoMismatch = undoRefusal("The undo record does not match this fix on this host.")

func changedSince(what string) error {
	return undoRefusal(what + " changed since the apply.")
}

// UndoHardening undoes the last apply of the fix called name. The status is
// undone; refused when nothing was changed, keeping the record; or failed,
// also keeping it.
func UndoHardening(name string) HardeningFixResult {
	res := HardeningFixResult{Name: name, Title: name, Status: "undone"}
	msg, err := undoHardening(name)
	var refusal undoRefusal
	switch {
	case errors.As(err, &refusal):
		res.Status, res.Message = "refused", err.Error()
	case err != nil:
		res.Status, res.Message = "failed", err.Error()
	default:
		res.Message = msg
	}
	return res
}

func undoHardening(name string) (string, error) {
	if !knownHardeningFix(name) {
		return "", undoRefusal("Unknown hardening fix.")
	}
	rec, ok, err := readHardeningUndo(name)
	if err != nil {
		return "", fmt.Errorf("reading the undo record: %w", err)
	}
	if !ok {
		return "", undoRefusal("There is no undo record for this fix.")
	}
	msg, err := undoRecord(rec)
	if err != nil {
		return "", err
	}
	if err := deleteHardeningUndo(name); err != nil {
		msg += " Removing the undo record failed (" + err.Error() + ")."
	}
	return msg, nil
}

func undoRecord(rec HardeningUndoRecord) (string, error) {
	if d, ok := sshFixDirectives[rec.Name]; ok {
		return undoSSH(rec, d.key)
	}
	if kv, ok := sysctlFixes[rec.Name]; ok {
		return undoSysctl(rec, kv.key)
	}
	if kv, ok := cpTweakFixes[rec.Name]; ok {
		return undoTweak(rec, kv.key)
	}
	if dir, ok := hardeningTmpDirs[rec.Name]; ok {
		return undoMode(rec, dir, true)
	}
	if key, suffix, ok := phpFixFor(rec.Name); ok {
		return undoPHP(rec, key, suffix)
	}
	switch rec.Name {
	case "os_shadow_permissions":
		return undoMode(rec, hardeningShadowPath, false)
	case "cp_compilers":
		return undoCompilers(rec)
	case "cp_updates":
		return undoFile(rec, hardeningCPUpdateConf)
	}
	return "", errUndoMismatch
}

// --- SSH ---

// undoSSH takes the keyword out of CSM's sshd_config block, or puts back
// the value the block had, and enables the global lines CSM disabled for
// it. sshd checks the file before it is reloaded, as on apply.
func undoSSH(rec HardeningUndoRecord, keyword string) (string, error) {
	if rec.SSH == nil || rec.SSH.Keyword != keyword {
		return "", errUndoMismatch
	}
	info, err := os.Lstat(sshdConfigPath)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", sshdConfigPath)
	}
	// #nosec G304 -- fixed sshd config path.
	orig, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return "", err
	}
	updated, err := undoSSHDConfig(string(orig), *rec.SSH)
	if err != nil {
		return "", err
	}
	if err := replaceSSHDConfig(info.Mode().Perm(), orig, []byte(updated)); err != nil {
		return "", err
	}
	msg := keyword + " restored in " + sshdConfigPath + " and sshd reloaded."
	if err := reloadSSHD(); err != nil {
		failure := fmt.Errorf("reloading sshd failed: %w", err)
		if rerr := atomicio.AtomicWrite(sshdConfigPath, info.Mode().Perm(), orig); rerr != nil {
			return "", errors.Join(failure, fmt.Errorf("restoring the applied SSH config failed: %w; recover it from %s.csm-bak", rerr, sshdConfigPath))
		}
		// A failed reload may have reached the daemon before its caller failed.
		if rerr := reloadSSHD(); rerr != nil {
			failure = errors.Join(failure, fmt.Errorf("applied SSH config restored, but reload it manually: %w", rerr))
		}
		return "", failure
	}
	return msg, nil
}

// undoSSHDConfig returns content with the keyword's line in CSM's block
// removed, or set back to its earlier value, and every global line CSM
// disabled for the keyword enabled again; a later apply of another fix can
// disable more of them than the record lists. A block left empty goes: no
// apply leaves one. It refuses unless the block, closed by its end marker,
// still holds the applied value and the lines the record lists are still
// disabled.
func undoSSHDConfig(content string, s sshUndoState) (string, error) {
	changed := changedSince(s.Keyword + " in " + sshdConfigPath)
	kw := strings.ToLower(s.Keyword)
	var out, enabled []string
	inBlock, inMatch, found, seenBlock := false, false, false, false
	begin := 0
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == sshdBlockBegin:
			if inBlock || inMatch || seenBlock {
				return "", changed
			}
			seenBlock = true
			inBlock, begin = true, len(out)
		case inBlock && t == sshdBlockEnd:
			inBlock = false
			if len(out) == begin+1 {
				out = out[:begin]
				continue
			}
		case inBlock:
			k, v, ok := splitSSHDKeyword(t)
			if k == "match" {
				return "", changed
			}
			if ok && k == kw {
				// sshd takes the first value for a keyword.
				if !found && v != s.AppliedValue {
					return "", changed
				}
				if !found && s.HadValue {
					out = append(out, s.Keyword+" "+s.PrevValue)
				}
				found = true
				continue
			}
		default:
			// The apply disables lines only before the first Match block.
			if original, ok := strings.CutPrefix(line, sshdDisabledBy); ok && !inMatch {
				if k, _, _ := splitSSHDKeyword(strings.TrimSpace(original)); k == kw {
					enabled = append(enabled, original)
					line = original
				}
			} else if k, _, _ := splitSSHDKeyword(t); k == "match" {
				inMatch = true
			}
		}
		out = append(out, line)
	}
	// Without its end marker the block would run to the end of the file.
	if !found || inBlock {
		return "", changed
	}
	left := map[string]int{}
	for _, line := range enabled {
		left[line]++
	}
	for _, line := range s.DisabledLines {
		if left[line] == 0 {
			return "", changed
		}
		left[line]--
	}
	return strings.Join(out, "\n"), nil
}

// --- sysctl ---

// undoSysctl puts back the drop-in lines the apply replaced for the key
// before the runtime value, so a failed drop-in write leaves both as they
// were.
func undoSysctl(rec HardeningUndoRecord, key string) (string, error) {
	s := rec.Sysctl
	if s == nil || s.Key != key {
		return "", errUndoMismatch
	}
	value, err := sysctlRuntime(key)
	if err != nil {
		return "", err
	}
	if value != s.AppliedValue {
		return "", changedSince(key)
	}
	msg := key + " set back to " + s.PrevRuntime + "."
	var original appliedDropIn
	if !s.RuntimeOnly {
		// The drop-in can change apart from the runtime value, and a record
		// can carry an earlier apply's drop-in change, so check it as well.
		snapshot, err := readUndoDropIn(hardeningSysctlConfPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		original = snapshot
		lines, err := restoreKeyLines(string(snapshot.data), key+" in "+hardeningSysctlConfPath, s.AppliedValue, s.PrevLines,
			func(line string) (string, bool) { return sysctlLineValue(line, key) })
		if err != nil {
			return "", err
		}
		if err := hardeningUndoWriteDropIn(hardeningSysctlConfPath, sysctlDropInHeader, lines); err != nil {
			return "", errors.Join(err, restoreAppliedDropIns([]appliedDropIn{original}))
		}
		msg = key + " set back to " + s.PrevRuntime + " and restored in " + hardeningSysctlConfPath + "."
	}
	if _, err := hardeningRun("sysctl", "-w", key+"="+s.PrevRuntime); err != nil {
		failure := errors.Join(err, restoreAppliedSysctl(*s))
		if !s.RuntimeOnly {
			failure = errors.Join(failure, restoreAppliedDropIns([]appliedDropIn{original}))
		}
		return "", failure
	}
	return msg, nil
}

// A command can fail after its write reached the kernel. Do not leave that
// completed step blocking the unchanged record's guard on the next retry.
func restoreAppliedSysctl(s sysctlUndoState) error {
	value, err := sysctlRuntime(s.Key)
	if err != nil {
		return fmt.Errorf("checking runtime rollback: %w", err)
	}
	if value == s.AppliedValue {
		return nil
	}
	if value != s.PrevRuntime {
		return fmt.Errorf("%s changed during undo; runtime rollback refused", s.Key)
	}
	if _, err := hardeningRun("sysctl", "-w", s.Key+"="+s.AppliedValue); err != nil {
		return fmt.Errorf("restoring applied runtime value for %s: %w", s.Key, err)
	}
	return nil
}

// restoreKeyLines returns content's lines with prev put back in place of the
// setting's lines, which value picks out, once each of them holds applied.
// Extra setting lines go; extra prev lines follow the last setting line.
func restoreKeyLines(content, what, applied string, prev []string, value func(string) (string, bool)) ([]string, error) {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	var at []int
	for i, line := range lines {
		if v, ok := value(line); ok {
			if v != applied {
				return nil, changedSince(what)
			}
			at = append(at, i)
		}
	}
	if len(at) == 0 {
		return nil, changedSince(what)
	}
	out := make([]string, 0, len(lines)+len(prev))
	for i, line := range lines {
		switch {
		case !slices.Contains(at, i):
			out = append(out, line)
		case i == at[len(at)-1]:
			out = append(out, prev...)
		case len(prev) > 0:
			out, prev = append(out, prev[0]), prev[1:]
		}
	}
	return out, nil
}

// writeDropIn writes lines to a CSM drop-in, or removes the drop-in when
// only the header CSM created it with is left.
func writeDropIn(path, header string, lines []string) error {
	if slices.Equal(lines, []string{header}) {
		return os.Remove(path)
	}
	return atomicio.AtomicWrite(path, 0o644, []byte(strings.Join(lines, "\n")+"\n"))
}

// --- cPanel ---

// undoTweak sets a WHM tweak setting back to its value before the apply.
func undoTweak(rec HardeningUndoRecord, key string) (string, error) {
	tw := rec.Tweak
	if tw == nil || tw.Key != key {
		return "", errUndoMismatch
	}
	value, had, err := getWHMTweak(key)
	if err != nil {
		return "", err
	}
	if !had || value != tw.Applied {
		return "", changedSince("The WHM tweak setting " + key)
	}
	if !tw.HadValue {
		// set_tweaksetting saves a setting only when given a value, and
		// cPanel refuses an empty one, so whmapi1 cannot remove a value.
		return "", undoRefusal(key + " had no value before the apply, and whmapi1 cannot remove one. Set it back to its default in WHM Tweak Settings.")
	}
	if err := setWHMTweak(key, tw.Previous); err != nil {
		return "", errors.Join(err, restoreAppliedTweak(*tw))
	}
	return "Tweak setting " + key + " set back to " + tw.Previous + ".", nil
}

// A missing or failed reply does not prove that WHM left the value alone.
func restoreAppliedTweak(tw tweakUndoState) error {
	value, had, err := getWHMTweak(tw.Key)
	if err != nil {
		return fmt.Errorf("checking WHM rollback: %w", err)
	}
	if had && value == tw.Applied {
		return nil
	}
	if !had || value != tw.Previous {
		return fmt.Errorf("%s changed during undo; WHM rollback refused", tw.Key)
	}
	if err := setWHMTweak(tw.Key, tw.Applied); err != nil {
		return fmt.Errorf("restoring applied WHM value for %s: %w", tw.Key, err)
	}
	return nil
}

// undoCompilers opens compiler access again: with cPanel's own script when
// the apply used it, which sets cPanel's modes rather than the earlier ones,
// or by putting back the compiler's owner and mode.
func undoCompilers(rec HardeningUndoRecord) (string, error) {
	c := rec.Compilers
	if c == nil {
		return "", errUndoMismatch
	}
	switch c.Method {
	case "script":
		info, err := os.Stat(hardeningCompilerPath)
		if err != nil {
			return "", err
		}
		// The script's own test: compilers are open when cc's mode is above 0750.
		if info.Mode().Perm() > 0o750 {
			return "", changedSince("Compiler access")
		}
		if _, err := hardeningRun(hardeningCompilersScript, "on"); err != nil {
			if _, rerr := hardeningRun(hardeningCompilersScript, "off"); rerr != nil {
				return "", errors.Join(err, fmt.Errorf("restoring restricted compiler access: %w", rerr))
			}
			return "", err
		}
		return "Compiler access restored with " + hardeningCompilersScript + " on.", nil
	case "chmod":
		target, err := filepath.EvalSymlinks(hardeningCompilerPath)
		if err != nil {
			return "", err
		}
		if c.Path != target {
			return "", errUndoMismatch
		}
		return restoreModeByFD(modeUndoState{Path: c.Path, Mode: c.Mode, UID: c.UID, GID: c.GID,
			AppliedMode: c.AppliedMode, AppliedUID: c.AppliedUID, AppliedGID: c.AppliedGID}, false)
	}
	return "", errUndoMismatch
}

// undoFile writes back the whole file as it was before the apply.
func undoFile(rec HardeningUndoRecord, path string) (string, error) {
	file := rec.File
	if file == nil || file.Path != path {
		return "", errUndoMismatch
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	// #nosec G304 -- fixed operator config path.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if string(data) != file.Applied {
		return "", changedSince(path)
	}
	if err := hardeningConfigWrite(path, info.Mode().Perm(), []byte(file.Previous)); err != nil {
		if rerr := atomicio.AtomicWrite(path, info.Mode().Perm(), data); rerr != nil {
			return "", errors.Join(err, fmt.Errorf("restoring applied configuration in %s failed: %w", path, rerr))
		}
		return "", err
	}
	return path + " restored.", nil
}

// --- OS ---

func undoMode(rec HardeningUndoRecord, path string, wantDir bool) (string, error) {
	if rec.Mode == nil || rec.Mode.Path != path {
		return "", errUndoMismatch
	}
	return restoreModeByFD(*rec.Mode, wantDir)
}

// restoreModeByFD puts back the owner and mode st records, through a
// descriptor opened without following a final symlink, once the object
// still has the owner and mode the apply set.
func restoreModeByFD(st modeUndoState, wantDir bool) (string, error) {
	// #nosec G304 -- path re-derived from the fix name and matched with the record.
	f, err := os.OpenFile(st.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if wantDir && !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", st.Path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", st.Path)
	}
	cur, err := modeState(st.Path, info)
	if err != nil {
		return "", err
	}
	if cur.Mode != st.AppliedMode || cur.UID != st.AppliedUID || cur.GID != st.AppliedGID {
		return "", changedSince("The owner or mode of " + st.Path)
	}
	ownerChanged := st.UID != cur.UID || st.GID != cur.GID
	if ownerChanged {
		if err := hardeningUndoChown(f, int(st.UID), int(st.GID)); err != nil {
			return "", err
		}
	}
	// After the chown, which clears the setuid and setgid bits.
	if err := hardeningUndoChmod(f, st.Mode&0o7777); err != nil {
		if ownerChanged {
			chownErr := hardeningUndoChown(f, int(cur.UID), int(cur.GID))
			chmodErr := hardeningUndoChmod(f, cur.Mode)
			if rollbackErr := errors.Join(chownErr, chmodErr); rollbackErr != nil {
				return "", errors.Join(err, fmt.Errorf("restoring applied owner and mode of %s: %w", st.Path, rollbackErr))
			}
		}
		return "", err
	}
	return fmt.Sprintf("%s is mode %04o, owner %d:%d again.", st.Path, st.Mode, st.UID, st.GID), nil
}

// --- PHP ---

// undoPHP puts back the key's line in each drop-in the apply set it Off
// in, once every one of them still holds Off, and reloads PHP as the apply
// did.
func undoPHP(rec HardeningUndoRecord, key, suffix string) (string, error) {
	if len(rec.PHP) == 0 {
		return "", errUndoMismatch
	}
	inst, _ := findPHPInstall(hardeningPHPInstalls(), suffix)
	derived := phpDropInPaths(phpInstallScanDirs(inst))
	if slices.ContainsFunc(rec.PHP, func(p phpUndoState) bool { return p.Key != key || !slices.Contains(derived, p.Path) }) {
		return "", errUndoMismatch
	}
	restored := make([][]string, len(rec.PHP))
	original := make([]appliedDropIn, len(rec.PHP))
	for i, p := range rec.PHP {
		snapshot, err := readUndoDropIn(p.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		original[i] = snapshot
		lines, err := restorePHPDropIn(p, string(snapshot.data))
		if err != nil {
			return "", err
		}
		restored[i] = lines
	}
	var dirs []string
	for i, p := range rec.PHP {
		if err := hardeningUndoWriteDropIn(p.Path, phpDropInHeader, restored[i]); err != nil {
			err = fmt.Errorf("restoring %s: %w", p.Path, err)
			// Include the failed write: rename may have succeeded before fsync failed.
			return "", errors.Join(err, restoreAppliedDropIns(original[:i+1]))
		}
		dirs = append(dirs, filepath.Dir(p.Path))
	}
	msg, err := reloadPHPResult(dirs)
	if err != nil {
		rerr := restoreAppliedDropIns(original)
		// Some services may have reloaded before another service failed.
		_, reloadErr := reloadPHPResult(dirs)
		return "", errors.Join(err, rerr, reloadErr)
	}
	return key + " restored in " + strings.Join(phpDropInPaths(dirs), ", ") + ". " + msg, nil
}

// restorePHPDropIn returns the drop-in's lines with the key's earlier line
// back in place of the applied one.
func restorePHPDropIn(p phpUndoState, content string) ([]string, error) {
	var prev []string
	if p.HadKey {
		prev = []string{p.PrevLine}
	}
	return restoreKeyLines(content, p.Key+" in "+p.Path, p.Applied, prev, func(line string) (string, bool) {
		k, v, ok := phpIniSetting(line)
		return v, ok && k == p.Key
	})
}

// Snapshots are taken only after deriving paths from the fix name. Rolling
// back failed undos keeps the unchanged record's Applied guards retryable.
type appliedDropIn struct {
	path string
	data []byte
	perm os.FileMode
}

func restoreAppliedDropIns(files []appliedDropIn) error {
	var errs []error
	for _, file := range files {
		if err := atomicio.AtomicWrite(file.path, file.perm, file.data); err != nil {
			errs = append(errs, fmt.Errorf("restoring applied settings in %s failed: %w", file.path, err))
		}
	}
	return errors.Join(errs...)
}

func readUndoDropIn(path string) (appliedDropIn, error) {
	f, err := (realOS{}).openRegularFile(path, syscall.O_NOFOLLOW)
	if err != nil {
		return appliedDropIn{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return appliedDropIn{}, err
	}
	data, err := io.ReadAll(f)
	return appliedDropIn{path: path, data: data, perm: info.Mode().Perm()}, err
}
