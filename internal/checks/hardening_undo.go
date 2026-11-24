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

// alreadyBack is the message for an undo whose setting already holds its
// state from before the apply, as after a reset by hand: nothing is left to
// undo, so the record goes and the page stops offering Undo.
func alreadyBack(what string) string {
	return what + " is already back to its earlier state."
}

// settingValues returns the values of the lines value picks out.
func settingValues(lines []string, value func(string) (string, bool)) []string {
	var values []string
	for _, line := range lines {
		if v, ok := value(line); ok {
			values = append(values, v)
		}
	}
	return values
}

// UndoHardening undoes the last apply of the fix called name. The status is
// undone, also when the setting was already back, and the record goes;
// refused when nothing was changed, keeping the record; or failed, also
// keeping it.
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
	if sshAlreadyBack(string(orig), *rec.SSH) {
		return alreadyBack(keyword + " in " + sshdConfigPath), nil
	}
	updated, err := undoSSHDConfig(string(orig), *rec.SSH)
	if err != nil {
		return "", err
	}
	if err := replaceSSHDConfig(info.Mode().Perm(), orig, []byte(updated)); err != nil {
		return "", err
	}
	msg := keyword + " restored in " + sshdConfigPath + " and sshd reloaded."
	// As on apply, sshd -t passed the file, so a failed reload leaves it for
	// a manual reload; a host where the reload always fails can still undo.
	if err := reloadSSHD(); err != nil {
		msg = keyword + " restored in " + sshdConfigPath + ", but reloading sshd failed (" + err.Error() + "); reload it manually."
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

// sshAlreadyBack reports whether content holds the keyword as it was before
// the apply: the block's earlier value or none, and each global line the
// apply disabled enabled again before any Match block. A block structure
// undo would refuse never counts as back.
func sshAlreadyBack(content string, s sshUndoState) bool {
	kw := strings.ToLower(s.Keyword)
	var value string
	found, inBlock, inMatch, seenBlock := false, false, false, false
	var active []string
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		k, v, ok := splitSSHDKeyword(t)
		switch {
		case t == sshdBlockBegin:
			if inBlock || inMatch || seenBlock {
				return false
			}
			inBlock, seenBlock = true, true
		case inBlock && t == sshdBlockEnd:
			inBlock = false
		case inBlock && k == "match":
			return false
		case inBlock:
			if ok && k == kw && !found {
				value, found = v, true
			}
		case k == "match":
			inMatch = true
		case !inMatch:
			if original, disabled := strings.CutPrefix(line, sshdDisabledBy); disabled {
				if key, _, _ := splitSSHDKeyword(strings.TrimSpace(original)); key == kw {
					return false
				}
			}
			if ok && k == kw {
				active = append(active, line)
			}
		}
	}
	if inBlock || found != s.HadValue || value != s.PrevValue {
		return false
	}
	// Order matters: sshd uses the first active value for a keyword.
	return slices.Equal(active, s.DisabledLines)
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
	var original appliedDropIn
	if !s.RuntimeOnly {
		// The drop-in can change apart from the runtime value, and a record
		// can carry an earlier apply's drop-in change, so check it as well.
		original, err = readUndoDropIn(hardeningSysctlConfPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	lineValue := func(line string) (string, bool) { return sysctlLineValue(line, key) }
	if value == s.PrevRuntime && (s.RuntimeOnly ||
		slices.Equal(settingValues(strings.Split(string(original.data), "\n"), lineValue), settingValues(s.PrevLines, lineValue))) {
		return alreadyBack(key), nil
	}
	if value != s.AppliedValue {
		return "", changedSince(key)
	}
	msg := key + " set back to " + s.PrevRuntime + "."
	if !s.RuntimeOnly {
		lines, err := restoreKeyLines(string(original.data), key+" in "+hardeningSysctlConfPath, s.AppliedValue, s.PrevLines, lineValue)
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
// An earlier value whmapi1 cannot set is left to WHM Tweak Settings.
func undoTweak(rec HardeningUndoRecord, key string) (string, error) {
	tw := rec.Tweak
	if tw == nil || tw.Key != key {
		return "", errUndoMismatch
	}
	value, had, err := getWHMTweak(key)
	if err != nil {
		return "", err
	}
	// No value reads as "", like an empty one: WHM treats both as none, and
	// its own reset leaves none.
	if value == tw.Previous {
		return alreadyBack("The WHM tweak setting " + key), nil
	}
	if !had || value != tw.Applied {
		return "", changedSince("The WHM tweak setting " + key)
	}
	if tw.Previous == "" {
		// set_tweaksetting saves a setting only when given a value, and
		// cPanel refuses an empty one, so whmapi1 cannot remove a value.
		return "", undoRefusal(key + " had no value before the apply, and whmapi1 cannot remove one. Set it back to its default in WHM Tweak Settings.")
	}
	if err := setWHMTweak(key, tw.Previous); err != nil {
		rerr := restoreAppliedTweak(*tw)
		// cPanel validates the value and may refuse one it held before.
		if errors.Is(err, errWHMRefused) && rerr == nil {
			return "", undoRefusal(strings.TrimSuffix(err.Error(), ".") + ". Set " + key + " back in WHM Tweak Settings.")
		}
		return "", errors.Join(err, rerr)
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
		// The script's own test: compilers are open when cc's mode is above
		// 0750, as they were before the apply.
		if info.Mode().Perm() > 0o750 {
			return alreadyBack("Compiler access"), nil
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

// undoFile puts back the UPDATES lines the apply changed in path and keeps
// every other line as it is now: cPanel rewrites the whole file when its
// update preferences are saved.
func undoFile(rec HardeningUndoRecord, path string) (string, error) {
	file := rec.File
	if file == nil || file.Path != path {
		return "", errUndoMismatch
	}
	prev := configLines(file.Previous)
	edits, ok := updatesEdits(prev, configLines(file.Applied))
	if !ok {
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
	what := cpUpdatesKey + " in " + path
	lines := configLines(string(data))
	if slices.Equal(settingValues(lines, updatesValue), settingValues(prev, updatesValue)) {
		return alreadyBack(what), nil
	}
	restored, err := restoreUpdatesLines(lines, edits, what)
	if err != nil {
		return "", err
	}
	if err := hardeningConfigWrite(path, info.Mode().Perm(), []byte(strings.Join(restored, "\n")+"\n")); err != nil {
		if rerr := atomicio.AtomicWrite(path, info.Mode().Perm(), data); rerr != nil {
			return "", errors.Join(err, fmt.Errorf("restoring applied configuration in %s failed: %w", path, rerr))
		}
		return "", err
	}
	return cpUpdatesKey + " restored in " + path + ".", nil
}

// configLines splits a config file into lines as setKeyValueFile does.
func configLines(content string) []string {
	return strings.Split(strings.TrimRight(content, "\n"), "\n")
}

func updatesValue(line string) (string, bool) { return keyValueLine(line, cpUpdatesKey) }

// updatesEdit identifies a setting line, including an unchanged first line.
// nth and total distinguish comments created by apply from identical comments
// that already existed. was is empty for a line the apply added.
type updatesEdit struct {
	wrote string
	nth   int
	total int
	was   string
}

// updatesEdits accepts only the transformation setKeyValueFile performs.
func updatesEdits(prev, applied []string) ([]updatesEdit, bool) {
	set := cpUpdatesKey + "=" + cpUpdatesValue
	expected := slices.Clone(prev)
	var edits []updatesEdit
	for i, line := range prev {
		if _, ok := updatesValue(line); !ok {
			continue
		}
		wrote := "# " + line
		if len(edits) == 0 {
			wrote = set
		}
		expected[i] = wrote
		edits = append(edits, updatesEdit{wrote: wrote, was: line})
	}
	if len(edits) == 0 {
		expected = append(expected, set)
		edits = append(edits, updatesEdit{wrote: set})
	}
	if !slices.Equal(expected, applied) {
		return nil, false
	}
	seen := map[string]int{}
	next := 0
	for i, line := range applied {
		active := false
		if i < len(prev) {
			_, active = updatesValue(prev[i])
		}
		if active || i == len(prev) {
			edits[next].nth = seen[line]
			next++
		}
		seen[line]++
	}
	for i := range edits {
		edits[i].total = seen[edits[i].wrote]
	}
	return edits, true
}

// restoreUpdatesLines keeps the original setting order even if only some
// comments survived a later save. Ambiguous identical comments are refused
// rather than enabling a comment that may have predated the apply.
func restoreUpdatesLines(lines []string, edits []updatesEdit, what string) ([]string, error) {
	first := -1
	counts := map[string]int{}
	for i, line := range lines {
		counts[line]++
		if v, ok := updatesValue(line); ok {
			if v != cpUpdatesValue {
				return nil, changedSince(what)
			}
			if first < 0 {
				first = i
			}
		}
	}
	if first < 0 {
		return nil, changedSince(what)
	}
	put := map[int][]string{first: nil}
	anchor := first
	for n, e := range edits {
		if n > 0 && counts[e.wrote] > 0 {
			if counts[e.wrote] != e.total {
				return nil, changedSince(what)
			}
			i := nthIndex(lines, e.wrote, e.nth)
			if i <= anchor {
				return nil, changedSince(what)
			}
			anchor = i
		}
		if e.was != "" {
			put[anchor] = append(put[anchor], e.was)
		}
	}
	out := make([]string, 0, len(lines)+len(edits))
	for i, line := range lines {
		if restored, ok := put[i]; ok {
			out = append(out, restored...)
		} else if _, active := updatesValue(line); !active {
			out = append(out, line)
		}
	}
	return out, nil
}

// nthIndex returns the index of the nth line equal to s, from 0, or -1.
func nthIndex(lines []string, s string, n int) int {
	for i, line := range lines {
		if line == s {
			if n == 0 {
				return i
			}
			n--
		}
	}
	return -1
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
	if cur.Mode == st.Mode && cur.UID == st.UID && cur.GID == st.GID {
		return alreadyBack("The owner and mode of " + st.Path), nil
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
	original := make([]appliedDropIn, len(rec.PHP))
	paths := make([]string, len(rec.PHP))
	back := true
	for i, p := range rec.PHP {
		snapshot, err := readUndoDropIn(p.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		original[i], paths[i] = snapshot, p.Path
		value := phpKeyValue(p.Key)
		back = back && slices.Equal(settingValues(strings.Split(string(snapshot.data), "\n"), value), settingValues(p.prevLines(), value))
	}
	if back {
		return alreadyBack(key + " in " + strings.Join(paths, ", ")), nil
	}
	restored := make([][]string, len(rec.PHP))
	for i, p := range rec.PHP {
		lines, err := restorePHPDropIn(p, string(original[i].data))
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
	// As on apply, a failed reload leaves the drop-ins and names what to
	// restart by hand.
	return key + " restored in " + strings.Join(phpDropInPaths(dirs), ", ") + ". " + reloadPHP(dirs), nil
}

// restorePHPDropIn returns the drop-in's lines with the key's earlier line
// back in place of the applied one.
func restorePHPDropIn(p phpUndoState, content string) ([]string, error) {
	return restoreKeyLines(content, p.Key+" in "+p.Path, p.Applied, p.prevLines(), phpKeyValue(p.Key))
}

// prevLines is the key's line in the drop-in before the apply, if any.
func (p phpUndoState) prevLines() []string {
	if p.HadKey {
		return []string{p.PrevLine}
	}
	return nil
}

// phpKeyValue picks out the drop-in lines that set key.
func phpKeyValue(key string) func(string) (string, bool) {
	return func(line string) (string, bool) {
		k, v, ok := phpIniSetting(line)
		return v, ok && k == key
	}
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
