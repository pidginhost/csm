package checks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"
)

// The root hardening worker keeps each applied fix's previous state in a
// directory only root can write, outside the daemon's writable paths. Undo
// requests carry only a fix name, so a daemon bug or compromise cannot make
// root write values of its choosing.

// hardeningUndoDir holds one <fix name>.json record per applied fix.
var hardeningUndoDir = "/var/lib/csm-hardening-undo"

// hardeningUndoOwner is the uid that must own hardeningUndoDir. Tests use
// their own uid.
var hardeningUndoOwner = 0

// HardeningUndoRecord is what one applied fix changed. Kind is ssh, sysctl,
// tweak, php, mode, compilers or file, and names the one state field set.
type HardeningUndoRecord struct {
	Name      string              `json:"name"`
	Category  string              `json:"category"`
	Kind      string              `json:"kind"`
	AppliedAt time.Time           `json:"applied_at"`
	SSH       *sshUndoState       `json:"ssh,omitempty"`
	Sysctl    *sysctlUndoState    `json:"sysctl,omitempty"`
	Tweak     *tweakUndoState     `json:"tweak,omitempty"`
	PHP       []phpUndoState      `json:"php,omitempty"`
	Mode      *modeUndoState      `json:"mode,omitempty"`
	Compilers *compilersUndoState `json:"compilers,omitempty"`
	File      *fileUndoState      `json:"file,omitempty"`
}

// sshUndoState is one keyword in CSM's sshd_config block. PrevValue is the
// block's value before the apply when HadValue; DisabledLines are the global
// lines the apply commented out, as they read before.
type sshUndoState struct {
	Keyword       string   `json:"keyword"`
	PrevValue     string   `json:"prev_value"`
	HadValue      bool     `json:"had_value"`
	AppliedValue  string   `json:"applied_value"`
	DisabledLines []string `json:"disabled_lines"`
}

// sysctlUndoState is one kernel key. PrevLines are the drop-in's lines for
// the key before the apply; RuntimeOnly means the runtime value was set but
// the drop-in write failed.
type sysctlUndoState struct {
	Key          string   `json:"key"`
	PrevRuntime  string   `json:"prev_runtime"`
	PrevLines    []string `json:"prev_lines"`
	AppliedValue string   `json:"applied_value"`
	RuntimeOnly  bool     `json:"runtime_only"`
}

// tweakUndoState is one WHM tweak setting.
type tweakUndoState struct {
	Key      string `json:"key"`
	Previous string `json:"previous"`
	Applied  string `json:"applied"`
}

// phpUndoState is one ini key in one CSM drop-in. PrevLine is the key's line
// before the apply when HadKey.
type phpUndoState struct {
	Path     string `json:"path"`
	Key      string `json:"key"`
	PrevLine string `json:"prev_line"`
	HadKey   bool   `json:"had_key"`
	Applied  string `json:"applied"`
}

// modeUndoState is the owner and mode of a tmp directory or the shadow file.
// Modes are st_mode permission bits (mask 07777).
type modeUndoState struct {
	Path        string `json:"path"`
	Mode        uint32 `json:"mode"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	AppliedMode uint32 `json:"applied_mode"`
	AppliedUID  uint32 `json:"applied_uid"`
	AppliedGID  uint32 `json:"applied_gid"`
}

// compilersUndoState is how compiler access was restricted. Method is
// "script" or "chmod"; the owner and modes, as in modeUndoState, are the
// resolved compiler's and matter only for chmod.
type compilersUndoState struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Mode        uint32 `json:"mode"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	AppliedMode uint32 `json:"applied_mode"`
	AppliedUID  uint32 `json:"applied_uid"`
	AppliedGID  uint32 `json:"applied_gid"`
}

// fileUndoState is a whole config file before and after the fix. The apply
// refuses a missing file, so there is no absent case.
type fileUndoState struct {
	Path     string `json:"path"`
	Previous string `json:"previous"`
	Applied  string `json:"applied"`
}

// knownHardeningFix reports whether the worker has a fix called name. It
// also keeps a record's file name to one plain path component.
func knownHardeningFix(name string) bool {
	if !hardeningCheckNamePattern.MatchString(name) {
		return false
	}
	switch name {
	case "os_shadow_permissions", "cp_compilers", "cp_updates":
		return true
	}
	_, ssh := sshFixDirectives[name]
	_, sysctl := sysctlFixes[name]
	_, tweak := cpTweakFixes[name]
	_, tmp := hardeningTmpDirs[name]
	_, _, php := phpFixFor(name)
	return ssh || sysctl || tweak || tmp || php
}

// openHardeningUndoDir opens the record directory once it is a root-owned
// 0700 directory and not a link. Only the worker creates it; when it is
// missing, readers get fs.ErrNotExist.
func openHardeningUndoDir(create bool) (*os.Root, error) {
	if create {
		if err := os.Mkdir(hardeningUndoDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	info, err := os.Lstat(hardeningUndoDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("%s must be a directory with mode 0700, not a link", hardeningUndoDir)
	}
	root, err := os.OpenRoot(hardeningUndoDir)
	if err != nil {
		return nil, err
	}
	if err := checkOpenedUndoDir(root, info); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

// checkOpenedUndoDir checks the opened directory, since the path can be
// swapped after the Lstat.
func checkOpenedUndoDir(root *os.Root, checked fs.FileInfo) error {
	opened, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(checked, opened) {
		return fmt.Errorf("%s changed while opening", hardeningUndoDir)
	}
	st, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != hardeningUndoOwner {
		return fmt.Errorf("%s is not owned by root", hardeningUndoDir)
	}
	return nil
}

// undoRecordInfo refuses a record file that is not a regular file, so no
// read or write goes through a link.
func undoRecordInfo(root *os.Root, file string) (fs.FileInfo, error) {
	info, err := root.Lstat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("undo record %s is not a regular file", file)
	}
	return info, nil
}

// writeHardeningUndo stores rec as the record for rec.Name, replacing an
// older one: the newest apply wins.
func writeHardeningUndo(rec HardeningUndoRecord) error {
	if !knownHardeningFix(rec.Name) {
		return fmt.Errorf("unknown hardening fix %q", rec.Name)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	root, err := openHardeningUndoDir(true)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	file := rec.Name + ".json"
	if _, err = undoRecordInfo(root, file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	tmp := "." + rec.Name + ".tmp"
	if err = root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// os.Root never follows a link when it creates a file exclusively.
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, file)
	}
	if err != nil {
		_ = root.Remove(tmp)
		return err
	}
	// Sync the directory so the rename survives a crash.
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// readHardeningUndo returns the record for name; ok is false when there is
// none.
func readHardeningUndo(name string) (HardeningUndoRecord, bool, error) {
	var rec HardeningUndoRecord
	data, err := readUndoRecordFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return rec, false, nil
	}
	if err == nil {
		err = json.Unmarshal(data, &rec)
	}
	if err == nil && rec.Name != name {
		err = fmt.Errorf("undo record for %s names %q", name, rec.Name)
	}
	if err != nil {
		return HardeningUndoRecord{}, false, err
	}
	return rec, true, nil
}

// readUndoRecordFile reads the record file for name without going through a
// link. It returns fs.ErrNotExist when there is no record.
func readUndoRecordFile(name string) ([]byte, error) {
	if !knownHardeningFix(name) {
		return nil, fmt.Errorf("unknown hardening fix %q", name)
	}
	root, err := openHardeningUndoDir(false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	file := name + ".json"
	info, err := undoRecordInfo(root, file)
	if err != nil {
		return nil, err
	}
	// os.Root follows links inside the root, so match the opened file to
	// the checked entry.
	f, err := root.OpenFile(file, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("undo record %s changed while opening", file)
	}
	return io.ReadAll(f)
}

// deleteHardeningUndo removes the record for name, if there is one.
func deleteHardeningUndo(name string) error {
	if !knownHardeningFix(name) {
		return fmt.Errorf("unknown hardening fix %q", name)
	}
	root, err := openHardeningUndoDir(false)
	if err == nil {
		err = root.Remove(name + ".json")
		_ = root.Close()
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// HardeningUndoNames lists the fixes that have an undo record. It only
// reads, so the sandboxed daemon can call it. Entries that are not a known
// fix's regular record file are ignored.
func HardeningUndoNames() ([]string, error) {
	root, err := openHardeningUndoDir(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if ok && e.Type().IsRegular() && knownHardeningFix(name) {
			names = append(names, name)
		}
	}
	return names, nil
}
