package checks

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
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

var hardeningUndoSync = (*os.File).Sync

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
func openHardeningUndoDir(create bool) (*os.File, error) {
	parent, err := os.OpenFile(filepath.Dir(hardeningUndoDir), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	name := filepath.Base(hardeningUndoDir)
	if create {
		if err = unix.Mkdirat(int(parent.Fd()), name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	dir, err := openUndoFile(parent, name, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	if err := checkOpenedUndoDir(dir); err != nil {
		_ = dir.Close()
		return nil, err
	}
	// Sync even when another writer created the directory: its mkdir may
	// not have reached stable storage yet.
	if create {
		if err := hardeningUndoSync(parent); err != nil {
			_ = dir.Close()
			return nil, err
		}
	}
	return dir, nil
}

// The directory handle pins all operations to the inode whose permissions
// we checked. O_NOFOLLOW refuses links at open time, including racing swaps.
func openUndoFile(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name)), nil
}

func checkOpenedUndoDir(dir *os.File) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return err
	}
	if st.Mode&(unix.S_IFMT|0o7777) != unix.S_IFDIR|0o700 || int(st.Uid) != hardeningUndoOwner {
		return fmt.Errorf("%s must be a root-owned directory with mode 0700", hardeningUndoDir)
	}
	return nil
}

func checkUndoRecordStat(st *unix.Stat_t) error {
	if st.Mode&(unix.S_IFMT|0o7777) != unix.S_IFREG|0o600 || int(st.Uid) != hardeningUndoOwner {
		return errors.New("undo record must be a root-owned regular file with mode 0600")
	}
	return nil
}

func undoRecordInfo(dir *os.File, file string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), file, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	return checkUndoRecordStat(&st)
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
	if err = undoRecordInfo(root, file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Writers must never remove or publish another writer's staging file.
	tmp := "." + rec.Name + "." + rand.Text() + ".tmp"
	f, err := openUndoFile(root, tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = hardeningUndoSync(f)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(int(root.Fd()), tmp, int(root.Fd()), file)
	}
	if err != nil {
		_ = unix.Unlinkat(int(root.Fd()), tmp, 0)
		return err
	}
	// Sync the directory so the rename survives a crash.
	return hardeningUndoSync(root)
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
	f, err := openUndoFile(root, file, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, err
	}
	if err := checkUndoRecordStat(&st); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// deleteHardeningUndo removes the record for name, if there is one.
func deleteHardeningUndo(name string) error {
	if !knownHardeningFix(name) {
		return fmt.Errorf("unknown hardening fix %q", name)
	}
	root, err := openHardeningUndoDir(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	if err := unix.Unlinkat(int(root.Fd()), name+".json", 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Also sync a retry after an earlier unlink whose sync failed.
	return hardeningUndoSync(root)
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
	entries, err := root.ReadDir(-1)
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
	slices.Sort(names)
	return names, nil
}
