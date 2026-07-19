package checks

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Virtual patching for web-exposed files.
//
// A confirmed web_exposed_* finding means a visitor can download a sensitive
// file. Rather than delete the customer's file, CSM can write an .htaccess
// "Require all denied" rule that blocks HTTP access while leaving the file on
// disk (so the application, which reads it from the filesystem, keeps working).
//
// Every write records rollback metadata under the quarantine pre_clean dir so
// the existing /api/v1/quarantine-restore path can restore an existing file or
// remove one CSM created. Gating (off/manual/auto + dry_run) lives in callers.

// chownFunc is overridable in tests. It receives the already-open temporary
// file so ownership cannot be redirected through a path swap.
var chownFunc = func(file *os.File, uid, gid int) error {
	return file.Chown(uid, gid)
}

// virtualPatchBeforeCommitForTest simulates a customer or deploy process
// changing .htaccess between the initial read and the atomic commit.
var virtualPatchBeforeCommitForTest func(string, string)

const maxVirtualPatchHtaccessSize = 4 << 20

const (
	QuarantineRestoreReplaceIfUnchanged = "replace_if_unchanged"
	QuarantineRestoreRemoveIfUnchanged  = "remove_if_unchanged"
)

const (
	vpBeginFile = "# BEGIN CSM exposed-file virtual-patch"
	vpEndFile   = "# END CSM exposed-file virtual-patch"
	vpBeginDir  = "# BEGIN CSM exposed-file virtual-patch: deny directory"
	vpEndDir    = "# END CSM exposed-file virtual-patch: deny directory"
)

const virtualPatchAlreadyApplied = "already virtual-patched"

var ErrVirtualPatchRestoreConflict = errors.New("virtual-patch restore conflicts with current .htaccess")

var errVirtualPatchRollbackIncomplete = errors.New("virtual-patch rollback incomplete")

type htaccessState struct {
	content []byte
	info    os.FileInfo
	existed bool
	uid     int
	gid     int
	mode    os.FileMode
}

type virtualPatchBackup struct {
	itemPath string
	metaPath string
}

// vpExposedChecks are the web_exposed_* finding names eligible for virtual
// patching -- every web-reachable file class the detector reports.
var vpExposedChecks = map[string]bool{
	"web_exposed_config_leak":    true,
	"web_exposed_db_dump":        true,
	"web_exposed_sample_sql":     true,
	"web_exposed_backup_archive": true,
	"web_exposed_source_backup":  true,
	"web_exposed_phpinfo":        true,
}

func isVirtualPatchableExposedCheck(check string) bool { return vpExposedChecks[check] }

// VirtualPatchExposedFile writes an .htaccess "Require all denied" rule that
// blocks HTTP download of a confirmed web-exposed file without modifying the
// file itself. For an archive inside a known backup-plugin directory the whole
// directory is denied. Returns Success=false with an "already" error when the
// rule is already present (idempotent no-op).
func VirtualPatchExposedFile(filePath string) RemediationResult {
	resolved, targetInfo, err := resolveExistingFixPath(filePath, fixHtaccessAllowedRoots)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	if !targetInfo.Mode().IsRegular() {
		return RemediationResult{Error: "virtual-patch target is not a regular file"}
	}
	name := filepath.Base(resolved)
	dir := filepath.Dir(resolved)
	dirDeny := isKnownBackupPluginDir(dir)

	if !dirDeny {
		if nameErr := validDenyName(name); nameErr != nil {
			return RemediationResult{Error: nameErr.Error()}
		}
	}

	htaccess := filepath.Join(dir, ".htaccess")
	if _, sanitizeErr := sanitizeFixPath(htaccess, fixHtaccessAllowedRoots); sanitizeErr != nil {
		return RemediationResult{Error: sanitizeErr.Error()}
	}

	state, err := readHtaccessState(htaccess, dir)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	marker := vpBeginFile + " " + name
	if dirDeny {
		marker = vpBeginDir
	}
	if state.existed && containsLine(state.content, marker) {
		return RemediationResult{Error: virtualPatchAlreadyApplied}
	}

	block := buildDenyBlock(name, dirDeny)
	newContent := block
	if state.existed {
		newContent = append(ensureTrailingNewline(state.content), block...)
	}
	if len(newContent) > maxVirtualPatchHtaccessSize {
		return RemediationResult{Error: fmt.Sprintf("refusing patched .htaccess larger than %d bytes", maxVirtualPatchHtaccessSize)}
	}

	backup, err := backupHtaccessBeforePatch(htaccess, state, newContent)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	keepBackup := false
	defer func() {
		if !keepBackup {
			backup.remove()
		}
	}()

	tmp, tempState, err := writeVirtualPatchTemp(dir, newContent, state)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	if virtualPatchBeforeCommitForTest != nil {
		virtualPatchBeforeCommitForTest(htaccess, tmp)
	}
	if err := commitVirtualPatchTemp(tmp, htaccess, state, tempState); err != nil {
		removeVirtualPatchTemp(tmp, tempState)
		if errors.Is(err, errVirtualPatchRollbackIncomplete) {
			keepBackup = true
		}
		return RemediationResult{Error: err.Error()}
	}
	keepBackup = true

	target := name
	if dirDeny {
		target = filepath.Base(dir) + "/ (whole directory)"
	}
	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("denied HTTP access to %s", target),
		Description: fmt.Sprintf("Wrote Require all denied for %s in %s", target, htaccess),
	}
}

// validDenyName rejects file names that could break out of the quoted
// <Files "..."> argument and inject arbitrary .htaccess directives.
func validDenyName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("empty file name")
	}
	if strings.ContainsAny(name, "\"\n\r<>\\*?[]${}") || strings.HasPrefix(strings.TrimLeft(name, " \t"), "#") {
		return fmt.Errorf("file name %q contains characters unsafe for an .htaccess directive", name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("file name %q contains control characters unsafe for an .htaccess directive", name)
		}
	}
	return nil
}

func buildDenyBlock(name string, dirDeny bool) []byte {
	if dirDeny {
		return []byte(fmt.Sprintf("%s\n<FilesMatch \"^\">\nRequire all denied\n</FilesMatch>\n%s\n", vpBeginDir, vpEndDir))
	}
	return []byte(fmt.Sprintf("%s %s\n<Files \"%s\">\nRequire all denied\n</Files>\n%s %s\n",
		vpBeginFile, name, name, vpEndFile, name))
}

func isKnownBackupPluginDir(dir string) bool {
	base := strings.ToLower(filepath.Base(dir))
	switch base {
	case "ai1wm-backups", "wpvividbackups", "updraft":
		return strings.EqualFold(filepath.Base(filepath.Dir(dir)), "wp-content")
	default:
		return false
	}
}

func containsLine(content []byte, line string) bool {
	for _, l := range strings.Split(string(content), "\n") {
		if strings.TrimRight(l, "\r") == line {
			return true
		}
	}
	return false
}

func ensureTrailingNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] != '\n' {
		return append(b, '\n')
	}
	return b
}

func readHtaccessState(htaccess, dir string) (htaccessState, error) {
	info, err := os.Lstat(htaccess)
	if err != nil {
		if !os.IsNotExist(err) {
			return htaccessState{}, fmt.Errorf("inspecting .htaccess: %v", err)
		}
		dirInfo, statErr := os.Stat(dir)
		if statErr != nil {
			return htaccessState{}, fmt.Errorf("inspecting target directory: %v", statErr)
		}
		uid, gid, ownerErr := ownerFromInfo(dirInfo)
		if ownerErr != nil {
			return htaccessState{}, ownerErr
		}
		return htaccessState{uid: uid, gid: gid, mode: 0644}, nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return htaccessState{}, fmt.Errorf("refusing symlinked .htaccess: %s", htaccess)
	}
	if !info.Mode().IsRegular() {
		return htaccessState{}, fmt.Errorf("refusing non-regular .htaccess: %s", htaccess)
	}
	if info.Size() > maxVirtualPatchHtaccessSize {
		return htaccessState{}, fmt.Errorf("refusing .htaccess larger than %d bytes", maxVirtualPatchHtaccessSize)
	}

	// #nosec G304 -- htaccess is under the resolved and validated target dir;
	// O_NOFOLLOW rejects a path swap to a symlink.
	file, err := os.OpenFile(htaccess, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return htaccessState{}, fmt.Errorf("opening .htaccess: %v", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return htaccessState{}, fmt.Errorf("stating .htaccess: %v", err)
	}
	if !os.SameFile(info, openedInfo) {
		return htaccessState{}, fmt.Errorf(".htaccess changed while preparing virtual-patch")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxVirtualPatchHtaccessSize+1))
	if err != nil {
		return htaccessState{}, fmt.Errorf("reading .htaccess: %v", err)
	}
	if len(content) > maxVirtualPatchHtaccessSize {
		return htaccessState{}, fmt.Errorf("refusing .htaccess larger than %d bytes", maxVirtualPatchHtaccessSize)
	}
	uid, gid, err := ownerFromInfo(openedInfo)
	if err != nil {
		return htaccessState{}, err
	}
	return htaccessState{
		content: content,
		info:    openedInfo,
		existed: true,
		uid:     uid,
		gid:     gid,
		mode:    openedInfo.Mode().Perm(),
	}, nil
}

func ownerFromInfo(info os.FileInfo) (int, int, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("cannot determine filesystem owner")
	}
	return int(st.Uid), int(st.Gid), nil
}

func writeVirtualPatchTemp(dir string, content []byte, state htaccessState) (string, htaccessState, error) {
	tmp, err := os.CreateTemp(dir, ".htaccess.csm-vpatch-*")
	if err != nil {
		return "", htaccessState{}, fmt.Errorf("creating temporary .htaccess: %v", err)
	}
	tmpPath := tmp.Name()
	remove := true
	defer func() {
		_ = tmp.Close()
		if remove {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, writeErr := tmp.Write(content); writeErr != nil {
		return "", htaccessState{}, fmt.Errorf("writing temporary .htaccess: %v", writeErr)
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		return "", htaccessState{}, fmt.Errorf("syncing temporary .htaccess: %v", syncErr)
	}
	if chownErr := chownFunc(tmp, state.uid, state.gid); chownErr != nil {
		return "", htaccessState{}, fmt.Errorf("setting owner on temporary .htaccess: %v", chownErr)
	}
	if chmodErr := tmp.Chmod(state.mode); chmodErr != nil {
		return "", htaccessState{}, fmt.Errorf("setting mode on temporary .htaccess: %v", chmodErr)
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		return "", htaccessState{}, fmt.Errorf("syncing temporary .htaccess metadata: %v", syncErr)
	}
	tmpInfo, err := tmp.Stat()
	if err != nil {
		return "", htaccessState{}, fmt.Errorf("stating temporary .htaccess: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return "", htaccessState{}, fmt.Errorf("closing temporary .htaccess: %v", err)
	}
	remove = false
	return tmpPath, htaccessState{
		content: append([]byte(nil), content...),
		info:    tmpInfo,
		existed: true,
		uid:     state.uid,
		gid:     state.gid,
		mode:    state.mode,
	}, nil
}

func htaccessStateMatchesPath(path string, state htaccessState) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf(".htaccess path is no longer a regular file")
	}
	if state.info == nil || !os.SameFile(state.info, info) {
		return fmt.Errorf(".htaccess inode changed")
	}
	// #nosec G304 -- path is either the validated .htaccess or its randomized
	// same-directory staging name; O_NOFOLLOW and the repeated inode check keep
	// a path swap from redirecting the read.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, openedInfo) || !os.SameFile(state.info, openedInfo) {
		return fmt.Errorf(".htaccess inode changed")
	}
	uid, gid, err := ownerFromInfo(openedInfo)
	if err != nil {
		return err
	}
	if uid != state.uid || gid != state.gid || openedInfo.Mode().Perm() != state.mode.Perm() {
		return fmt.Errorf(".htaccess ownership or mode changed")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxVirtualPatchHtaccessSize+1))
	if err != nil {
		return err
	}
	if len(content) > maxVirtualPatchHtaccessSize {
		return fmt.Errorf(".htaccess content exceeds validation limit")
	}
	if !bytes.Equal(content, state.content) {
		return fmt.Errorf(".htaccess content changed")
	}
	return nil
}

func removeVirtualPatchTemp(path string, state htaccessState) {
	if htaccessStateMatchesPath(path, state) == nil {
		_ = os.Remove(path)
	}
}

// backupHtaccessBeforePatch records both the pre-patch content and the exact
// expected post-patch hash. Restore can then replace or remove .htaccess only
// while it still matches the version CSM wrote, preserving later user edits.
func backupHtaccessBeforePatch(htaccess string, state htaccessState, patched []byte) (virtualPatchBackup, error) {
	if err := os.MkdirAll(htaccessBackupDirRoot, 0750); err != nil {
		return virtualPatchBackup{}, fmt.Errorf("creating backup dir: %v", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	pathSum := sha256.Sum256([]byte(htaccess))
	backupFile, err := os.CreateTemp(htaccessBackupDirRoot, fmt.Sprintf("%s_vpatch_%x_", stamp, pathSum[:6]))
	if err != nil {
		return virtualPatchBackup{}, fmt.Errorf("creating backup: %v", err)
	}
	backup := virtualPatchBackup{itemPath: backupFile.Name(), metaPath: backupFile.Name() + ".meta"}
	keep := false
	defer func() {
		_ = backupFile.Close()
		if !keep {
			backup.remove()
		}
	}()
	if state.existed {
		if _, writeErr := backupFile.Write(state.content); writeErr != nil {
			return virtualPatchBackup{}, fmt.Errorf("writing backup: %v", writeErr)
		}
	}
	if chmodErr := backupFile.Chmod(0640); chmodErr != nil {
		return virtualPatchBackup{}, fmt.Errorf("setting backup mode: %v", chmodErr)
	}
	if syncErr := backupFile.Sync(); syncErr != nil {
		return virtualPatchBackup{}, fmt.Errorf("syncing backup: %v", syncErr)
	}
	if closeErr := backupFile.Close(); closeErr != nil {
		return virtualPatchBackup{}, fmt.Errorf("closing backup: %v", closeErr)
	}
	restoreAction := QuarantineRestoreReplaceIfUnchanged
	if !state.existed {
		restoreAction = QuarantineRestoreRemoveIfUnchanged
	}
	metaJSON, err := json.Marshal(QuarantineMeta{
		OriginalPath:          htaccess,
		Owner:                 state.uid,
		Group:                 state.gid,
		Mode:                  state.mode.String(),
		Size:                  int64(len(state.content)),
		QuarantineAt:          time.Now().UTC(),
		Reason:                "exposed-file virtual-patch: pre-patch .htaccess backup",
		RestoreAction:         restoreAction,
		ExpectedCurrentSHA256: virtualPatchSHA256(patched),
	})
	if err != nil {
		return virtualPatchBackup{}, fmt.Errorf("encoding backup meta: %v", err)
	}
	metaFile, err := os.OpenFile(backup.metaPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return virtualPatchBackup{}, fmt.Errorf("creating backup meta: %v", err)
	}
	if _, err := metaFile.Write(metaJSON); err != nil {
		_ = metaFile.Close()
		return virtualPatchBackup{}, fmt.Errorf("writing backup meta: %v", err)
	}
	if err := metaFile.Sync(); err != nil {
		_ = metaFile.Close()
		return virtualPatchBackup{}, fmt.Errorf("syncing backup meta: %v", err)
	}
	if err := metaFile.Close(); err != nil {
		return virtualPatchBackup{}, fmt.Errorf("closing backup meta: %v", err)
	}
	keep = true
	return backup, nil
}

func (backup virtualPatchBackup) remove() {
	if backup.metaPath != "" {
		_ = os.Remove(backup.metaPath)
	}
	if backup.itemPath != "" {
		_ = os.Remove(backup.itemPath)
	}
}

func virtualPatchSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("sha256:%x", sum[:])
}

// RestoreVirtualPatchBackup reverts a virtual-patch only when the live
// .htaccess still has the exact content recorded after enforcement. This keeps
// quarantine restore from overwriting customer edits made after the patch.
func RestoreVirtualPatchBackup(backupPath, htaccess string, meta QuarantineMeta) error {
	if filepath.Base(htaccess) != ".htaccess" {
		return fmt.Errorf("virtual-patch restore applies only to .htaccess")
	}
	if meta.RestoreAction != QuarantineRestoreReplaceIfUnchanged &&
		meta.RestoreAction != QuarantineRestoreRemoveIfUnchanged {
		return fmt.Errorf("unsupported virtual-patch restore action %q", meta.RestoreAction)
	}
	mode, err := parseVirtualPatchMode(meta.Mode)
	if err != nil {
		return err
	}
	state, err := readHtaccessState(htaccess, filepath.Dir(htaccess))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, err)
	}
	if !state.existed || virtualPatchSHA256(state.content) != meta.ExpectedCurrentSHA256 ||
		state.uid != meta.Owner || state.gid != meta.Group || state.mode.Perm() != mode.Perm() {
		return fmt.Errorf("%w: live file was modified after enforcement", ErrVirtualPatchRestoreConflict)
	}

	if meta.RestoreAction == QuarantineRestoreRemoveIfUnchanged {
		if removeErr := removeVirtualPatchIfUnchanged(htaccess, state); removeErr != nil {
			return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, removeErr)
		}
		return nil
	}

	// #nosec G304 -- backupPath is resolved by the quarantine handler beneath
	// quarantineDir/pre_clean; O_NOFOLLOW rejects a replaced sidecar item.
	backupInfo, err := os.Lstat(backupPath)
	if err != nil {
		return fmt.Errorf("inspecting virtual-patch backup: %v", err)
	}
	if backupInfo.Mode()&os.ModeSymlink != 0 || !backupInfo.Mode().IsRegular() {
		return fmt.Errorf("virtual-patch backup is not a regular file")
	}
	backup, err := os.OpenFile(backupPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- validated pre_clean item; O_NOFOLLOW and inode checks reject swaps
	if err != nil {
		return fmt.Errorf("opening virtual-patch backup: %v", err)
	}
	openedBackupInfo, err := backup.Stat()
	if err != nil || !os.SameFile(backupInfo, openedBackupInfo) || !openedBackupInfo.Mode().IsRegular() {
		_ = backup.Close()
		return fmt.Errorf("virtual-patch backup changed while opening")
	}
	backupContent, readErr := io.ReadAll(io.LimitReader(backup, maxVirtualPatchHtaccessSize+1))
	closeErr := backup.Close()
	if readErr != nil {
		return fmt.Errorf("reading virtual-patch backup: %v", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing virtual-patch backup: %v", closeErr)
	}
	if len(backupContent) > maxVirtualPatchHtaccessSize {
		return fmt.Errorf("virtual-patch backup exceeds %d bytes", maxVirtualPatchHtaccessSize)
	}
	restoreState := htaccessState{uid: meta.Owner, gid: meta.Group, mode: mode.Perm()}
	tmp, tempState, err := writeVirtualPatchTemp(filepath.Dir(htaccess), backupContent, restoreState)
	if err != nil {
		return err
	}
	if err := commitVirtualPatchTemp(tmp, htaccess, state, tempState); err != nil {
		removeVirtualPatchTemp(tmp, tempState)
		return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, err)
	}
	return nil
}

func parseVirtualPatchMode(value string) (os.FileMode, error) {
	if len(value) != 10 || value[0] != '-' {
		return 0, fmt.Errorf("invalid virtual-patch mode %q", value)
	}
	perms := value[1:]
	wantChars := "rwxrwxrwx"
	bits := []os.FileMode{0400, 0200, 0100, 0040, 0020, 0010, 0004, 0002, 0001}
	var mode os.FileMode
	for i, char := range perms {
		if char == '-' {
			continue
		}
		if char != rune(wantChars[i]) {
			return 0, fmt.Errorf("invalid virtual-patch mode %q", value)
		}
		mode |= bits[i]
	}
	return mode, nil
}

// VirtualPatchExposedFindings applies (apply=true) or previews (apply=false) a
// deny rule for each virtual-patchable web_exposed_* finding, deduplicated by
// path. It returns one auto_response action finding per file.
func VirtualPatchExposedFindings(_ *config.Config, findings []alert.Finding, apply bool) []alert.Finding {
	var actions []alert.Finding
	seen := make(map[string]struct{})
	for _, f := range findings {
		if !isVirtualPatchableExposedCheck(f.Check) {
			continue
		}
		path := f.FilePath
		if path == "" {
			path = extractFilePath(f.Message)
		}
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}

		if !apply {
			details := "Enable auto_response.virtual_patch_exposed_files=auto with dry_run:false, or run `csm virtual-patch --apply`, to write the deny rule."
			if f.Check == "web_exposed_sample_sql" {
				details = "Warning-only sample SQL is never enforced automatically; run `csm virtual-patch --apply` to write the deny rule."
			}
			actions = append(actions, alert.Finding{
				Severity:  alert.Warning,
				Check:     "auto_response",
				Message:   fmt.Sprintf("VIRTUAL-PATCH (preview): would deny HTTP access to %s", path),
				Details:   details,
				Timestamp: time.Now(),
			})
			continue
		}

		res := VirtualPatchExposedFile(path)
		switch {
		case res.Success:
			actions = append(actions, alert.Finding{
				Severity:  alert.Critical,
				Check:     "auto_response",
				Message:   fmt.Sprintf("VIRTUAL-PATCH: denied HTTP access to %s", path),
				Details:   res.Description,
				Timestamp: time.Now(),
			})
		case res.Error != "" && res.Error != virtualPatchAlreadyApplied:
			actions = append(actions, alert.Finding{
				Severity:  alert.Warning,
				Check:     "auto_response",
				Message:   fmt.Sprintf("VIRTUAL-PATCH failed: %s", path),
				Details:   res.Error,
				Timestamp: time.Now(),
			})
		}
	}
	return actions
}

// AutoVirtualPatchExposedFiles is the scan-time entry point. It acts only when
// auto_response is enabled and the mode is "auto"; the write is gated by the
// shared auto_response dry_run flag (dry_run reports the intended denials).
func AutoVirtualPatchExposedFiles(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if cfg == nil || !cfg.AutoResponse.Enabled || cfg.VirtualPatchMode() != config.VirtualPatchAuto {
		return nil
	}
	autoEligible := make([]alert.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Check != "web_exposed_sample_sql" {
			autoEligible = append(autoEligible, finding)
		}
	}
	return VirtualPatchExposedFindings(cfg, autoEligible, !cfg.AutoResponseDryRunEnabled())
}
