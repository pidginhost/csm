package store

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	bolt "go.etcd.io/bbolt"
)

// ArchiveSchemaVersion is the on-wire schema for backup archives. Bump
// when the manifest layout or contents shape changes incompatibly. Old
// CSM binaries refuse archives newer than the version they understand.
const ArchiveSchemaVersion = 1

// Standard entry names inside the tar.
const (
	manifestEntry      = "manifest.json"
	bboltSnapshotEntry = "bbolt.snapshot"
	stateEntryPrefix   = "state/"
	rulesEntryPrefix   = "rules/"
)

// Sentinel errors so callers can branch on the failure mode instead of
// matching strings.
var (
	ErrSchemaVersionTooNew = errors.New("archive schema version is newer than this binary supports")
	ErrPlatformMismatch    = errors.New("archive source platform does not match current host")
	ErrManifestMissing     = errors.New("archive does not contain manifest.json")
	ErrCorruptArchive      = errors.New("archive is corrupt or not a CSM backup")
)

// Manifest is the JSON header at the top of every archive.
type Manifest struct {
	SchemaVersion  int               `json:"schema_version"`
	CSMVersion     string            `json:"csm_version"`
	SourceHostname string            `json:"source_hostname"`
	SourcePlatform map[string]string `json:"source_platform"`
	ExportTS       time.Time         `json:"export_ts"`
	Contents       []string          `json:"contents"`
	BboltBuckets   []string          `json:"bbolt_buckets,omitempty"`
	BboltSHA256    string            `json:"bbolt_sha256,omitempty"`
}

// ExportOptions configures Export.
type ExportOptions struct {
	StatePath string   // /opt/csm/state, source for state JSON files
	RulesPath string   // /opt/csm/rules, source for signature cache (empty -> skip)
	DstPath   string   // .csmbak file to create
	Manifest  Manifest // caller fills CSMVersion/SourceHostname/SourcePlatform; rest filled here
}

// ExportResult summarises a successful export.
type ExportResult struct {
	Path          string
	Bytes         int64
	ArchiveSHA256 string
	BboltSHA256   string
}

// ImportOptions configures Import.
type ImportOptions struct {
	SrcPath               string
	StatePath             string
	RulesPath             string
	Only                  string // "all" | "baseline" | "firewall"
	ForcePlatformMismatch bool
	CurrentPlatform       map[string]string // for the mismatch check
}

// ImportResult summarises a successful import.
type ImportResult struct {
	Manifest        Manifest
	BucketsRestored []string
	StateFiles      int
	RulesFiles      int
}

// Export writes a tar+zstd archive containing a bbolt snapshot, the
// state directory, and (optionally) the signature-rules directory. The
// daemon is the single source of truth for paths; the caller fills the
// manifest with hostname/version/platform.
func (db *DB) Export(opts ExportOptions) (*ExportResult, error) {
	if opts.DstPath == "" {
		return nil, errors.New("DstPath is empty")
	}
	if opts.StatePath == "" {
		return nil, errors.New("StatePath is empty")
	}

	man := opts.Manifest
	if man.SchemaVersion == 0 {
		man.SchemaVersion = ArchiveSchemaVersion
	}
	if man.ExportTS.IsZero() {
		man.ExportTS = time.Now().UTC()
	}
	man.Contents = []string{"bbolt", "state"}
	if opts.RulesPath != "" {
		man.Contents = append(man.Contents, "rules")
	}
	man.BboltBuckets = listBuckets(db)

	// Snapshot bbolt to a temp file in the same directory so we can hash it
	// and stream it into the tar without holding a long bolt transaction.
	snapDir := filepath.Dir(opts.DstPath)
	snap, err := os.CreateTemp(snapDir, "csm-export-bbolt-*.snap")
	if err != nil {
		return nil, fmt.Errorf("creating bbolt snapshot temp: %w", err)
	}
	snapPath := snap.Name()
	defer os.Remove(snapPath)

	bboltHash := sha256.New()
	err = db.bolt.View(func(tx *bolt.Tx) error {
		_, werr := tx.WriteTo(io.MultiWriter(snap, bboltHash))
		return werr
	})
	if err != nil {
		_ = snap.Close()
		return nil, fmt.Errorf("bbolt snapshot: %w", err)
	}
	if err = snap.Close(); err != nil {
		return nil, fmt.Errorf("closing bbolt snapshot: %w", err)
	}
	man.BboltSHA256 = hex.EncodeToString(bboltHash.Sum(nil))

	// Build the archive on disk; hash it as we write. Close is called
	// explicitly below so any close error after fsync is surfaced --
	// silently dropping it would mean the operator gets "export
	// succeeded" for a file that may not be fully persisted.
	out, err := os.OpenFile(opts.DstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("creating archive: %w", err)
	}
	// closed gates the deferred Close so the explicit Close below
	// can return its error without a double-close. success gates the
	// cleanup of the partial archive + companion file: any
	// error-return path between OpenFile and the final return removes
	// the half-written files so the operator does not mistake them
	// for a usable backup.
	closed := false
	success := false
	defer func() {
		if !closed {
			_ = out.Close()
		}
		if !success {
			_ = os.Remove(opts.DstPath)
			_ = os.Remove(opts.DstPath + ".sha256")
		}
	}()

	archHash := sha256.New()
	mw := io.MultiWriter(out, archHash)
	zw, err := zstd.NewWriter(mw, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, fmt.Errorf("zstd writer: %w", err)
	}
	tw := tar.NewWriter(zw)

	// 1. manifest first so a streaming reader sees schema info before payload.
	manBytes, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	if err = writeTarFile(tw, manifestEntry, manBytes, man.ExportTS); err != nil {
		return nil, err
	}

	// 2. bbolt snapshot (already on disk).
	if err = streamFileToTar(tw, bboltSnapshotEntry, snapPath, man.ExportTS); err != nil {
		return nil, err
	}

	// 3. state files (skip the bbolt file itself, which is captured in step 2).
	if _, err = walkDirIntoTar(tw, opts.StatePath, stateEntryPrefix, []string{"csm.db"}, man.ExportTS); err != nil {
		return nil, err
	}

	// 4. rules files (optional).
	if opts.RulesPath != "" {
		if _, err = walkDirIntoTar(tw, opts.RulesPath, rulesEntryPrefix, nil, man.ExportTS); err != nil {
			return nil, err
		}
	}

	if err = tw.Close(); err != nil {
		return nil, fmt.Errorf("closing tar: %w", err)
	}
	if err = zw.Close(); err != nil {
		return nil, fmt.Errorf("closing zstd: %w", err)
	}
	if err = out.Sync(); err != nil {
		return nil, fmt.Errorf("fsync archive: %w", err)
	}
	if err = out.Close(); err != nil {
		return nil, fmt.Errorf("closing archive: %w", err)
	}
	closed = true

	info, err := os.Stat(opts.DstPath)
	if err != nil {
		return nil, fmt.Errorf("stat archive: %w", err)
	}
	archiveSHA := hex.EncodeToString(archHash.Sum(nil))

	// Write companion .sha256 file alongside for operator verification.
	companion := opts.DstPath + ".sha256"
	companionLine := fmt.Sprintf("%s  %s\n", archiveSHA, filepath.Base(opts.DstPath))
	if err = os.WriteFile(companion, []byte(companionLine), 0600); err != nil {
		return nil, fmt.Errorf("writing companion sha256: %w", err)
	}

	success = true
	return &ExportResult{
		Path:          opts.DstPath,
		Bytes:         info.Size(),
		ArchiveSHA256: archiveSHA,
		BboltSHA256:   man.BboltSHA256,
	}, nil
}

// Import unpacks an archive into the target state and rules paths. Live
// daemons must be stopped first; callers enforce that before invoking.
func Import(opts ImportOptions) (*ImportResult, error) {
	if opts.SrcPath == "" {
		return nil, errors.New("SrcPath is empty")
	}
	if opts.StatePath == "" {
		return nil, errors.New("StatePath is empty")
	}
	only := opts.Only
	if only == "" {
		only = "all"
	}
	switch only {
	case "all", "baseline", "firewall":
	default:
		return nil, fmt.Errorf("invalid Only value %q (want all|baseline|firewall)", only)
	}

	in, err := os.Open(opts.SrcPath)
	if err != nil {
		return nil, fmt.Errorf("opening archive: %w", err)
	}
	defer in.Close()

	zr, err := zstd.NewReader(in)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptArchive, err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)

	// Manifest must come first.
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("%w: reading first entry: %v", ErrCorruptArchive, err)
	}
	if hdr.Name != manifestEntry {
		return nil, fmt.Errorf("%w: first entry is %q, want %q", ErrManifestMissing, hdr.Name, manifestEntry)
	}
	manBytes, err := io.ReadAll(tr)
	if err != nil {
		return nil, fmt.Errorf("%w: reading manifest: %v", ErrCorruptArchive, err)
	}
	var man Manifest
	if err = json.Unmarshal(manBytes, &man); err != nil {
		return nil, fmt.Errorf("%w: parsing manifest: %v", ErrCorruptArchive, err)
	}

	if man.SchemaVersion > ArchiveSchemaVersion {
		return nil, fmt.Errorf("%w: archive=%d binary=%d", ErrSchemaVersionTooNew, man.SchemaVersion, ArchiveSchemaVersion)
	}
	if !opts.ForcePlatformMismatch && !platformMatches(man.SourcePlatform, opts.CurrentPlatform) {
		return nil, fmt.Errorf("%w: archive=%v current=%v (use --force-platform-mismatch to override)", ErrPlatformMismatch, man.SourcePlatform, opts.CurrentPlatform)
	}

	// Stage every payload into a temp dir; commit only after a complete
	// successful read so a half-imported state is impossible.
	stage, err := os.MkdirTemp(filepath.Dir(opts.StatePath), "csm-import-stage-*")
	if err != nil {
		return nil, fmt.Errorf("creating staging dir: %w", err)
	}
	defer os.RemoveAll(stage)

	stagedBbolt := ""
	stagedState := []string{}
	stagedRules := []string{}

	for {
		nextHdr, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nil, fmt.Errorf("%w: reading entry: %v", ErrCorruptArchive, nextErr)
		}
		if nextHdr.Typeflag != tar.TypeReg {
			continue
		}
		clean := filepath.Clean(nextHdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return nil, fmt.Errorf("%w: unsafe entry name %q", ErrCorruptArchive, nextHdr.Name)
		}
		dst := filepath.Join(stage, clean)
		if mkErr := os.MkdirAll(filepath.Dir(dst), 0700); mkErr != nil {
			return nil, fmt.Errorf("staging dir: %w", mkErr)
		}
		f, openErr := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if openErr != nil {
			return nil, fmt.Errorf("staging file: %w", openErr)
		}
		// nextHdr.Size bound caps bytes copied so a hostile archive can't
		// drive the stage dir to fill the filesystem.
		if _, copyErr := io.CopyN(f, tr, nextHdr.Size); copyErr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("staging copy %s: %w", clean, copyErr)
		}
		if closeErr := f.Close(); closeErr != nil {
			return nil, fmt.Errorf("closing staged file: %w", closeErr)
		}
		switch {
		case clean == bboltSnapshotEntry:
			stagedBbolt = dst
		case strings.HasPrefix(clean, stateEntryPrefix):
			stagedState = append(stagedState, clean)
		case strings.HasPrefix(clean, rulesEntryPrefix):
			stagedRules = append(stagedRules, clean)
		}
	}

	res := &ImportResult{Manifest: man}

	// Apply state files (always, unless caller filtered everything out).
	if only == "all" || only == "baseline" {
		if err := os.MkdirAll(opts.StatePath, 0700); err != nil {
			return nil, fmt.Errorf("creating state path: %w", err)
		}
		for _, rel := range stagedState {
			src := filepath.Join(stage, rel)
			dst := filepath.Join(opts.StatePath, strings.TrimPrefix(rel, stateEntryPrefix))
			if err := atomicReplace(src, dst); err != nil {
				return nil, fmt.Errorf("restoring %s: %w", rel, err)
			}
			res.StateFiles++
		}
	}

	// Apply rules files (only=all only; baseline and firewall skip rules).
	if only == "all" && opts.RulesPath != "" {
		if err := os.MkdirAll(opts.RulesPath, 0700); err != nil {
			return nil, fmt.Errorf("creating rules path: %w", err)
		}
		for _, rel := range stagedRules {
			src := filepath.Join(stage, rel)
			dst := filepath.Join(opts.RulesPath, strings.TrimPrefix(rel, rulesEntryPrefix))
			if err := atomicReplace(src, dst); err != nil {
				return nil, fmt.Errorf("restoring %s: %w", rel, err)
			}
			res.RulesFiles++
		}
	}

	// Apply bbolt:
	//   only=all      -> wholesale rename the snapshot over csm.db
	//   only=firewall -> open snapshot read-only and copy fw:* buckets
	//                    into the target bbolt
	//   only=baseline -> skip bbolt entirely
	switch only {
	case "all":
		if stagedBbolt != "" {
			target := filepath.Join(opts.StatePath, "csm.db")
			if err := atomicReplace(stagedBbolt, target); err != nil {
				return nil, fmt.Errorf("restoring csm.db: %w", err)
			}
			// Report every bucket that came from the snapshot.
			res.BucketsRestored = append([]string(nil), man.BboltBuckets...)
		}
	case "firewall":
		if stagedBbolt == "" {
			return nil, fmt.Errorf("%w: firewall import needs bbolt snapshot in archive", ErrCorruptArchive)
		}
		restored, err := mergeBucketsFromSnapshot(stagedBbolt, opts.StatePath, isFirewallBucket)
		if err != nil {
			return nil, fmt.Errorf("merging firewall buckets: %w", err)
		}
		res.BucketsRestored = restored
	case "baseline":
		// no bbolt work
	}

	return res, nil
}

// platformMatches compares the archive's stored platform map against the
// current host. Empty maps match anything (used when a caller hasn't
// supplied detection results, e.g., in some test paths).
func platformMatches(a, b map[string]string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	keys := []string{"os", "panel", "webserver"}
	for _, k := range keys {
		if a[k] != b[k] {
			return false
		}
	}
	return true
}

// listBuckets returns the bucket names actually present in the running
// DB (not the static bucketNames slice; callers may have been told via
// migration that some are gone).
func listBuckets(db *DB) []string {
	out := []string{}
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			out = append(out, string(name))
			return nil
		})
	})
	sort.Strings(out)
	return out
}

func writeTarFile(tw *tar.Writer, name string, data []byte, modTime time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0600,
		Size:    int64(len(data)),
		ModTime: modTime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("tar header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("tar write %s: %w", name, err)
	}
	return nil
}

// streamFileToTar copies srcPath into the tar under name. There is a
// theoretical Stat-then-Copy race when the source file is replaced
// between f.Stat() and io.Copy() -- the tar writer would then see a
// mismatched byte count. In practice the only files this function
// reads on a live daemon are state JSON written via atomic-replace
// (so a mid-write read sees either the old or the new full content)
// and the bbolt snapshot (already a frozen copy on disk). The risk
// is bounded enough to live with for v1.
func streamFileToTar(tw *tar.Writer, name, srcPath string, modTime time.Time) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", srcPath, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", srcPath, err)
	}
	hdr := &tar.Header{
		Name:    name,
		Mode:    0600,
		Size:    info.Size(),
		ModTime: modTime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("tar header %s: %w", name, err)
	}
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("tar copy %s: %w", name, err)
	}
	return nil
}

// walkDirIntoTar streams every regular file under srcDir into the tar
// under entryPrefix, skipping any base names in the skip list. Returns
// how many files were written.
func walkDirIntoTar(tw *tar.Writer, srcDir, entryPrefix string, skip []string, modTime time.Time) (int, error) {
	skipSet := map[string]bool{}
	for _, s := range skip {
		skipSet[s] = true
	}
	count := 0
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if skipSet[info.Name()] {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		entry := entryPrefix + filepath.ToSlash(rel)
		if err := streamFileToTar(tw, entry, path, modTime); err != nil {
			return err
		}
		count++
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return count, err
	}
	return count, nil
}

// atomicReplace renames src over dst, ensuring the parent directory is
// fsync'd so the rename survives a crash.
func atomicReplace(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(dst))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

// mergeBucketsFromSnapshot opens the snapshot bbolt read-only, iterates
// matching buckets, and copies their key/value pairs into the target
// bbolt at statePath/csm.db. The target may or may not exist; Open
// creates it. Returns the bucket names actually merged.
func mergeBucketsFromSnapshot(snapshotPath, statePath string, match func(string) bool) ([]string, error) {
	src, err := bolt.Open(snapshotPath, 0600, &bolt.Options{Timeout: 5 * time.Second, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("opening snapshot: %w", err)
	}
	defer func() { _ = src.Close() }()

	dst, err := Open(statePath)
	if err != nil {
		return nil, fmt.Errorf("opening target: %w", err)
	}
	defer func() { _ = dst.Close() }()

	merged := []string{}
	err = src.View(func(stx *bolt.Tx) error {
		return stx.ForEach(func(name []byte, sb *bolt.Bucket) error {
			if !match(string(name)) {
				return nil
			}
			if upErr := dst.bolt.Update(func(dtx *bolt.Tx) error {
				db, berr := dtx.CreateBucketIfNotExists(name)
				if berr != nil {
					return berr
				}
				return sb.ForEach(func(k, v []byte) error {
					return db.Put(append([]byte(nil), k...), append([]byte(nil), v...))
				})
			}); upErr != nil {
				return upErr
			}
			merged = append(merged, string(name))
			return nil
		})
	})
	if err != nil {
		return merged, err
	}
	sort.Strings(merged)
	return merged, nil
}

func isFirewallBucket(name string) bool {
	return strings.HasPrefix(name, "fw:")
}
