package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/platform"
	"gopkg.in/yaml.v3"
)

const (
	defaultSupportBundleJournalLines = 1000
	// supportBundleExportName names the store export in the bundle and in
	// the daemon's staging directory.
	supportBundleExportName = "store-export.tar.zst"
)

// supportBundleJournal returns the last lines of the csm unit's journal; a
// var so tests stub the journal.
var supportBundleJournal = func(lines int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// #nosec G204 -- fixed program and unit; lines is a parsed integer.
	out, err := exec.CommandContext(ctx, "journalctl", "-u", "csm.service", "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso").Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		err = fmt.Errorf("journalctl: %w: %s", err, bytes.TrimSpace(exitErr.Stderr))
	}
	return out, err
}

func runSupportBundle() {
	args := os.Args[2:]
	if slices.Contains(args, "--help") || slices.Contains(args, "-h") {
		printSupportBundleUsage()
		return
	}
	path, lines, err := parseSupportBundleArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm support-bundle: %v\n", err)
		printSupportBundleUsage()
		os.Exit(2)
	}
	cfg := loadConfigLiteWith(secretFreeLoadOptions)
	failed, err := writeSupportBundle(path, cfg, lines)
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm support-bundle: %v\n", err)
		os.Exit(1)
	}
	for _, name := range failed {
		fmt.Fprintf(os.Stderr, "warning: %s could not be collected; the bundle holds %s.err with the reason\n", name, name)
	}
	fmt.Printf("support bundle: %s\n", path)
}

func printSupportBundleUsage() {
	fmt.Fprintf(os.Stderr, `csm support-bundle - collect diagnostics for a support request

Usage:
  csm support-bundle <path> [--journal-lines N]

Writes a tar+zstd archive holding the store export (as csm store export
writes it), the last N lines of the csm.service journal (default %d), the
configuration with secrets redacted, and system.txt with versions and
integrity results. Configured secret values are removed from every text
part. The archive is created with mode 0600 and an existing path is never
replaced. The store export needs a running daemon; a part that cannot be
collected is stored as <name>.err with the reason.
`, defaultSupportBundleJournalLines)
}

// parseSupportBundleArgs accepts one output path and --journal-lines; the
// global --config and --config-dir values are read by the config loader.
func parseSupportBundleArgs(args []string) (string, int, error) {
	path, lines := "", defaultSupportBundleJournalLines
	for i := 0; i < len(args); i++ {
		name, value, assigned := strings.Cut(args[i], "=")
		switch name {
		case "--config", "--config-dir", "--journal-lines":
			if !assigned {
				i++
				if i == len(args) {
					return "", 0, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			if name == "--journal-lines" {
				n, err := strconv.Atoi(value)
				if err != nil || n < 1 {
					return "", 0, errors.New("--journal-lines must be a positive number")
				}
				lines = n
			}
		default:
			if strings.HasPrefix(args[i], "-") || path != "" {
				return "", 0, fmt.Errorf("unexpected argument %q", args[i])
			}
			path = args[i]
		}
	}
	if path == "" {
		return "", 0, errors.New("missing output path")
	}
	return path, lines, nil
}

// writeSupportBundle creates path as a new 0600 file and writes the bundle
// into it, removing the file again if any step fails. It returns the parts
// that could not be collected.
//
// #nosec G304 G703 -- path is the operator's destination; O_EXCL|O_NOFOLLOW
// refuse anything already there, including a planted symlink.
func writeSupportBundle(path string, cfg *config.Config, journalLines int) ([]string, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("creating bundle: %w", err)
	}
	failed, err := writeSupportBundleArchive(f, cfg, journalLines)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return failed, nil
}

// writeSupportBundleArchive writes the tar+zstd stream. A part that cannot be
// collected is stored as <name>.err. Every text part is scrubbed of the
// configured secret values: a logged request error quotes a webhook URL
// with its token, and the integrity result quotes the recorded hashes.
func writeSupportBundleArchive(w io.Writer, cfg *config.Config, journalLines int) ([]string, error) {
	zw, err := zstd.NewWriter(w)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	secrets := config.SecretValues(cfg)
	var failed []string
	add := func(name string, data []byte, partErr error) error {
		if partErr != nil {
			failed = append(failed, name)
			name, data = name+".err", []byte(partErr.Error()+"\n")
		}
		for _, s := range secrets {
			data = bytes.ReplaceAll(data, []byte(s), []byte(config.RedactedValue))
		}
		return addBytes(tw, name, data)
	}

	export, exportErr := requestSupportBundleExport(cfg.StatePath)
	if exportErr == nil {
		defer removeStagedExport(export.Path)
	}
	cfgYAML, cfgErr := yaml.Marshal(config.Redact(cfg))
	journal, journalErr := supportBundleJournalTail(journalLines)
	parts := []struct {
		name string
		data []byte
		err  error
	}{
		{"system.txt", supportBundleSystem(cfg, export), nil},
		{"config.yaml", cfgYAML, cfgErr},
		{"journal.txt", journal, journalErr},
	}
	for _, p := range parts {
		if err = add(p.name, p.data, p.err); err != nil {
			return nil, err
		}
	}
	if exportErr != nil {
		err = add(supportBundleExportName, nil, exportErr)
	} else {
		err = addVerifiedStoreExport(tw, export)
	}
	if err != nil {
		return nil, err
	}
	if err = tw.Close(); err != nil {
		return nil, err
	}
	return failed, zw.Close()
}

// supportBundleJournalTail trims to the requested line count: journalctl -n
// counts entries, and one entry can span several lines.
func supportBundleJournalTail(lines int) ([]byte, error) {
	out, err := supportBundleJournal(lines)
	if err != nil {
		return nil, err
	}
	all := strings.SplitAfter(string(out), "\n")
	if all[len(all)-1] == "" {
		all = all[:len(all)-1]
	}
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return []byte(strings.Join(all, "")), nil
}

// requestSupportBundleExport asks the daemon for a staged store export, as
// csm store export does. A staging daemon uses only the base name; one too
// old to stage writes the path itself, which keeps it in its state directory.
func requestSupportBundleExport(statePath string) (*control.StoreExportResult, error) {
	raw, err := sendControlWithTimeout(control.CmdStoreExport, control.StoreExportArgs{
		DstPath: filepath.Join(statePath, "exports", supportBundleExportName),
		Stage:   true,
	}, 30*time.Minute)
	if err != nil {
		return nil, err
	}
	var res control.StoreExportResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &res, nil
}

// addVerifiedStoreExport copies the staged export into the bundle once its
// bytes match the digest the daemon reported, so a staged file damaged or
// replaced after the daemon wrote it is never handed on.
func addVerifiedStoreExport(tw *tar.Writer, export *control.StoreExportResult) error {
	got, err := fileSHA256(export.Path)
	if err != nil {
		return err
	}
	if want := strings.ToLower(strings.TrimSpace(export.ArchiveSHA256)); got != want {
		return fmt.Errorf("staged archive digest %s does not match export digest %s", got, want)
	}
	return addFile(tw, export.Path, supportBundleExportName)
}

// removeStagedExport drops the staged export, its companion digest and the
// per-request staging directory, which stays if it still holds anything.
//
// #nosec G703 -- path is the staged export the local daemon returned.
func removeStagedExport(path string) {
	_ = os.Remove(path + ".sha256")
	_ = os.Remove(path)
	_ = os.Remove(filepath.Dir(path))
}

// supportBundleSystem reports versions, platform and integrity. Integrity is
// the doctor check's result rather than raw digests: Redact treats the
// recorded hashes as secret, and on a healthy host the computed ones equal them.
func supportBundleSystem(cfg *config.Config, export *control.StoreExportResult) []byte {
	var b strings.Builder
	pi := platform.Detect()
	fmt.Fprintf(&b, "csm: %s (build: %s, date: %s)\n", Version, BuildHash, BuildTime)
	fmt.Fprintf(&b, "go: %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "os: %s %s\npanel: %s\nweb server: %s\n", pi.OS, pi.OSVersion, pi.Panel, pi.WebServer)
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		kernel = []byte(err.Error())
	}
	fmt.Fprintf(&b, "kernel: %s\n", bytes.TrimSpace(kernel))
	check := doctorIntegrityCheck(cfg, func(c *config.Config) error { return integrity.Verify(binaryPath, c) })
	fmt.Fprintf(&b, "integrity: %s", check.Status)
	if check.Message != "" {
		fmt.Fprintf(&b, " (%s)", check.Message)
	}
	b.WriteString("\n")
	if export != nil {
		fmt.Fprintf(&b, "store export sha256: %s\nstore export bbolt sha256: %s\n", export.ArchiveSHA256, export.BboltSHA256)
	}
	return []byte(b.String())
}
