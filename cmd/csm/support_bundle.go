package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	supportBundleExportName = control.SupportBundleExportName
)

// supportBundleJournal returns the last lines of the csm unit's journal; a
// var so tests stub the journal.
var supportBundleJournal = func(lines int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// #nosec G204 -- fixed program and unit; lines is a parsed integer.
	cmd := exec.CommandContext(ctx, "journalctl", "-u", "csm.service", "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
	var diagnostic journalStderr
	cmd.Stderr = &diagnostic
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	// One journal entry can span megabytes even when only one line was requested.
	const limit = 16 << 20
	out, err := io.ReadAll(io.LimitReader(stdout, limit+1))
	if len(out) > limit {
		err = errors.New("journal output exceeds 16 MiB")
	}
	if err != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if err != nil {
		return nil, err
	}
	if waitErr != nil {
		return nil, fmt.Errorf("journalctl: %w: %s", waitErr, diagnostic.text())
	}
	return out, nil
}

// Keep journalctl's failure reason without buffering unbounded stderr.
type journalStderr struct {
	data      []byte
	truncated bool
}

func (b *journalStderr) Write(p []byte) (int, error) {
	const limit = 4096
	n := min(len(p), limit-len(b.data))
	b.data = append(b.data, p[:n]...)
	if n < len(p) {
		b.truncated = true
	}
	return len(p), nil
}

func (b *journalStderr) text() string {
	if b.truncated {
		return "diagnostic exceeds capture limit"
	}
	return string(bytes.TrimSpace(b.data))
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

Writes the last N journal lines (default %d), redacted configuration,
system versions, integrity results and a store export from a running daemon
that supports diagnostic exports. The archive is created with mode 0600.
Use a new filename in a directory protected from other accounts.
Configured credentials are scrubbed from the text. Key files are excluded.
A part that cannot be collected safely has a <name>.err entry with the reason.
Review the remaining host data before sharing.
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
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return "", 0, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			if value == "" {
				return "", 0, fmt.Errorf("%s requires a value", name)
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

// writeSupportBundle publishes the completed 0600 archive at a new path.
// It returns the parts that could not be collected.
//
// #nosec G703 -- path is checked by assertExportDestination before publication.
func writeSupportBundle(path string, cfg *config.Config, journalLines int) ([]string, error) {
	// Preserve symlink/.. semantics until the shared export destination check resolves the directory.
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		path = cwd + string(os.PathSeparator) + path
	}
	path, err := assertExportDestination(path)
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(path); err == nil {
		return nil, fmt.Errorf("creating bundle: %w", os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, tmp, err := createExportTemp(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp) }()
	failed, err := writeSupportBundleArchive(f, cfg, journalLines)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	// Link publishes only a complete bundle and fails if a concurrent collector won.
	if err := os.Link(tmp, path); err != nil {
		return nil, fmt.Errorf("publishing bundle: %w", err)
	}
	if err := syncParentDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("bundle is in place at %s but its directory could not be synced: %w", path, err)
	}
	return failed, nil
}

// writeSupportBundleArchive writes the tar+zstd stream. A part that cannot be
// collected is stored as <name>.err. Every text part is scrubbed of the
// configured secret values: a logged request error quotes a webhook URL
// with its token, and the integrity result quotes the recorded hashes.
func writeSupportBundleArchive(w io.Writer, cfg *config.Config, journalLines int) (failed []string, err error) {
	zw, err := zstd.NewWriter(w)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := zw.Close(); err == nil {
			err = closeErr
		}
	}()
	tw := tar.NewWriter(zw)
	secrets, secretErr := config.SecretValues(cfg)
	pairs := make([]string, 0, 2*len(secrets))
	for _, value := range secrets {
		pairs = append(pairs, value, config.RedactedValue)
	}
	scrub := strings.NewReplacer(pairs...).Replace
	add := func(name string, data []byte, partErr error) error {
		if partErr != nil {
			failed = append(failed, name)
			name, data = name+".err", []byte(scrub(partErr.Error())+"\n")
		}
		return addBytes(tw, name, data)
	}

	var export *control.StoreExportResult
	var journal []byte
	exportErr, journalErr := secretErr, secretErr
	if secretErr == nil {
		export, exportErr = requestSupportBundleExport(secrets)
		if exportErr != nil && !errors.Is(exportErr, errDaemonNotRunning) {
			journalErr = errors.New("could not confirm the running daemon's redaction settings")
		} else {
			journal, journalErr = supportBundleJournalTail(journalLines, scrub)
		}
	}
	if exportErr == nil {
		defer removeStagedExport(export.Path)
		if checkErr := inspectSupportExport(export, cfg, secrets); checkErr != nil {
			if !errors.Is(checkErr, errSensitiveExport) && !errors.Is(checkErr, os.ErrNotExist) && !errors.Is(checkErr, os.ErrPermission) {
				return nil, checkErr
			}
			export, exportErr = nil, checkErr
		}
	}
	cfgYAML, cfgErr := supportConfigYAML(cfg, scrub)
	parts := []struct {
		name string
		data []byte
		err  error
	}{
		{"system.txt", []byte(scrub(string(supportBundleSystem(cfg, export)))), nil},
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
	return failed, nil
}

// Scrub values before YAML quoting or multiline indentation can hide a match.
func supportConfigYAML(cfg *config.Config, scrub func(string) string) ([]byte, error) {
	var root yaml.Node
	if err := root.Encode(config.Redact(cfg)); err != nil {
		return nil, err
	}
	var visit func(*yaml.Node)
	visit = func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode {
			switch n.ShortTag() {
			case "!!str":
				n.Value = scrub(n.Value)
			case "!!binary":
				var raw string
				if err := n.Decode(&raw); err != nil || scrub(raw) != raw {
					n.SetString(config.RedactedValue)
				}
			}
			return
		}
		if n.Kind == yaml.MappingNode {
			// A map may be keyed by operator data. Omit a sensitive key and
			// its value together so redacted keys cannot collide.
			kept := n.Content[:0]
			for i := 0; i < len(n.Content); i += 2 {
				key, value := n.Content[i], n.Content[i+1]
				original := key.Value
				visit(key)
				if key.Value != original {
					continue
				}
				visit(value)
				kept = append(kept, key, value)
			}
			n.Content = kept
			return
		}
		for _, child := range n.Content {
			visit(child)
		}
	}
	visit(&root)
	return yaml.Marshal(&root)
}

// journalctl counts entries, including entries with several physical lines.
func supportBundleJournalTail(lines int, scrub func(string) string) ([]byte, error) {
	out, err := supportBundleJournal(lines)
	if err != nil {
		return nil, err
	}
	data := scrub(string(out))
	end := len(strings.TrimSuffix(data, "\n"))
	for range lines {
		i := strings.LastIndexByte(data[:end], '\n')
		if i < 0 {
			return []byte(data), nil
		}
		end = i
	}
	return []byte(data[end+1:]), nil
}

// An older daemon requires DstPath and rejects this request before writing a backup.
func requestSupportBundleExport(values []string) (*control.StoreExportResult, error) {
	raw, err := sendControlWithTimeout(control.CmdStoreExport, control.StoreExportArgs{
		SupportRedactionSHA256: config.SecretValuesDigest(values),
		Stage:                  true,
	}, 30*time.Minute)
	if err != nil {
		return nil, err
	}
	var res control.StoreExportResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	dir := filepath.Dir(res.Path)
	if !filepath.IsAbs(res.Path) || filepath.Clean(res.Path) != res.Path || filepath.Base(res.Path) != supportBundleExportName ||
		!strings.HasPrefix(filepath.Base(dir), "export-") || filepath.Base(filepath.Dir(dir)) != "exports" {
		return nil, errors.New("daemon did not return a staged store export")
	}
	return &res, nil
}

func addVerifiedStoreExport(tw *tar.Writer, export *control.StoreExportResult) error {
	f, err := openSupportExport(export.Path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err = tw.WriteHeader(&tar.Header{Name: supportBundleExportName, Size: export.Bytes, Mode: 0o600}); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, h), f)
	if err != nil {
		return err
	}
	if n != export.Bytes || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), export.ArchiveSHA256) {
		return errors.New("staged archive changed while copying")
	}
	return nil
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
	if cfg.WebServer.Type != "" {
		pi.WebServer = platform.WebServer(cfg.WebServer.Type)
	}
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
