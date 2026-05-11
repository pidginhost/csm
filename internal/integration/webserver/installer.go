// Package webserver auto-installs the CSM challenge webserver glue
// (Apache / LSWS / Nginx) with a write-validate-reload-or-revert flow.
// The operator runs `csm webserver-integration {install|upgrade|...}`;
// the package picks the right handler for the host and never reloads
// the webserver with a snippet that does not pass configtest.
package webserver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// templateHeader is prepended to every rendered snippet so the
// installer can read the version back without parsing the body. The
// header is a single comment line whose value uniquely identifies
// "CSM owns this file". Manual edits that wipe or change the header
// trip ErrManualEdits at upgrade time and the file is left untouched.
const templateHeaderPrefix = "# csm-managed-version: "

const (
	defaultChallengeListenAddr = "127.0.0.1"
	defaultChallengeListenPort = 8439
)

// RenderConfig contains the daemon settings that have to be baked
// into webserver snippets. Values come from csm.yaml at install time
// where they are operator-configurable.
type RenderConfig struct {
	ChallengeMapPath    string
	ChallengeListenAddr string
	ChallengeListenPort int
}

type templateData struct {
	ChallengeMapPath string
	BackendHostPort  string
	BackendURL       string
}

// Result is the structured outcome of an installer run. JSON-friendly
// shape so the CLI can render either human text or `--json` output.
type Result struct {
	Action      string `json:"action"`       // "install" | "upgrade" | "remove" | "status" | "validate"
	Status      string `json:"status"`       // "ok" | "no-op" | "skipped" | "fail"
	Webserver   string `json:"webserver"`    // detected handler kind, "" if none
	SnippetPath string `json:"snippet_path"` // "" if no handler
	OnDiskVer   int    `json:"on_disk_version,omitempty"`
	ShippedVer  int    `json:"shipped_version,omitempty"`
	Message     string `json:"message,omitempty"`
}

// Installer drives the install / upgrade / status / remove flow. All
// I/O goes through injected hooks so unit tests can run on darwin or
// against a temp tree without touching real webserver paths.
type Installer struct {
	Handler  Handler
	Config   RenderConfig
	MkdirAll func(path string, mode os.FileMode) error
	WriteAt  func(path string, data []byte, mode os.FileMode) error
	ReadAt   func(path string) ([]byte, error)
	StatAt   func(path string) (os.FileInfo, error)
	RemoveAt func(path string) error
	Stderr   io.Writer
}

// New returns an Installer wired for live operation: real filesystem
// reads, atomic writes, real exec runner. The handler is auto-selected
// from platform.Detect(); pass info to override for tests.
func New(info platform.Info, cfg *config.Config) (*Installer, error) {
	h, err := pickHandler(info, realCmdRunner{})
	if err != nil {
		return nil, err
	}
	return &Installer{
		Handler:  h,
		Config:   renderConfigFrom(cfg),
		MkdirAll: os.MkdirAll,
		WriteAt:  atomicWrite,
		ReadAt:   os.ReadFile,
		StatAt:   os.Stat,
		RemoveAt: os.Remove,
		Stderr:   os.Stderr,
	}, nil
}

// Install writes the snippet for the first time (or overwrites a
// stale one) with the safe rollback flow:
//
//  1. Stash existing bytes (or note absence).
//  2. Write new snippet atomically.
//  3. Validate via the webserver's own configtest.
//  4. On pass: reload + done.
//  5. On fail: restore previous bytes + return error.
//
// Reload failure after a passing configtest is restored the same way,
// then a recovery reload is attempted so the host returns to the
// last-known-good state.
func (i *Installer) Install() (Result, error) {
	res := Result{
		Action:      "install",
		Webserver:   i.Handler.Kind(),
		SnippetPath: i.Handler.SnippetPath(),
		ShippedVer:  TemplateVersion,
	}

	prevBytes, prevExists, prevVer, err := i.readSnippet()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Status = "fail"
		res.Message = err.Error()
		return res, err
	}
	res.OnDiskVer = prevVer

	if prevExists && prevVer == 0 {
		res.Status = "fail"
		res.Message = ErrManualEdits.Error() + ": " + i.Handler.SnippetPath()
		return res, ErrManualEdits
	}

	if err := i.ensureChallengeMapFiles(); err != nil {
		res.Status = "fail"
		res.Message = "runtime files: " + err.Error()
		return res, err
	}

	rendered, err := i.renderTemplate()
	if err != nil {
		res.Status = "fail"
		res.Message = "render: " + err.Error()
		return res, err
	}

	if prevExists && bytes.Equal(prevBytes, rendered) {
		res.Status = "no-op"
		res.Message = "snippet already current"
		return res, nil
	}

	if err := i.WriteAt(i.Handler.SnippetPath(), rendered, 0o644); err != nil {
		res.Status = "fail"
		res.Message = "write: " + err.Error()
		return res, err
	}

	if verr := i.Handler.Validate(); verr != nil {
		i.restore(prevBytes, prevExists)
		res.Status = "fail"
		res.Message = "configtest: " + verr.Error()
		return res, verr
	}

	if rerr := i.Handler.Reload(); rerr != nil {
		i.restore(prevBytes, prevExists)
		// Best-effort recovery reload. Even if it fails, the file is
		// already back to the last-good content.
		_ = i.Handler.Reload()
		res.Status = "fail"
		res.Message = "reload: " + rerr.Error() + " (rolled back)"
		return res, rerr
	}

	res.Status = "ok"
	if prevExists {
		res.Message = fmt.Sprintf("snippet upgraded v%d -> v%d", prevVer, TemplateVersion)
	} else {
		res.Message = fmt.Sprintf("snippet installed (v%d)", TemplateVersion)
	}
	return res, nil
}

// Upgrade is an alias for Install with a more honest CLI verb. The
// underlying flow is the same: idempotent install + version compare.
func (i *Installer) Upgrade() (Result, error) {
	res, err := i.Install()
	res.Action = "upgrade"
	return res, err
}

// Status returns the current integration state without writing
// anything. Used by post-upgrade hooks and operator-facing diagnostic
// commands to detect drift.
func (i *Installer) Status() (Result, error) {
	res := Result{
		Action:      "status",
		Webserver:   i.Handler.Kind(),
		SnippetPath: i.Handler.SnippetPath(),
		ShippedVer:  TemplateVersion,
	}
	_, exists, ver, err := i.readSnippet()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Status = "fail"
		res.Message = err.Error()
		return res, err
	}
	res.OnDiskVer = ver
	res.Status, res.Message = classifyStatus(exists, ver, TemplateVersion)
	return res, nil
}

// classifyStatus is the pure-logic version compare extracted so the
// stale / modified / ok branches can be unit-tested without depending
// on the current TemplateVersion constant.
func classifyStatus(exists bool, onDisk, shipped int) (status, message string) {
	switch {
	case !exists:
		return "missing", "no snippet installed; run `csm webserver-integration install`"
	case onDisk == 0:
		return "modified", ErrManualEdits.Error()
	case onDisk < shipped:
		return "stale", fmt.Sprintf("on-disk v%d < shipped v%d; run `csm webserver-integration upgrade`", onDisk, shipped)
	default:
		return "ok", fmt.Sprintf("snippet at v%d", onDisk)
	}
}

// Remove deletes the snippet, runs configtest to confirm the webserver
// is happy without it, and reloads. Mirrors the install rollback
// discipline: if removing the file makes configtest fail, restore the
// original and exit non-zero.
func (i *Installer) Remove() (Result, error) {
	res := Result{
		Action:      "remove",
		Webserver:   i.Handler.Kind(),
		SnippetPath: i.Handler.SnippetPath(),
		ShippedVer:  TemplateVersion,
	}
	prevBytes, prevExists, prevVer, err := i.readSnippet()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Status = "fail"
		res.Message = err.Error()
		return res, err
	}
	res.OnDiskVer = prevVer
	if !prevExists {
		res.Status = "no-op"
		res.Message = "snippet not present"
		return res, nil
	}
	if prevVer == 0 {
		res.Status = "fail"
		res.Message = ErrManualEdits.Error() + ": refusing to delete an operator-edited file"
		return res, ErrManualEdits
	}
	if err := i.RemoveAt(i.Handler.SnippetPath()); err != nil {
		res.Status = "fail"
		res.Message = "delete: " + err.Error()
		return res, err
	}
	if verr := i.Handler.Validate(); verr != nil {
		i.restore(prevBytes, prevExists)
		res.Status = "fail"
		res.Message = "configtest after remove: " + verr.Error()
		return res, verr
	}
	if rerr := i.Handler.Reload(); rerr != nil {
		i.restore(prevBytes, prevExists)
		_ = i.Handler.Reload()
		res.Status = "fail"
		res.Message = "reload: " + rerr.Error() + " (rolled back)"
		return res, rerr
	}
	res.Status = "ok"
	res.Message = "snippet removed"
	return res, nil
}

// Validate is a dry-run that exercises the webserver's own configtest
// against the current on-disk state. No writes, no reload.
func (i *Installer) Validate() (Result, error) {
	res := Result{
		Action:      "validate",
		Webserver:   i.Handler.Kind(),
		SnippetPath: i.Handler.SnippetPath(),
		ShippedVer:  TemplateVersion,
	}
	if err := i.Handler.Validate(); err != nil {
		res.Status = "fail"
		res.Message = err.Error()
		return res, err
	}
	res.Status = "ok"
	res.Message = "configtest passed"
	return res, nil
}

// renderTemplate prefixes the handler's body with the version marker
// the installer reads back at status/upgrade time.
func (i *Installer) renderTemplate() ([]byte, error) {
	tpl, err := template.New(i.Handler.Kind()).Parse(i.Handler.Template())
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(templateHeaderPrefix)
	b.WriteString(strconv.Itoa(TemplateVersion))
	b.WriteByte('\n')
	if err := tpl.Execute(&b, i.templateData()); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func renderConfigFrom(cfg *config.Config) RenderConfig {
	rc := RenderConfig{
		ChallengeMapPath:    challenge.DefaultMapPath,
		ChallengeListenAddr: defaultChallengeListenAddr,
		ChallengeListenPort: defaultChallengeListenPort,
	}
	if cfg == nil {
		return rc
	}
	if strings.TrimSpace(cfg.Challenge.ListenAddr) != "" {
		rc.ChallengeListenAddr = strings.TrimSpace(cfg.Challenge.ListenAddr)
	}
	if cfg.Challenge.ListenPort > 0 {
		rc.ChallengeListenPort = cfg.Challenge.ListenPort
	}
	return rc
}

func (i *Installer) templateData() templateData {
	mapPath := strings.TrimSpace(i.Config.ChallengeMapPath)
	if mapPath == "" {
		mapPath = challenge.DefaultMapPath
	}
	port := i.Config.ChallengeListenPort
	if port <= 0 {
		port = defaultChallengeListenPort
	}
	host := challengeBackendHost(i.Config.ChallengeListenAddr)
	backendHostPort := net.JoinHostPort(host, strconv.Itoa(port))
	return templateData{
		ChallengeMapPath: mapPath,
		BackendHostPort:  backendHostPort,
		BackendURL:       "http://" + backendHostPort + "/challenge",
	}
}

func challengeBackendHost(addr string) string {
	addr = strings.Trim(strings.TrimSpace(addr), "[]")
	switch addr {
	case "", "0.0.0.0", "::":
		return defaultChallengeListenAddr
	default:
		return addr
	}
}

func (i *Installer) ensureChallengeMapFiles() error {
	data := i.templateData()
	mkdirAll := i.MkdirAll
	if mkdirAll == nil {
		mkdirAll = os.MkdirAll
	}
	if err := mkdirAll(filepath.Dir(data.ChallengeMapPath), 0o755); err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		body []byte
	}{
		{path: data.ChallengeMapPath, body: []byte("# Generated by CSM.\n")},
	} {
		statAt := i.StatAt
		if statAt == nil {
			statAt = os.Stat
		}
		if _, err := statAt(f.path); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := i.WriteAt(f.path, f.body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// readSnippet parses the on-disk snippet header to recover the
// embedded version. Returns the raw bytes, a presence flag, and the
// parsed version (zero when the file exists but lacks the marker).
func (i *Installer) readSnippet() ([]byte, bool, int, error) {
	data, err := i.ReadAt(i.Handler.SnippetPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, 0, err
		}
		return nil, false, 0, err
	}
	ver := parseHeaderVersion(data)
	return data, true, ver, nil
}

// restore writes the previous bytes back (or removes the new file if
// there were none) after a failed validate/reload step. Best-effort:
// I/O errors here are reported via stderr but do not change the
// installer's return code, because the caller already knows the
// original error.
func (i *Installer) restore(prevBytes []byte, prevExists bool) {
	if !prevExists {
		if err := i.RemoveAt(i.Handler.SnippetPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(i.Stderr, "webserver integration: rollback delete failed: %v\n", err)
		}
		return
	}
	if err := i.WriteAt(i.Handler.SnippetPath(), prevBytes, 0o644); err != nil {
		fmt.Fprintf(i.Stderr, "webserver integration: rollback write failed: %v\n", err)
	}
}

func parseHeaderVersion(data []byte) int {
	scanner := bytes.SplitN(data, []byte("\n"), 2)
	if len(scanner) == 0 {
		return 0
	}
	line := strings.TrimSpace(string(scanner[0]))
	if !strings.HasPrefix(line, templateHeaderPrefix) {
		return 0
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, templateHeaderPrefix))
	v, err := strconv.Atoi(rest)
	if err != nil {
		return 0
	}
	return v
}

func pickHandler(info platform.Info, r cmdRunner) (Handler, error) {
	switch info.WebServer {
	case platform.WSApache:
		return newApacheHandler(info, r), nil
	case platform.WSLiteSpeed:
		return newLSWSHandler(r), nil
	case platform.WSNginx:
		return newNginxHandler(r), nil
	default:
		return nil, ErrUnknownWebserver
	}
}

// atomicWrite writes data to a sibling temp file then renames it into
// place so the webserver never sees a half-written snippet. fsync on
// the directory is best-effort; rename + fsync on the file before
// rename gives crash safety on every common Linux filesystem.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".csm-ws-install-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, werr := tmp.Write(data); werr != nil {
		_ = tmp.Close()
		cleanup()
		return werr
	}
	if serr := tmp.Sync(); serr != nil {
		_ = tmp.Close()
		cleanup()
		return serr
	}
	if cerr := tmp.Close(); cerr != nil {
		cleanup()
		return cerr
	}
	if merr := os.Chmod(tmpName, mode); merr != nil {
		cleanup()
		return merr
	}
	return os.Rename(tmpName, path)
}
