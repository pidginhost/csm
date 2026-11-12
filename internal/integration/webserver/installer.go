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
	"net/url"
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

// RenderConfig contains the daemon settings that have to be baked
// into webserver snippets. Values come from csm.yaml at install time
// where they are operator-configurable.
type RenderConfig struct {
	ChallengeMapPath      string
	ChallengeNginxMapPath string
	ChallengeListenAddr   string
	ChallengeListenGroup  string
	// ChallengePublicURL is the fully-qualified redirect target the
	// webserver snippet emits. Required on install; empty value blocks
	// the installer with a clear error. Operator typically points it at
	// the host's TLS-valid control-panel domain on a CSM-owned port,
	// e.g. https://server.example.com:8439/challenge.
	ChallengePublicURL string
	// ChallengeTrustedProxies is checked so the installer never wires
	// redirects to a listener that trusts an address of this host.
	ChallengeTrustedProxies []string
}

type templateData struct {
	ChallengeMapPath      string
	ChallengeNginxMapPath string
	ChallengePublicURL    string
}

// ErrMissingPublicURL is returned by Install when challenge.public_url
// is empty. The webserver snippet has no fallback redirect target so
// the integration cannot function without it.
var ErrMissingPublicURL = errors.New("webserver integration: challenge.public_url is not set")

// ErrInvalidPublicURL is returned when challenge.public_url cannot be
// used as the direct browser redirect target.
var ErrInvalidPublicURL = errors.New("webserver integration: challenge.public_url must be an absolute http(s) URL ending in /challenge")

// ErrLoopbackPublicURL is returned when the installed snippets would
// redirect browsers to a TCP listener that only accepts loopback traffic.
var ErrLoopbackPublicURL = errors.New("webserver integration: challenge.listen_addr must be non-loopback when challenge.public_url redirects are enabled; for a proxy on this host use challenge.listen_addr: " + config.ChallengeSocketExample)

// Result is the structured outcome of an installer run. JSON-friendly
// shape so the CLI can render either human text or `--json` output.
type Result struct {
	Action      string `json:"action"`       // "install" | "upgrade" | "remove" | "status" | "validate"
	Status      string `json:"status"`       // "ok" | "no-op" | "skipped" | "fail"
	Webserver   string `json:"webserver"`    // detected handler kind, "" if none
	SnippetPath string `json:"snippet_path"` // "" if no handler
	// SitePath is the per-site snippet on stacks whose HTTPS sites need it.
	SitePath   string `json:"site_snippet_path,omitempty"`
	OnDiskVer  int    `json:"on_disk_version,omitempty"`
	ShippedVer int    `json:"shipped_version,omitempty"`
	Message    string `json:"message,omitempty"`
	// FollowUp is the operator-facing setup the integration could not
	// automate on this stack. Empty when install is fully automatic.
	// The CLI prints it after the result block on successful install.
	FollowUp string `json:"follow_up,omitempty"`
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
	// LegacySnippetPath is the pre-integration snippet Install retires
	// in the same configtest and reload as its own write. Set only when
	// the handler's configtest covers that file; empty elsewhere.
	LegacySnippetPath string
	// RebuildSiteIncludes lets Install regenerate the web server
	// configuration once so site blocks read the per-site snippet. Only the
	// explicit command sets it; the daemon never rebuilds on its own.
	RebuildSiteIncludes bool
}

// LegacySnippetPath is where the package installer used to deploy a
// proxy-mode challenge snippet on cPanel Apache and LiteSpeed. It proxied
// challenged visitors to the loopback listener, which sees them all as
// loopback unless challenge.trusted_proxies lists it, and it doubled the
// integration snippet in the same directory.
const LegacySnippetPath = "/etc/apache2/conf.d/csm_challenge.conf"

// legacySnippetFor returns LegacySnippetPath when the handler's snippet
// shares its directory, so the handler's configtest and reload cover a
// change to the legacy file; otherwise "".
func legacySnippetFor(h Handler) string {
	if filepath.Dir(h.SnippetPath()) == filepath.Dir(LegacySnippetPath) {
		return LegacySnippetPath
	}
	return ""
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
		Handler:           h,
		Config:            renderConfigFrom(cfg),
		MkdirAll:          os.MkdirAll,
		WriteAt:           atomicWrite,
		ReadAt:            os.ReadFile,
		StatAt:            os.Stat,
		RemoveAt:          os.Remove,
		Stderr:            os.Stderr,
		LegacySnippetPath: legacySnippetFor(h),
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
// A legacy snippet beside it is removed before step 3, so one configtest
// and one reload cover both changes and a rollback restores both.
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

	if err := validateChallengePublicURL(i.Config); err != nil {
		res.Status = "fail"
		res.Message = err.Error()
		return res, err
	}
	// Kept out of validateChallengePublicURL so doctor, which reports this
	// in its own check, does not report it twice.
	if err := config.ChallengeLocalTrustError(i.Config.ChallengeTrustedProxies); err != nil {
		err = fmt.Errorf("webserver integration: %w", err)
		res.Status = "fail"
		res.Message = err.Error()
		return res, err
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

	legacyBytes, legacyExists, err := i.readLegacySnippet()
	if err != nil {
		res.Status = "fail"
		res.Message = err.Error()
		return res, err
	}

	if mapErr := i.ensureChallengeMapFiles(); mapErr != nil {
		res.Status = "fail"
		res.Message = "runtime files: " + mapErr.Error()
		return res, mapErr
	}

	rendered, rerr := i.renderTemplate()
	if rerr != nil {
		res.Status = "fail"
		res.Message = "render: " + rerr.Error()
		return res, rerr
	}

	site, err := i.prepareSite()
	if err != nil {
		res.Status = "fail"
		res.Message = err.Error()
		return res, err
	}
	if site != nil {
		res.SitePath = site.path
	}
	rebuild := site != nil && i.RebuildSiteIncludes && !site.active
	if site != nil && i.RebuildSiteIncludes && site.activeErr != nil {
		res.Status = "fail"
		res.Message = "read site includes: " + site.activeErr.Error()
		return res, site.activeErr
	}

	current := prevExists && bytes.Equal(prevBytes, rendered)
	if current && !legacyExists && (site == nil || site.current) && !rebuild {
		res.Status = "no-op"
		res.Message = "snippet already current" + site.pendingNote()
		return res, nil
	}

	// A second rebuild is not a rollback: it can fail or regenerate the same
	// bad configuration. Save the exact active file before changing anything.
	var configBefore []byte
	var configMode os.FileMode
	if rebuild {
		configBefore, err = i.ReadAt(site.sites.SiteConfigPath())
		if err == nil {
			statAt := i.StatAt
			if statAt == nil {
				statAt = os.Stat
			}
			var info os.FileInfo
			info, err = statAt(site.sites.SiteConfigPath())
			if err == nil {
				configMode = info.Mode().Perm()
			}
		}
		if err != nil {
			res.Status = "fail"
			res.Message = "save site configuration: " + err.Error()
			return res, err
		}
	}

	if !current {
		if err := i.WriteAt(i.Handler.SnippetPath(), rendered, 0o644); err != nil {
			res.Status = "fail"
			res.Message = "write: " + err.Error()
			return res, err
		}
	}
	siteWritten := false
	legacyRemoved := false
	rebuilt := false
	rollback := func() error {
		var errs []error
		if !current {
			errs = append(errs, i.restore(prevBytes, prevExists))
		}
		if siteWritten {
			errs = append(errs, i.restoreAt(site.path, site.prevBytes, site.prevExists))
		}
		if legacyRemoved {
			errs = append(errs, i.restoreLegacySnippet(legacyBytes))
		}
		if rebuilt {
			if err := i.WriteAt(site.sites.SiteConfigPath(), configBefore, configMode); err != nil {
				errs = append(errs, fmt.Errorf("rollback site configuration: %w", err))
			}
		}
		return errors.Join(errs...)
	}

	if site != nil && !site.current {
		err := i.mkdirAll(filepath.Dir(site.path), 0o755)
		if err == nil {
			err = i.WriteAt(site.path, site.rendered, 0o644)
		}
		if err != nil {
			err = errors.Join(err, rollback())
			res.Status = "fail"
			res.Message = "write site snippet: " + err.Error()
			return res, err
		}
		siteWritten = true
	}

	if legacyExists {
		if err := i.RemoveAt(i.LegacySnippetPath); err != nil {
			err = errors.Join(err, rollback())
			res.Status = "fail"
			res.Message = "delete legacy snippet: " + err.Error()
			return res, err
		}
		legacyRemoved = true
	}

	if rebuild {
		// Even a failed command may have replaced httpd.conf.
		rebuilt = true
		site.rebuilt = true
		if err := site.sites.RebuildSiteIncludes(); err != nil {
			err = errors.Join(err, rollback())
			res.Status = "fail"
			res.Message = err.Error()
			return res, err
		}
		site.active, site.activeErr = site.sites.SiteIncludeActive()
	}

	if verr := i.Handler.Validate(); verr != nil {
		verr = errors.Join(verr, rollback())
		res.Status = "fail"
		res.Message = "configtest: " + verr.Error()
		return res, verr
	}

	if rerr := i.Handler.Reload(); rerr != nil {
		res.Status = "fail"
		if rollbackErr := rollback(); rollbackErr != nil {
			err := errors.Join(rerr, rollbackErr)
			res.Message = "reload: " + err.Error()
			return res, err
		}
		if rebuilt {
			if err := i.Handler.Validate(); err != nil {
				err = errors.Join(rerr, fmt.Errorf("rollback configtest: %w", err))
				res.Message = err.Error()
				return res, err
			}
		}
		// Only reload after all changed files are back to their previous content.
		if err := i.Handler.Reload(); err != nil {
			err = errors.Join(rerr, fmt.Errorf("recovery reload: %w", err))
			res.Message = err.Error()
			return res, err
		}
		res.Message = "reload: " + rerr.Error() + " (rolled back)"
		return res, rerr
	}

	res.Status = "ok"
	switch {
	case current:
		res.Message = fmt.Sprintf("snippet already current (v%d)", TemplateVersion)
	case prevExists:
		res.Message = fmt.Sprintf("snippet upgraded v%d -> v%d", prevVer, TemplateVersion)
	default:
		res.Message = fmt.Sprintf("snippet installed (v%d)", TemplateVersion)
	}
	if legacyExists {
		res.Message += "; legacy snippet " + i.LegacySnippetPath + " removed"
	}
	if siteWritten {
		res.Message += "; site snippet " + site.path + " written"
	}
	if rebuilt {
		res.Message += "; httpd.conf rebuilt"
	}
	res.Message += site.pendingNote()
	res.FollowUp = i.Handler.PostInstallInstructions()
	return res, nil
}

// siteChange is the per-site snippet Install manages beside the server one.
type siteChange struct {
	sites      siteIncluder
	path       string
	prevBytes  []byte
	prevExists bool
	rendered   []byte
	current    bool
	active     bool
	activeErr  error
	rebuilt    bool
}

// pendingNote tells the operator when HTTPS sites still miss the rule. Safe
// on a nil receiver.
func (s *siteChange) pendingNote() string {
	switch {
	case s == nil || s.active:
		return ""
	case s.activeErr != nil:
		return "; could not tell whether HTTPS sites read " + s.path + ": " + s.activeErr.Error()
	case s.rebuilt:
		return "; HTTPS sites still do not read " + s.path + " after the rebuild: check cPanel's Apache virtual host templates"
	default:
		return "; HTTPS sites are redirected only after httpd.conf is rebuilt: run `csm webserver-integration upgrade`"
	}
}

// SiteCoverage reports, on stacks with a per-site snippet, whether the site
// blocks read it. applicable is false on other stacks.
func (i *Installer) SiteCoverage() (applicable, active bool, path string, err error) {
	sites := i.siteSnippets()
	if sites == nil {
		return false, false, "", nil
	}
	path = sites.SiteSnippetPath()
	body, readErr := i.ReadAt(path)
	if errors.Is(readErr, os.ErrNotExist) || bytes.Equal(body, []byte(disabledSiteSnippet)) {
		return true, false, path, nil
	}
	if readErr != nil {
		return true, false, path, readErr
	}
	active, err = sites.SiteIncludeActive()
	return true, active && err == nil, path, err
}

// siteSnippets returns the handler's per-site include support, or nil.
func (i *Installer) siteSnippets() siteIncluder {
	s, ok := i.Handler.(siteIncluder)
	if !ok || s.SiteSnippetPath() == "" {
		return nil
	}
	return s
}

// prepareSite reads and renders the per-site snippet, or returns nil when
// the handler has none.
func (i *Installer) prepareSite() (*siteChange, error) {
	sites := i.siteSnippets()
	if sites == nil {
		return nil, nil
	}
	path := sites.SiteSnippetPath()
	prev, exists, ver, err := i.readManaged(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if exists && ver == 0 {
		return nil, fmt.Errorf("%w: %s", ErrManualEdits, path)
	}
	rendered, err := i.renderBody(i.Handler.Kind()+"-site", sites.SiteTemplate())
	if err != nil {
		return nil, fmt.Errorf("render site snippet: %w", err)
	}
	active, activeErr := sites.SiteIncludeActive()
	return &siteChange{
		sites:      sites,
		path:       path,
		prevBytes:  prev,
		prevExists: exists,
		rendered:   rendered,
		current:    exists && bytes.Equal(prev, rendered),
		active:     active && activeErr == nil,
		activeErr:  activeErr,
	}, nil
}

func (i *Installer) mkdirAll(path string, mode os.FileMode) error {
	if i.MkdirAll == nil {
		return os.MkdirAll(path, mode)
	}
	return i.MkdirAll(path, mode)
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
	// A newer template must not become an automatic downgrade merely
	// because the legacy file is present after a binary rollback.
	if res.Status == "ok" && ver == TemplateVersion {
		_, legacyExists, err := i.readLegacySnippet()
		if err != nil {
			res.Status = "fail"
			res.Message = err.Error()
			return res, err
		}
		if legacyExists {
			res.Status = "stale"
			res.Message = fmt.Sprintf("legacy snippet %s still present; run `csm webserver-integration upgrade`", i.LegacySnippetPath)
		}
	}
	if sites := i.siteSnippets(); sites != nil && ver <= TemplateVersion && (res.Status == "ok" || res.Status == "stale") {
		path := sites.SiteSnippetPath()
		res.SitePath = path
		_, exists, siteVer, err := i.readManaged(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Status = "fail"
			res.Message = err.Error()
			return res, err
		}
		switch {
		case siteVer > TemplateVersion:
			res.Status = "ok"
			res.Message = "site snippet is newer than this binary; leaving both snippets unchanged"
		case !exists || (siteVer > 0 && siteVer < TemplateVersion):
			res.Status = "stale"
			res.Message = fmt.Sprintf("site snippet %s missing or old; run `csm webserver-integration upgrade`", path)
		case siteVer == 0:
			res.Status = "modified"
			res.Message = ErrManualEdits.Error() + ": " + path
		}
	}
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

// disabledSiteSnippet remains managed so a later install can replace it.
const disabledSiteSnippet = "# csm-managed-version: 1\n# Challenge redirects disabled; keep this file for cPanel's required include.\n"

// Remove disables the snippets, runs configtest to confirm the webserver
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
	if prevExists && prevVer == 0 {
		res.Status = "fail"
		res.Message = ErrManualEdits.Error() + ": refusing to delete an operator-edited file"
		return res, ErrManualEdits
	}
	var (
		sitePath   string
		siteBytes  []byte
		siteExists bool
	)
	if sites := i.siteSnippets(); sites != nil {
		sitePath = sites.SiteSnippetPath()
		var siteVer int
		siteBytes, siteExists, siteVer, err = i.readManaged(sitePath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Status = "fail"
			res.Message = err.Error()
			return res, err
		}
		if siteExists && siteVer == 0 {
			res.Status = "fail"
			res.Message = ErrManualEdits.Error() + ": refusing to delete an operator-edited file: " + sitePath
			return res, ErrManualEdits
		}
	}
	res.SitePath = sitePath
	changeSite := siteExists && !bytes.Equal(siteBytes, []byte(disabledSiteSnippet))
	if !prevExists && !changeSite {
		res.Status = "no-op"
		res.Message = "challenge redirects not installed"
		return res, nil
	}
	serverRemoved, siteWritten := false, false
	restoreAll := func() error {
		var errs []error
		if serverRemoved {
			errs = append(errs, i.restore(prevBytes, true))
		}
		if siteWritten {
			errs = append(errs, i.restoreAt(sitePath, siteBytes, true))
		}
		return errors.Join(errs...)
	}
	if prevExists {
		if err := i.RemoveAt(i.Handler.SnippetPath()); err != nil {
			res.Status = "fail"
			res.Message = "delete: " + err.Error()
			return res, err
		}
		serverRemoved = true
	}
	if changeSite {
		// cPanel uses Include, not IncludeOptional. Keep a comment-only
		// match so removing the last snippet cannot break server startup.
		if err := i.WriteAt(sitePath, []byte(disabledSiteSnippet), 0o644); err != nil {
			err = errors.Join(err, restoreAll())
			res.Status = "fail"
			res.Message = "disable site snippet: " + err.Error()
			return res, err
		}
		siteWritten = true
	}
	if verr := i.Handler.Validate(); verr != nil {
		verr = errors.Join(verr, restoreAll())
		res.Status = "fail"
		res.Message = "configtest after remove: " + verr.Error()
		return res, verr
	}
	if rerr := i.Handler.Reload(); rerr != nil {
		res.Status = "fail"
		if err := restoreAll(); err != nil {
			err = errors.Join(rerr, err)
			res.Message = "reload: " + err.Error()
			return res, err
		}
		if err := i.Handler.Validate(); err != nil {
			err = errors.Join(rerr, fmt.Errorf("rollback configtest: %w", err))
			res.Message = err.Error()
			return res, err
		}
		if err := i.Handler.Reload(); err != nil {
			err = errors.Join(rerr, fmt.Errorf("recovery reload: %w", err))
			res.Message = err.Error()
			return res, err
		}
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
	return i.renderBody(i.Handler.Kind(), i.Handler.Template())
}

// renderBody renders one snippet template behind the version marker.
func (i *Installer) renderBody(name, body string) ([]byte, error) {
	tpl, err := template.New(name).Parse(body)
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
		ChallengeMapPath:      challenge.DefaultMapPath,
		ChallengeNginxMapPath: challenge.DefaultNginxMapPath,
		ChallengeListenAddr:   "127.0.0.1",
	}
	if cfg == nil {
		return rc
	}
	rc.ChallengeListenAddr = strings.TrimSpace(cfg.Challenge.ListenAddr)
	if rc.ChallengeListenAddr == "" {
		rc.ChallengeListenAddr = "127.0.0.1"
	}
	rc.ChallengeListenGroup = strings.TrimSpace(cfg.Challenge.ListenGroup)
	rc.ChallengePublicURL = strings.TrimSpace(cfg.Challenge.PublicURL)
	rc.ChallengeTrustedProxies = cfg.Challenge.TrustedProxies
	return rc
}

// RenderConfigFromConfig exposes the daemon-to-template projection for
// diagnostics that need to validate the same inputs before install.
func RenderConfigFromConfig(cfg *config.Config) RenderConfig {
	return renderConfigFrom(cfg)
}

func (i *Installer) templateData() templateData {
	mapPath := strings.TrimSpace(i.Config.ChallengeMapPath)
	if mapPath == "" {
		mapPath = challenge.DefaultMapPath
	}
	nginxMapPath := strings.TrimSpace(i.Config.ChallengeNginxMapPath)
	if nginxMapPath == "" {
		nginxMapPath = challenge.DefaultNginxMapPath
	}
	return templateData{
		ChallengeMapPath:      mapPath,
		ChallengeNginxMapPath: nginxMapPath,
		ChallengePublicURL:    strings.TrimSpace(i.Config.ChallengePublicURL),
	}
}

func (i *Installer) ensureChallengeMapFiles() error {
	data := i.templateData()
	mkdirAll := i.MkdirAll
	if mkdirAll == nil {
		mkdirAll = os.MkdirAll
	}
	for _, f := range []struct {
		path string
		body []byte
	}{
		{path: data.ChallengeMapPath, body: []byte("# Generated by CSM.\n")},
		{path: data.ChallengeNginxMapPath, body: []byte("# Generated by CSM.\n")},
	} {
		if err := mkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			return err
		}
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

func validateChallengePublicURL(rc RenderConfig) error {
	raw := strings.TrimSpace(rc.ChallengePublicURL)
	if raw == "" {
		return ErrMissingPublicURL
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%w: %q", ErrInvalidPublicURL, raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme %q", ErrInvalidPublicURL, u.Scheme)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/challenge" {
		return fmt.Errorf("%w: %q", ErrInvalidPublicURL, raw)
	}
	if isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("%w: host %q is loopback", ErrInvalidPublicURL, u.Hostname())
	}
	// The installer loads config without running config.Validate. Check
	// socket settings before accepting redirects to a listener that cannot
	// start, and before the "unix:" prefix can be parsed as host:port.
	if path, socket := config.ChallengeSocketPath(rc.ChallengeListenAddr); socket {
		if err := config.ChallengeSocketPathError(path); err != nil {
			return fmt.Errorf("webserver integration: %w", err)
		}
		if strings.TrimSpace(rc.ChallengeListenGroup) == "" {
			return errors.New("webserver integration: challenge.listen_group must name the group your proxy runs as when challenge.listen_addr is a unix socket")
		}
		return nil
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(rc.ChallengeListenAddr)); err == nil {
		return errors.New("webserver integration: challenge.listen_addr must contain only a host; set the port in challenge.listen_port")
	}
	if isLoopbackListenAddr(rc.ChallengeListenAddr) {
		return ErrLoopbackPublicURL
	}
	return nil
}

// ValidateChallengePublicURL applies the same direct-redirect validation used
// by Install so diagnostics and tests do not drift from installer behavior.
func ValidateChallengePublicURL(rc RenderConfig) error {
	return validateChallengePublicURL(rc)
}

func isLoopbackListenAddr(addr string) bool {
	return isLoopbackHost(challenge.ListenHost(addr))
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// readSnippet parses the on-disk snippet header to recover the
// embedded version. Returns the raw bytes, a presence flag, and the
// parsed version (zero when the file exists but lacks the marker).
func (i *Installer) readSnippet() ([]byte, bool, int, error) {
	return i.readManaged(i.Handler.SnippetPath())
}

// readManaged reads a managed snippet at path like readSnippet does.
func (i *Installer) readManaged(path string) ([]byte, bool, int, error) {
	data, err := i.ReadAt(path)
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
// I/O errors are also returned so Install can refuse a recovery reload
// when either part of the configuration could not be restored.
func (i *Installer) restore(prevBytes []byte, prevExists bool) error {
	return i.restoreAt(i.Handler.SnippetPath(), prevBytes, prevExists)
}

// restoreAt puts path back to its previous state like restore does.
func (i *Installer) restoreAt(path string, prevBytes []byte, prevExists bool) error {
	if !prevExists {
		if err := i.RemoveAt(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(i.Stderr, "webserver integration: rollback delete failed: %v\n", err)
			return fmt.Errorf("rollback delete: %w", err)
		}
		return nil
	}
	if err := i.WriteAt(path, prevBytes, 0o644); err != nil {
		fmt.Fprintf(i.Stderr, "webserver integration: rollback write failed: %v\n", err)
		return fmt.Errorf("rollback write: %w", err)
	}
	return nil
}

// readLegacySnippet returns the legacy snippet's bytes and whether it
// exists. Always absent when the handler cannot validate its removal.
func (i *Installer) readLegacySnippet() ([]byte, bool, error) {
	if i.LegacySnippetPath == "" {
		return nil, false, nil
	}
	data, err := i.ReadAt(i.LegacySnippetPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read legacy snippet: %w", err)
	}
	return data, true, nil
}

// restoreLegacySnippet puts the legacy snippet back after a failed
// validate/reload step, reporting I/O errors like restore does.
func (i *Installer) restoreLegacySnippet(data []byte) error {
	if err := i.WriteAt(i.LegacySnippetPath, data, 0o644); err != nil {
		fmt.Fprintf(i.Stderr, "webserver integration: rollback of legacy snippet %s failed: %v\n", i.LegacySnippetPath, err)
		return fmt.Errorf("rollback legacy snippet %s: %w", i.LegacySnippetPath, err)
	}
	return nil
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
		return newLSWSHandler(info, r), nil
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
