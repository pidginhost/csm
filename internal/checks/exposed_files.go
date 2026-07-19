package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// userdataDomainsPath is cPanel's authoritative domain->docroot map. It covers
// addon and subdomain docroots that /home/*/public_html misses.
const userdataDomainsPath = "/etc/userdatadomains"

// Bounds so the deep scan stays cheap on a host with hundreds of docroots.
const (
	exposureDefaultDepth      = 2
	exposureMaxFilesPerRoot   = 4000
	exposureProbeConnTimeout  = 4 * time.Second
	exposureProbeTotalTimeout = 6 * time.Second
)

// walkSkipDirs are directory names never worth descending for a leaked dump or
// backup and expensive to traverse.
var walkSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".svn": true,
}

// CheckExposedFiles scans every cPanel docroot for sensitive files (database
// dumps, backup archives, config/source backups, phpinfo) that the web server
// actually serves, and reports each confirmed exposure. It reads only response
// headers during confirmation -- a leaked file's contents never enter CSM.
func CheckExposedFiles(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	content, err := osFS.ReadFile(userdataDomainsPath)
	if err != nil {
		return nil // non-cPanel host or map unreadable: nothing to enumerate.
	}
	return scanVhostsForExposure(ctx, dedupVhostsByDocroot(parseUserdataDomains(string(content))), cfg)
}

// dedupVhostsByDocroot keeps one vhost per docroot (multiple domains -- www,
// parked -- can share a docroot; one probe host is enough).
func dedupVhostsByDocroot(vhosts []vhost) []vhost {
	seen := make(map[string]struct{}, len(vhosts))
	out := vhosts[:0:0]
	for _, vh := range vhosts {
		if _, ok := seen[vh.docroot]; ok {
			continue
		}
		seen[vh.docroot] = struct{}{}
		out = append(out, vh)
	}
	return out
}

// scanVhostsForExposure walks each vhost's docroot, classifies candidate files,
// confirms the server serves them, and emits a finding per confirmed exposure.
func scanVhostsForExposure(ctx context.Context, vhosts []vhost, cfg *config.Config) []alert.Finding {
	depth := exposureScanDepth(cfg)
	var findings []alert.Finding
	for _, vh := range vhosts {
		if ctx.Err() != nil {
			return findings
		}
		for _, path := range walkExposureCandidates(vh.docroot, depth) {
			if ctx.Err() != nil {
				return findings
			}
			class := classifyExposedFile(filepath.Base(path))
			if class == classNone {
				continue
			}
			rel := relURLPath(vh.docroot, path)
			if rel == "" {
				continue
			}
			pr := webProber.probe(ctx, vh.domain, rel)
			if !confirmExposure(class, pr) {
				continue
			}
			findings = append(findings, buildExposedFinding(vh, path, rel, class, pr))
		}
	}
	return findings
}

func exposureScanDepth(cfg *config.Config) int {
	if cfg != nil && cfg.Thresholds.ExposedFileScanDepth > 0 {
		return cfg.Thresholds.ExposedFileScanDepth
	}
	return exposureDefaultDepth
}

// walkExposureCandidates returns files under docroot down to maxDepth directory
// levels, capped at exposureMaxFilesPerRoot to bound I/O on large trees.
func walkExposureCandidates(docroot string, maxDepth int) []string {
	var out []string
	var rec func(dir string, depth int)
	rec = func(dir string, depth int) {
		if len(out) >= exposureMaxFilesPerRoot {
			return
		}
		entries, err := osFS.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if len(out) >= exposureMaxFilesPerRoot {
				return
			}
			if e.IsDir() {
				if depth < maxDepth && !walkSkipDirs[e.Name()] {
					rec(filepath.Join(dir, e.Name()), depth+1)
				}
				continue
			}
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	rec(docroot, 0)
	return out
}

func relURLPath(docroot, path string) string {
	r, err := filepath.Rel(docroot, path)
	if err != nil || strings.HasPrefix(r, "..") {
		return ""
	}
	return "/" + filepath.ToSlash(r)
}

func buildExposedFinding(vh vhost, path, rel string, class exposedClass, pr probeResult) alert.Finding {
	size := int64(-1)
	if fi, err := osFS.Stat(path); err == nil {
		size = fi.Size()
	}
	return alert.Finding{
		Severity: class.severity(),
		Check:    class.findingName(),
		Message:  fmt.Sprintf("Web-exposed %s reachable at https://%s%s", exposureLabel(class), vh.domain, rel),
		Details: fmt.Sprintf("File: %s (%d bytes), served as %q. Remove it from the web root or deny HTTP access.",
			path, size, pr.contentType),
		FilePath:  path,
		Domain:    vh.domain,
		TenantID:  vh.user,
		Timestamp: time.Now(),
	}
}

func exposureLabel(class exposedClass) string {
	switch class {
	case classConfigLeak:
		return "configuration/credentials file"
	case classDBDump:
		return "database dump"
	case classBackupArchive:
		return "site backup archive"
	case classSourceBackup:
		return "source-code backup"
	case classPHPInfo:
		return "phpinfo diagnostic"
	default:
		return "sensitive file"
	}
}

// ---------------------------------------------------------------------------
// Reachability probe seam
// ---------------------------------------------------------------------------

// webProbe abstracts a headers-only reachability check against the local web
// server. Tests inject a fake; production hits 127.0.0.1 with the vhost's
// domain as SNI/Host and reads only the status line and Content-Type.
type webProbe interface {
	probe(ctx context.Context, domain, urlPath string) probeResult
}

var webProber webProbe = realWebProbe{}

// SetWebProbe replaces the reachability prober. Test-only seam.
func SetWebProbe(p webProbe) { webProber = p }

type realWebProbe struct{}

func (realWebProbe) probe(ctx context.Context, domain, urlPath string) probeResult {
	for _, scheme := range []string{"https", "http"} {
		if pr, ok := doLocalProbe(ctx, scheme, domain, urlPath); ok {
			return pr
		}
	}
	return probeResult{}
}

// doLocalProbe issues one HEAD (falling back to a ranged GET when HEAD is
// disallowed) to the loopback web server, presenting domain as the vhost. It
// never reads the response body.
func doLocalProbe(ctx context.Context, scheme, domain, urlPath string) (probeResult, bool) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			d := &net.Dialer{Timeout: exposureProbeConnTimeout}
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
		// #nosec G402 -- probing our own loopback vhost for reachability only;
		// no trust decision rides on the certificate, and SNI must match the
		// requested domain to select the right vhost.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: domain},
	}
	// A fresh transport per probe is needed because SNI (ServerName) is
	// per-domain; release its connections so the daemon does not accumulate
	// idle sockets across scan cycles.
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   exposureProbeTotalTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	u := url.URL{Scheme: scheme, Host: domain, Path: urlPath}

	resp, err := doProbeRequest(ctx, client, http.MethodHead, u.String(), "")
	if err != nil {
		return probeResult{}, false
	}
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		_ = resp.Body.Close()
		resp, err = doProbeRequest(ctx, client, http.MethodGet, u.String(), "bytes=0-0")
		if err != nil {
			return probeResult{}, false
		}
	}
	pr := probeResult{status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), reachable: true}
	_ = resp.Body.Close()
	return pr, true
}

func doProbeRequest(ctx context.Context, client *http.Client, method, u, rangeHdr string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	if rangeHdr != "" {
		req.Header.Set("Range", rangeHdr)
	}
	req.Header.Set("User-Agent", "csm-exposure-probe")
	return client.Do(req)
}

// phpExecExts are the extensions a cPanel PHP handler executes rather than

// exposedClass labels a docroot file by the kind of exposure it represents
// when the web server serves it as a raw download. The zero value classNone
// means "not a sensitive file" and is never emitted.
type exposedClass int

const (
	classNone exposedClass = iota
	classConfigLeak
	classDBDump
	classBackupArchive
	classSourceBackup
	classPHPInfo
)

// severity maps a class to its finding severity. Credential- and
// database-bearing exposures are Critical; a leaked source backup is High;
// a phpinfo dump is Warning (information disclosure only).
func (c exposedClass) severity() alert.Severity {
	switch c {
	case classConfigLeak, classDBDump, classBackupArchive:
		return alert.Critical
	case classSourceBackup:
		return alert.High
	default:
		return alert.Warning
	}
}

// findingName is the stable registry key / audit-log check name per class.
func (c exposedClass) findingName() string {
	switch c {
	case classConfigLeak:
		return "web_exposed_config_leak"
	case classDBDump:
		return "web_exposed_db_dump"
	case classBackupArchive:
		return "web_exposed_backup_archive"
	case classSourceBackup:
		return "web_exposed_source_backup"
	case classPHPInfo:
		return "web_exposed_phpinfo"
	default:
		return ""
	}
}

// vhost is one cPanel virtual host: the domain the web server answers for and
// the docroot it serves. Parsed from /etc/userdatadomains, which -- unlike the
// /home/*/public_html glob -- covers addon and subdomain docroots too.
type vhost struct {
	domain  string
	user    string
	typ     string
	docroot string
}

// parseUserdataDomains parses the /etc/userdatadomains map. Each line is
// "<domain>: <user>==<reseller>==<type>==<maindomain>==<docroot>==...".
// Wildcard, comment, and short/malformed lines are skipped.
func parseUserdataDomains(content string) []vhost {
	var out []vhost
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*:") {
			continue
		}
		colon := strings.Index(line, ": ")
		if colon <= 0 {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(line[:colon]))
		fields := strings.Split(line[colon+2:], "==")
		if domain == "" || len(fields) < 5 {
			continue
		}
		docroot := strings.TrimSpace(fields[4])
		user := strings.TrimSpace(fields[0])
		if docroot == "" || user == "" {
			continue
		}
		out = append(out, vhost{
			domain:  domain,
			user:    user,
			typ:     strings.TrimSpace(fields[2]),
			docroot: docroot,
		})
	}
	return out
}

// probeResult is the local reachability check outcome for one candidate file.
// It carries only headers-level facts (status, Content-Type); the body is
// never read, so a leaked file's secret contents never enter CSM.
type probeResult struct {
	status      int
	contentType string
	reachable   bool
}

// confirmExposure reports whether a classified candidate is a confirmed,
// downloadable exposure. It fails closed: anything the server blocks
// (403/404), redirects (3xx), or that comes back as executed HTML on a
// non-executing class is not a finding.
func confirmExposure(class exposedClass, pr probeResult) bool {
	if !pr.reachable {
		return false
	}
	if pr.status != 200 && pr.status != 206 {
		return false
	}
	if class == classPHPInfo {
		return true
	}
	// Non-executing sensitive files: a raw (non-HTML) body means the server
	// served the file itself. An HTML body means it executed or returned an
	// error/challenge page -- not a confirmed source leak.
	return !isHTMLContentType(pr.contentType)
}

func isHTMLContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	return strings.HasPrefix(ct, "text/html") || strings.HasPrefix(ct, "application/xhtml")
}

// phpExecExts are the extensions a cPanel PHP handler executes rather than
// serving as text. A backup whose FINAL extension is one of these is run by
// the interpreter, emits no source, and is therefore not a leak.
var phpExecExts = map[string]bool{
	"php": true, "php3": true, "php4": true, "php5": true, "php7": true,
	"php8": true, "phtml": true, "pht": true, "phar": true,
}

// backupSuffixSet are terminal dot-segments that mark a renamed backup a web
// server serves as text (not executed). "bak-<timestamp>" style segments are
// matched by prefix in isBackupSuffix.
var backupSuffixSet = map[string]bool{
	"old": true, "bak": true, "save": true, "orig": true, "broken": true,
	"swp": true, "swo": true, "tmp": true, "copy": true, "backup": true,
	"1": true, "2": true,
}

// dbDumpSuffixes are the (possibly compound) endings of a raw database dump.
var dbDumpSuffixes = []string{
	".sql", ".sql.gz", ".sql.zip", ".sql.bz2", ".sql.xz", ".dump", ".mysql",
}

// archiveExts are archive endings that, combined with a backup token, denote a
// full-site backup a visitor could download whole.
var archiveExts = []string{
	".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".tar", ".zip",
	".rar", ".7z", ".gz", ".bz2", ".xz",
}

// backupTokens are name fragments that mark an archive as a site/db backup
// rather than a legitimately-offered download. Kept strong to avoid flagging
// ordinary user zips.
var backupTokens = []string{
	"backup", "wpvivid", "updraft", "duplicator", "ai1wm", "all-in-one",
	"migrate", "migration", "snapshot", "public_html", "wp-content",
	"wordpress", "full", "dump",
}

// classifyExposedFile classifies a base file name. It is deliberately
// conservative: the benign long tail (samples, examples, live scripts, and
// backups that still execute) returns classNone so the detector does not
// drown operators in false positives.
func classifyExposedFile(name string) exposedClass {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return classNone
	}

	// Diagnostics by exact name. They execute (text/html); the reachability
	// probe distinguishes a live phpinfo from a 403.
	if lower == "phpinfo.php" || lower == "info.php" {
		return classPHPInfo
	}

	// Benign long tail excluded before any leak matching.
	if isBenignExposedName(lower) {
		return classNone
	}

	// Dotenv family (secrets).
	if lower == ".env" || strings.HasPrefix(lower, ".env.") {
		return classConfigLeak
	}

	if hasDBDumpSuffix(lower) {
		return classDBDump
	}

	if isBackupArchive(lower) {
		return classBackupArchive
	}

	// Non-executing backups of PHP source / config files.
	if stripped, ok := stripBackupSuffix(lower); ok && looksLikePHPSource(stripped) {
		if looksLikeConfig(stripped) {
			return classConfigLeak
		}
		return classSourceBackup
	}

	return classNone
}

// isBenignExposedName matches shipped samples and templates that carry no
// secret and must never be flagged.
func isBenignExposedName(lower string) bool {
	switch {
	case strings.Contains(lower, "sample"):
		return true
	case strings.Contains(lower, "example"):
		return true
	case strings.HasSuffix(lower, ".dist"):
		return true
	case strings.HasSuffix(lower, ".default"):
		return true
	}
	return false
}

func hasDBDumpSuffix(lower string) bool {
	for _, s := range dbDumpSuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

func isBackupArchive(lower string) bool {
	if strings.HasSuffix(lower, ".wpress") {
		return true
	}
	hasArchiveExt := false
	for _, e := range archiveExts {
		if strings.HasSuffix(lower, e) {
			hasArchiveExt = true
			break
		}
	}
	if !hasArchiveExt {
		return false
	}
	for _, tok := range backupTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// stripBackupSuffix removes a single trailing backup marker (a "~" or a
// terminal dot-segment such as ".old" / ".bak-20260515") and reports whether
// one was found.
func stripBackupSuffix(lower string) (string, bool) {
	if strings.HasSuffix(lower, "~") {
		return strings.TrimSuffix(lower, "~"), true
	}
	idx := strings.LastIndexByte(lower, '.')
	if idx <= 0 {
		return lower, false
	}
	seg := lower[idx+1:]
	if isBackupSuffix(seg) {
		return lower[:idx], true
	}
	return lower, false
}

func isBackupSuffix(seg string) bool {
	if backupSuffixSet[seg] {
		return true
	}
	// "bak-20260515-124446", "bak_1", "save1" style timestamped variants.
	for _, p := range []string{"bak-", "bak_", "bak.", "old-", "old_", "save-"} {
		if strings.HasPrefix(seg, p) {
			return true
		}
	}
	return false
}

// looksLikePHPSource reports whether the name (with its backup suffix already
// removed) is a PHP source file the server would serve as text.
func looksLikePHPSource(stripped string) bool {
	idx := strings.LastIndexByte(stripped, '.')
	if idx < 0 {
		return false
	}
	ext := stripped[idx+1:]
	return phpExecExts[ext]
}

// looksLikeConfig reports whether a source backup carries configuration /
// credentials, warranting Critical instead of High.
func looksLikeConfig(stripped string) bool {
	for _, tok := range []string{"config", "wp-config", "settings", "database", "db-config", "credentials", "secret"} {
		if strings.Contains(stripped, tok) {
			return true
		}
	}
	return false
}
